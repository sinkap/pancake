# Deploying pancake on Google Compute Engine

This walks through the full end-to-end flow:

1. Build a pancake-os image and upload it to GCS.
2. Create a GCE custom image from the upload.
3. Boot a Shielded VM from it (with vTPM + Secure Boot).
4. Have the VM auto-enroll with `pancake-fleet-server`.

Two configuration knobs are orthogonal:

- **`platform`** picks the infrastructure: `self-hosted` (default), `gce`.
  Bootstrap's behavior changes based on this: in `gce` mode the EFI image
  is also uploaded to GCS.
- **`attestation.mode`** picks the trust source: `custom` (pancake's own
  TPM attestation, works anywhere) or `gce-shielded` (GCE's Shielded VM
  API, simpler but GCE-locked). Set independently from `platform`.

## Prerequisites

```bash
# gcloud SDK + Application Default Credentials
gcloud auth login
gcloud auth application-default login

# A GCP project with the Compute, Cloud Storage, Cloud SQL, and IAM
# APIs enabled.
gcloud config set project YOUR_PROJECT
gcloud services enable compute.googleapis.com storage.googleapis.com \
  sqladmin.googleapis.com iam.googleapis.com

# A GCS bucket to receive pancake images.
gsutil mb -p YOUR_PROJECT -l us-central1 gs://YOUR_PROJECT-pancake-images
```

## 1. Recipe for GCE

`pancake-recipe.yaml`:

```yaml
output: ./pancake-kit
hostname: pancake-prod
platform: gce

attestation:
  mode: custom        # or gce-shielded for the GCE API path

packages:
  - openssh-server
  - chrony

distro:
  suite: noble

ssh:
  authorized-keys: ~/.ssh/id_ed25519.pub

kernel:
  version: tree
  bzimage: ~/projects/linux-bpf-for-next/arch/x86/boot/bzImage

outputs:
  image:     ./pancake-state.img
  initramfs: ./pancake-initramfs.cpio.gz
  bzimage:   ./pancake-bzImage
  efi:       ./pancake-efi.img

orchestrator:
  ca-url:      https://orchestrator.example.com:8443/acme/tpm/directory
  fleet-server: fleet.example.com:8081

gce:
  project:      YOUR_PROJECT
  bucket:       gs://YOUR_PROJECT-pancake-images
  create-image: true
  image-family: pancake-os
```

## 2. Build + upload

```bash
source pancake-host-state/pancake.env   # operator mTLS for the build server
pancake bootstrap pancake-recipe.yaml
```

When `platform: gce`, bootstrap follows the usual local build path and
then:

1. Re-packs `pancake-efi.img` as a GCE-compatible `image.tar.gz`
   (a single-file tar.gz with the disk image named `disk.raw`).
2. Uploads it to `gs://YOUR_PROJECT-pancake-images/pancake-os-<TS>.tar.gz`
   via the Go GCS SDK (Application Default Credentials).
3. If `create-image: true`, calls the Compute API to create a custom
   image with `UEFI_COMPATIBLE`, `GVNIC`, and `SEV_CAPABLE` guest-OS
   features.
4. Prints the next-step `gcloud compute instances create …` command.

Authentication uses ADC, so the build host needs either:

- `gcloud auth application-default login` (interactive workstation), or
- `GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json` (CI), or
- An instance service account with `storage.objectAdmin` +
  `compute.imageAdmin` (when the build server itself runs on GCE).

## 3. Boot a VM

```bash
gcloud compute instances create pancake-test \
  --image-family=pancake-os --image-project=YOUR_PROJECT \
  --machine-type=n2-standard-2 \
  --enable-vtpm --shielded-secure-boot \
  --tags=pancake-fleet
```

Inside the VM `/dev/tpmrm0` is the GCE vTPM. `pancake enroll` auto-detects
this via the `internal/tpmbackend` package (DMI product name + presence
of the device).

## 4. Auto-enrollment

After ACME succeeds, `pancake enroll` reads the baked-in
`/etc/pancake/orch/config.json` (which contains `fleet_server` if it was
set in the recipe) and calls `FleetManager.Enroll` on it:

```text
[enroll] enrollment complete.
[enroll]   cert:        /etc/pancake/server.crt
[enroll]   tpm marker:  /etc/pancake/server.tpmkey
[enroll]   ek pubkey:   /etc/pancake/ek.pub
[enroll] registering with fleet server fleet.example.com:8081
[enroll] fleet registered as vm id=42 (enrolled)
```

Within one poll cycle (default 60s) the fleet server attests the new VM
over mTLS and the dashboard at `https://fleet.example.com/` flips it to
**valid**.

## 5. Promote the policy

The first attestation also captures PCR values. To pin them as the
known-good baseline for this generation:

```bash
# Pull observed PCRs:
curl https://fleet.example.com/api/v1/vms/42/attestations?limit=1 \
  | jq '.attestations[0].pcrs' > policy.json

# Register as the policy for generation 1:
curl -X PUT https://fleet.example.com/api/v1/generations/1 \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --slurpfile p policy.json '{pcrs: $p[0], description: "production v1.0.0"}')"
```

Future attestations for that generation must match the policy or the VM
flips to **failed** with a precise `PCR[N] got=… want=…` error in the
attestation log.

Running the fleet server with `--attest-tofu` automates step 5 for the
first VM that boots on a new generation — convenient for staging, not for
production.

## 6. Fleet server on GKE

For production, run the fleet server on GKE with Cloud SQL:

```bash
cd deployment/gke
terraform -chdir=terraform apply -var project_id=YOUR_PROJECT

# Build + push the fleet-server image (UI bundled in)
gcloud builds submit ../.. --tag \
  us-central1-docker.pkg.dev/YOUR_PROJECT/pancake/pancake-fleet-server:v1 \
  --file=deployment/docker/fleet-server/Dockerfile

# Apply k8s manifests (after substituting REPLACE_ME placeholders)
kubectl apply -f k8s/
```

See [deployment/gke/README.md](../deployment/gke/README.md) for the full walkthrough.
