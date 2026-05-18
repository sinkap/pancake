# Deploying pancake on Google Cloud

End-to-end walkthrough for the gcp mode:

- Fleet-server (with bundled UI) on GKE Autopilot
- Build-server + sign-server on a privileged GCE VM
- VMs issue mTLS certs from Google CAS
- VMs' EK certs are read from the Google vTPM and validated against
  Google's vTPM root CA chain

## What you need

- A GCP project with billing enabled.
- A workstation with `gcloud`, `kubectl`, and `terraform` installed.
- ~$100/month for the smallest viable deployment (DevOps-tier CAS
  pool + GKE Autopilot baseline + n2-standard-4 build VM).

## 1. Bootstrap the project

```bash
gcloud auth login
gcloud auth application-default login
gcloud config set project YOUR_PROJECT

cd deployment/terraform
terraform init
terraform apply \
  -var project_id=YOUR_PROJECT \
  -var region=us-central1 \
  -var build_server_image=us-central1-docker.pkg.dev/YOUR_PROJECT/pancake/pancake-build-server:v1 \
  -var sign_server_image=us-central1-docker.pkg.dev/YOUR_PROJECT/pancake/pancake-sign:v1
```

Terraform produces:

- A GKE Autopilot cluster `pancake-fleet`.
- Cloud SQL Postgres for the fleet-server.
- A CAS pool `pancake-fleet` with a 10-year self-signed root and
  `pancake-vm` / `pancake-build-server` service accounts wired with
  the right `privateca.*` roles.
- A privileged GCE VM `pancake-build-server` running build + sign
  containers. The startup script fetches the CAS pool root and (if
  you've placed it) Google vTPM roots into the build-server trust
  directory.

Note the outputs:

```text
cas_pool_resource_name   = projects/YOUR_PROJECT/locations/us-central1/caPools/pancake-fleet
pancake_vm_gsa_email     = pancake-vm@YOUR_PROJECT.iam.gserviceaccount.com
build_server_internal_ip = 10.x.y.z
fleet_server_gsa_email   = pancake-fleet-server@YOUR_PROJECT.iam.gserviceaccount.com
```

## 2. Push images to Artifact Registry

```bash
gcloud artifacts repositories create pancake --repository-format=docker \
  --location=us-central1

# From the repo root. fleet-server (UI bundled):
cd ../..
gcloud builds submit . \
  --tag us-central1-docker.pkg.dev/YOUR_PROJECT/pancake/pancake-fleet-server:v1 \
  -f deployment/docker/fleet-server/Dockerfile

# build-server, sign-server: same recipe, swap Dockerfile path:
gcloud builds submit . \
  --tag us-central1-docker.pkg.dev/YOUR_PROJECT/pancake/pancake-build-server:v1 \
  -f deployment/docker/build-server/Dockerfile

gcloud builds submit . \
  --tag us-central1-docker.pkg.dev/YOUR_PROJECT/pancake/pancake-sign:v1 \
  -f deployment/docker/sign-server/Dockerfile

# Once pushed, restart the build VM so the startup script picks up the
# new images:
gcloud compute instances reset pancake-build-server --zone=us-central1-a
```

## 3. Capture the Google vTPM root bundle (one-time)

Google does not publish vTPM roots at a stable URL. Fetch them from a
known-good Shielded VM:

```bash
# Boot any throwaway Shielded VM; ssh in.
gcloud compute instances create vtpm-root-grab \
  --image-family=debian-12 --image-project=debian-cloud \
  --enable-vtpm --shielded-secure-boot --zone=us-central1-a

gcloud compute ssh vtpm-root-grab --zone=us-central1-a -- '
  sudo apt-get install -y tpm2-tools
  sudo tpm2_nvread 0x01C0000A | openssl x509 -inform der \
    -text -noout | grep -A1 "Authority Information Access"
'
# Note the AIA URL(s); curl each one, then chase the chain to the
# self-signed root. The result is a PEM bundle.

gcloud compute instances delete vtpm-root-grab --zone=us-central1-a --quiet
```

Place the resulting PEM at `/etc/pancake/google-vtpm-roots.pem` on
the build-server VM (the startup script copies it into the trust dir
on next boot):

```bash
gcloud compute scp google-vtpm-roots.pem \
  pancake-build-server:/etc/pancake/google-vtpm-roots.pem \
  --zone=us-central1-a
gcloud compute instances reset pancake-build-server --zone=us-central1-a
```

## 4. Deploy fleet-server to GKE

Update placeholders in `deployment/gke/k8s/` (PROJECT_ID, the image
tag, the SQL connection name). Then:

```bash
gcloud container clusters get-credentials pancake-fleet \
  --region=us-central1 --project=YOUR_PROJECT

kubectl apply -f deployment/gke/k8s/namespace.yaml
kubectl apply -f deployment/gke/k8s/serviceaccount.yaml
kubectl apply -f deployment/gke/k8s/configmap.yaml

# Secrets — use kubectl create secret rather than committing them
kubectl create secret generic cloudsql-db-credentials \
  -n pancake-fleet \
  --from-literal=connection-string="postgres://pancake:$(terraform output -raw db_password)@127.0.0.1:5432/pancake_fleet?sslmode=disable"

# EK trust bundle (Google vTPM roots) as a mounted secret
kubectl create secret generic pancake-ek-trust -n pancake-fleet \
  --from-file=ek-trust-bundle.pem=google-vtpm-roots.pem

# Operator mTLS for the fleet-server poller (CAS-issued client cert
# for the fleet-server's SA, plus the CAS pool root as ca.crt)
kubectl create secret generic pancake-mtls -n pancake-fleet \
  --from-file=ca.crt=cas-pool-root.pem \
  --from-file=client.crt=fleet-server-client.crt \
  --from-file=client.key=fleet-server-client.key

kubectl apply -f deployment/gke/k8s/fleet-server-deployment.yaml
kubectl apply -f deployment/gke/k8s/fleet-server-service.yaml
kubectl apply -f deployment/gke/k8s/ingress.yaml
```

You'll need to extend `fleet-server-deployment.yaml` to mount the
`pancake-ek-trust` secret and pass
`-ek-trust-bundle=/var/run/secrets/pancake-ek-trust/ek-trust-bundle.pem`.

## 5. Build an image with platform=gcp

On your workstation (or by SSHing into the build VM):

```yaml
# pancake-gcp-recipe.yaml
output: ./pancake-kit
hostname: pancake-gcp-demo
platform: gcp

distro:
  suite: noble

packages: [openssh-server, chrony]

ssh:
  authorized-keys: ~/.ssh/id_ed25519.pub

orchestrator:
  # ca-url is unused in pure gcp-cas mode, but pancake bootstrap
  # currently requires one. Use the CAS pool URL as a placeholder —
  # it's only baked into config.json as a fallback.
  ca-url: https://unused.example.com/acme/tpm/directory
  fleet-server: fleet.YOUR-DOMAIN:443

# Smart defaults: platform=gcp implies ek-trust=google-vtpm,
# issuance.ca=gcp-cas. Override only if you want a mixed mode.
issuance:
  cas:
    pool: projects/YOUR_PROJECT/locations/us-central1/caPools/pancake-fleet

gce:
  project: YOUR_PROJECT
  bucket: gs://YOUR_PROJECT-pancake-images
  create-image: true
  image-family: pancake-os
```

```bash
# Point the builder at the GCE build-server
echo "$(terraform output -raw build_server_external_ip):7879" \
  > pancake-host-state/builder-addr

pancake bootstrap pancake-gcp-recipe.yaml
# → builds locally, uploads tar.gz to GCS, creates the GCE image
```

## 6. Boot a Shielded VM from the image

```bash
gcloud compute instances create pancake-test-1 \
  --image-family=pancake-os --image-project=YOUR_PROJECT \
  --machine-type=n2-standard-2 \
  --enable-vtpm --shielded-secure-boot \
  --service-account=pancake-vm@YOUR_PROJECT.iam.gserviceaccount.com \
  --scopes=cloud-platform \
  --tags=pancake-fleet \
  --zone=us-central1-a
```

On first boot:

1. `pancake enroll` reads the Google EK cert from
   `tpm2_nvread 0x01c0000a`, writes it to `/etc/pancake/ek.crt`.
2. Issuance routes to `gcp-cas` (recipe set it; orch-config baked
   `issuance_ca=gcp-cas` + `cas_pool=...` into
   `/etc/pancake/orch/config.json`). The CAS issuer creates a TPM-
   resident ECDSA key, signs a CSR, calls
   `privateca.CreateCertificate` via ADC (the instance SA), and writes
   the returned PEM chain to `/etc/pancake/server.crt`.
3. `pancake enroll` calls `FleetManager.Enroll` on
   `fleet.YOUR-DOMAIN:443`.
4. Within 30–60s the fleet-server poller dials the VM at its internal
   IP, mTLS-handshakes against the CAS-issued server cert, calls
   `Attest`, and verifies the EK cert chain against the
   `-ek-trust-bundle` (Google vTPM roots).
5. Dashboard at `https://fleet.YOUR-DOMAIN/` shows the VM with
   `attestation_status=valid`, `EK chain ✓`, leaf serial visible.

## 7. Pin the PCR baseline

After the first valid attestation, capture and register the policy:

```bash
curl https://fleet.YOUR-DOMAIN/api/v1/vms/1/attestations?limit=1 \
  | jq '.attestations[0].pcrs' > policy-gen-1.json

curl -X PUT https://fleet.YOUR-DOMAIN/api/v1/generations/1 \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --slurpfile p policy-gen-1.json \
    '{pcrs: $p[0], description: "production v1.0.0"}')"
```

Subsequent VMs at generation 1 that don't match the policy will flip
to `failed` with a `PCR[N] got=… want=…` error.

## Cost notes

- DevOps CAS pool: $200/month flat.
- GKE Autopilot: ~$70/month baseline + pod usage.
- Build VM (n2-standard-4): ~$100/month if always-on.
- Cloud SQL (db-g1-small): ~$25/month.
- vTPM has no extra charge over standard Shielded VM.

For dev/staging you can spin everything down between sessions
(`terraform destroy` plus `gcloud compute instances delete`). Cloud
SQL takes a few minutes to come back; CAS pool deletion has a 30-day
recovery window unless you pass `--ignore-active-certificates`.
