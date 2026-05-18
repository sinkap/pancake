# Deployment modes

Pancake supports three deployment modes. They're driven by two
orthogonal knobs in the recipe (`attestation.ek-trust` and
`issuance.ca`), which both default from `platform`. You can override
either knob if your situation doesn't match the canonical mode.

| Mode           | platform        | TPM         | attestation.ek-trust | issuance.ca | Use case                       |
| -------------- | --------------- | ----------- | -------------------- | ----------- | ------------------------------ |
| dev            | `dev` / unset   | swtpm       | `dev-ek-ca`          | `step-ca`   | Local QEMU; what bootstrap does today |
| self-hosted    | `self-hosted`   | real HW TPM | `manufacturer`       | `step-ca`   | Customer on-prem fleet         |
| gcp            | `gcp` (or `gce`)| GCE vTPM    | `google-vtpm`        | `gcp-cas`   | GCE-managed fleet              |

The two knobs are independent. You can mix:

- **gcp deployment with a customer step-ca:**
  `platform: gcp`, `attestation.ek-trust: google-vtpm`,
  `issuance.ca: step-ca` (override). Get TPM trust from Google, but
  certs from your own CA — portable, doesn't bind you to GCP.

- **self-hosted with dev EK CA:**
  `platform: self-hosted`, `attestation.ek-trust: dev-ek-ca`
  (override). Useful when bringing up bare-metal hardware that has a
  TPM but no enrolled manufacturer roots yet — bootstrap with dev EK
  CA, register PCRs, switch to manufacturer roots later.

## ek-trust values

| Value          | EK cert source                              | Trust root                    |
| -------------- | ------------------------------------------- | ----------------------------- |
| `dev-ek-ca`    | Locally synthesised at AK enrollment time   | self-signed dev EK CA cert    |
| `manufacturer` | TPM NV at 0x01C0000A / 0x01C00002           | Vendor bundle (Intel/AMD/etc) |
| `google-vtpm`  | GCE vTPM NV at 0x01C0000A / 0x01C00002      | Google's vTPM root CA chain   |

The build server bakes the appropriate trust file into the
`pancake-orch-config` verity layer:

- `dev-ek-ca` → `/etc/pancake/orch/dev-ek-ca/{ca.crt,ca.key}`
- `manufacturer` → `/etc/pancake/orch/ek-trust-roots.pem`
  (operator pre-populates `<build-server trust-dir>/manufacturer-roots.pem`)
- `google-vtpm` → `/etc/pancake/orch/ek-trust-roots.pem`
  (operator pre-populates `<build-server trust-dir>/google-vtpm-roots.pem`)

## issuance.ca values

| Value     | CA                | Auth to CA                    | Cert chain validates to |
| --------- | ----------------- | ----------------------------- | ----------------------- |
| `step-ca` | customer step-ca  | ACME-tpm (TPM device-attest-01)| step-ca root            |
| `gcp-cas` | Google CAS pool   | GCE instance SA via ADC       | CAS pool root           |

For `gcp-cas`:

- Recipe must set `issuance.cas.pool: projects/<p>/locations/<l>/caPools/<x>`.
- Build server bakes the pool root cert at
  `/etc/pancake/orch/cas-pool-root.pem` (operator pre-populates
  `<build-server trust-dir>/cas-pool-root.pem`, or terraform's
  build-server startup script fetches it via
  `gcloud privateca pools get-ca-certs`).
- The VM's service account must hold
  `roles/privateca.certificateRequester` on the pool. Terraform's
  `cas.tf` sets this up for the `pancake-vm` SA.

## What the fleet-server needs

Per-mode trust the operator wires into `pancake-fleet-server`:

| Flag                  | Where it points                                  |
| --------------------- | ------------------------------------------------ |
| `-attest-ca-file`     | Trust roots for mTLS dial to pancaked. Bundle of step-ca root + CAS pool root when running mixed fleets. |
| `-ek-trust-bundle`    | EK chain trust roots (`google-vtpm-roots.pem`, manufacturer bundle, or both concatenated). Optional — when empty, EK chain is recorded but not verified. |
| `-attest-cert-file`, `-attest-key-file` | Operator mTLS client cert; same CA as VMs' mTLS server certs. |
