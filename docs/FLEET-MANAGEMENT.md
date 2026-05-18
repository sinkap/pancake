# Fleet management

`pancake-fleet-server` is the orchestrator-side service that tracks every
enrolled pancake VM, polls them for TPM attestations, and serves both a
gRPC API for the fleet and an HTTP REST API + web UI for operators.

## Architecture

```
                    operator browser
                          │
                          ▼  http(s)
        ┌──────────────────────────────────────┐
        │   pancake-fleet-server               │
        │   ┌─────────────┐  ┌──────────────┐  │
        │   │ HTTP / UI   │  │ gRPC         │  │     polls every -attest-interval
        │   │ :8080       │  │ :8081        │  │  ┌─────────────────────────────┐
        │   └─────────────┘  └──────────────┘  │  │                             │
        │                                      │  ▼                             │
        │   ┌────────────────────────────┐     │  pancaked on each VM           │
        │   │  attestation poller        │─────┘  /dev/tpmrm0 (or swtpm)        │
        │   │  PCR policy enforcement    │        gRPC Attest @ :7878 (mTLS)    │
        │   └────────────────────────────┘                                       │
        │                                                                        │
        │   PostgreSQL ─ vms, attestation_log, expected_pcrs, fleet_events       │
        └────────────────────────────────────────────────────────────────────────┘
                                ▲
                                │ Enroll RPC on first boot
                                │
                          pancake enroll
```

## Local stack

```bash
cd .   # repo root
docker compose -f fleet-compose.yaml up -d --build
# → Postgres on :5433
# → pancake-fleet-server on :8080 (HTTP + UI) and :8081 (gRPC)
```

Open <http://localhost:8080> for the dashboard.

By default the poller starts insecure (no mTLS) which is fine for early
testing but will fail to attest pancaked instances that require client
auth. Pass mTLS materials and (optionally) TOFU to enforce PCR policy:

```bash
DATABASE_URL='postgres://pancake:pancake-dev@127.0.0.1:5433/pancake_fleet?sslmode=disable' \
./pancake-fleet-server \
  -web-ui ./web-ui/build \
  -attest-interval 30s \
  -attest-ca-file   ./pancake-host-state/step-root.crt \
  -attest-cert-file ./pancake-host-state/client.crt \
  -attest-key-file  ./pancake-host-state/client.key \
  -attest-server-name pancake-demo \
  -attest-tofu
```

## REST API

| Endpoint                                     | Purpose                                       |
| -------------------------------------------- | --------------------------------------------- |
| `GET  /healthz` / `GET /readyz`              | Liveness + DB readiness                       |
| `GET  /api/v1/stats`                         | Aggregate fleet counters                      |
| `GET  /api/v1/vms`                           | List VMs (`?platform=…`, `?status=…`)         |
| `GET  /api/v1/vms/{id}`                      | One VM                                        |
| `POST /api/v1/vms/{id}/attest`               | Trigger on-demand attestation                 |
| `GET  /api/v1/vms/{id}/attestations`         | Attestation history for one VM                |
| `GET  /api/v1/attestations`                  | Fleet-wide attestation log                    |
| `GET  /api/v1/events`                        | Transparency log (hash-chained)               |
| `GET  /api/v1/generations`                   | All registered PCR policies                   |
| `PUT  /api/v1/generations/{id}`              | Register/replace policy for a generation      |

## VM enrollment

VMs auto-register at boot when `orchestrator.fleet-server` is set in the
recipe:

```yaml
orchestrator:
  ca-url: https://orchestrator.example.com:8443/acme/tpm/directory
  fleet-server: fleet.example.com:8081
```

`pancake enroll` calls `FleetManager.Enroll(name, platform, internal_ip,
cert_serial, cert_expires_at)` after the ACME flow succeeds. Enrollment is
best-effort: if the fleet server is unreachable, boot proceeds and the VM
can be enrolled later via:

```bash
go run ./fleet-server/cmd/fleet-test-client -addr fleet:8081 \
  -op enroll -name my-vm -platform gce -ip 10.128.0.5
```

## PCR policy

Operators register the expected PCR values for each pancake-os generation
once; the poller compares observed PCRs to that policy on every sweep and
flips the VM to **failed** on mismatch.

```bash
# Capture a known-good baseline (e.g. from a freshly built and verified VM):
curl http://localhost:8080/api/v1/vms/3/attestations?limit=1 \
  | jq '.attestations[0].pcrs' > /tmp/policy.json

# Register as the expected PCRs for generation 5:
curl -X PUT http://localhost:8080/api/v1/generations/5 \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --slurpfile p /tmp/policy.json '{pcrs: $p[0], description: "v5.0.0 release"}')"
```

The `--attest-tofu` flag automates this for development: the first valid
attestation for any unregistered generation becomes the baseline.

## Transparency log

Every meaningful action — enrollment, attestation success/failure, policy
update — is appended to `fleet_events` with a SHA-256 chain over
`(prev_event_hash || event_payload)`. The web UI's **Transparency Log**
page exposes both hashes for each entry so an auditor can spot-check.

A future iteration will publish the log to Sigstore/Rekor or a private
Trillian instance for external auditability.
