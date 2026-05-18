# pancake-os

Attested filesystem integrity system with dm-verity layers and TPM-backed auto-enrollment.

## Quick Start

```bash
# 1. Initialize dev EK CA (one-time, mimics TPM manufacturer CA)
./init-dev-ek-ca.sh

# 2. Start services (step-ca, build-server, sign-server)
docker compose up -d --wait

# 3. Initialize operator credentials
pancake host-cert init

# 4. Load credentials into environment
source pancake-host-state/pancake.env

# 5. Bootstrap VM image (builds layers, signs manifest, creates bootable EFI image)
pancake bootstrap

# 6. Boot VM with QEMU + TPM emulation
./boot-vm.sh

# 7. Wait ~30 seconds for auto-enrollment, then test attestation
pancake orchestrate attest --target localhost:7878
```

Or run the automated demo:
```bash
./demo.sh
```

## What Just Happened

1. **Dev EK CA created**: One-time setup generating a root CA that mimics TPM manufacturer CAs (Intel/AMD/Infineon). In production, you'd use real manufacturer roots.

2. **Docker services started**: step-ca (unified CA for mTLS), build-server (layer builder), sign-server (manifest signer)

3. **Operator enrolled**: `pancake host-cert init` got you an mTLS client certificate from step-ca for authenticating to orchestrator services

4. **VM image built**: 
   - Build server assembled dm-verity layers (APT packages + pancake runtime + custom kernel)
   - Baked dev EK CA into orch-config layer (for local AK cert issuance)
   - Sign server signed the manifest
   - Assembled bootable EFI image with initramfs + kernel

5. **VM booted**: QEMU with UEFI firmware + swtpm (software TPM 2.0 with EK cert signed by dev EK CA)

6. **Auto-enrollment**: 
   - VM's `pancake-enroll.service` ran on first boot
   - Created AK in TPM, signed AK cert locally using dev EK CA (baked into VM)
   - Enrolled via ACME device-attest-01, step-ca validated EK cert against dev EK CA root
   - Received mTLS server cert from step-ca
   - pancaked started with TPM-backed TLS cert

7. **Attestation**: Operator requested TPM quote with nonce, VM responded with signed PCR values

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│ Host (operator machine)                                        │
│                                                                 │
│  Dev EK CA (one-time): pancake-host-state/dev-ek-ca/           │
│    ├─ ca.crt (public, baked into VMs)                          │
│    └─ ca.key (private, signs swtpm EK + AK certs)              │
│                                                                 │
│  pancake CLI ──────────────┐                                   │
│    │ mTLS                   │                                   │
│    ↓                        ↓                                   │
│  Docker Compose:                                               │
│    ┌──────────────┐  ┌─────────────┐                           │
│    │  step-ca     │  │build-server │  Unified CA:              │
│    │  :8443       │  │  :7879      │  - step-ca issues mTLS    │
│    └──────────────┘  └─────────────┘  - dev EK CA signs TPM    │
│                                                                 │
│  QEMU VM (port-forwarded):                                     │
│    ┌──────────────────────────────────────────┐               │
│    │  swtpm: EK signed by dev EK CA           │               │
│    │  pancaked :7878 (mTLS, TPM-backed cert)  │               │
│    │  SSH :22 (forwarded to host :2222)       │               │
│    │                                           │               │
│    │  /etc/pancake/orch/dev-ek-ca/ (baked in) │               │
│    │    └─ VM signs own AK cert on first boot │               │
│    └──────────────────────────────────────────┘               │
└────────────────────────────────────────────────────────────────┘
```

## Files and Directories

- `pancake-recipe.yaml` - VM build config (hostname, packages, kernel, orchestrator URLs)
- `pancake-host-state/` - Operator credentials (client cert/key, CA roots, service URLs)
- `pancake-kit/` - Built VM artifacts (manifest, layers, signing keys)
- `vm-state/` - Running VM state (OVMF vars, TPM state, console log)
- `boot-vm.sh` - Boot VM with QEMU + swtpm
- `stop-vm.sh` - Stop running VM
- `clean-state.sh` - Clean all state (VMs, caches, artifacts)
- `demo.sh` - Automated end-to-end demo

## Common Commands

```bash
# SSH to VM
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost

# Check auto-enrollment status
ssh -p 2222 root@localhost "systemctl status pancake-enroll.service"

# Check pancaked status
ssh -p 2222 root@localhost "systemctl status pancaked"

# Get VM's current manifest
pancake orchestrate get-current --target localhost:7878

# Request TPM attestation
pancake orchestrate attest --target localhost:7878

# Rebuild from scratch
./clean-state.sh
docker compose down
docker compose up -d --wait
./demo.sh
```

## Requirements

- Go 1.21+
- Docker + Docker Compose
- QEMU with KVM support
- swtpm (TPM 2.0 emulator)
- OVMF (UEFI firmware)

Ubuntu/Debian:
```bash
sudo apt install qemu-system-x86 ovmf swtpm docker-compose-v2
```

## Development

See [HACKING.md](HACKING.md) for development workflow, protobuf regeneration, and architecture details.

## Troubleshooting

**VM won't boot:**
```bash
sudo tail -f vm-state/vm.log
```

**Attestation fails:**
- Ensure `source pancake-host-state/pancake.env` was run
- Wait 30s after boot for auto-enrollment to complete
- Check `ssh -p 2222 root@localhost "systemctl status pancaked"`

**Build fails:**
```bash
docker logs pancake-build-server
```

**Clean slate:**
```bash
./clean-state.sh
docker compose down -v
docker compose up -d --wait
```
