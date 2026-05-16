# pancake-os

Attested filesystem integrity system with dm-verity layers and TPM-backed auto-enrollment.

## Quick Start

```bash
# 1. Start services (step-ca, attest-ca, build-server, sign-server)
docker compose up -d --wait

# 2. Initialize operator credentials
pancake host-cert init

# 3. Load credentials into environment
source pancake-host-state/pancake.env

# 4. Bootstrap VM image (builds layers, signs manifest, creates bootable EFI image)
pancake bootstrap

# 5. Boot VM with QEMU + TPM emulation
./boot-vm.sh

# 6. Wait ~30 seconds for auto-enrollment, then test attestation
pancake orchestrate attest --target localhost:7878
```

Or run the automated demo:
```bash
./demo.sh
```

## What Just Happened

1. **Docker services started**: step-ca (ACME CA), attest-ca (TPM attestation CA), build-server (layer builder), sign-server (manifest signer)

2. **Operator enrolled**: `pancake host-cert init` got you an mTLS client certificate from step-ca for authenticating to orchestrator services

3. **VM image built**: 
   - Build server assembled dm-verity layers (APT packages + pancake runtime + custom kernel)
   - Sign server signed the manifest
   - Assembled bootable EFI image with initramfs + kernel

4. **VM booted**: QEMU with UEFI firmware + swtpm (software TPM 2.0)

5. **Auto-enrollment**: 
   - VM's `pancake-enroll.service` ran on first boot
   - Used TPM to attest to attest-ca, got AK certificate
   - Used AK cert to enroll via ACME device-attest-01, got TLS cert
   - pancaked started with TPM-backed TLS cert

6. **Attestation**: Operator requested TPM quote with nonce, VM responded with signed PCR values

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Host (operator machine)                                     │
│                                                              │
│  pancake CLI ──────────────────┐                            │
│    │                            │                            │
│    │ mTLS                       │ mTLS                       │
│    ↓                            ↓                            │
│  Docker Compose:                                            │
│    ┌──────────────┐  ┌──────────────┐  ┌─────────────┐     │
│    │  step-ca     │  │  attest-ca   │  │build-server │     │
│    │  :8443       │  │  :8444       │  │  :7879      │     │
│    └──────────────┘  └──────────────┘  └─────────────┘     │
│                                                              │
│  QEMU VM (port-forwarded):                                  │
│    ┌─────────────────────────────────────────┐             │
│    │  pancaked :7878 (mTLS, TPM-backed cert) │             │
│    │  SSH :22 (forwarded to host :2222)      │             │
│    └─────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────┘
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
