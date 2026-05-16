#!/bin/bash
# Boot pancake-os VM with QEMU + OVMF + swtpm
#
# Requirements:
#   - qemu-system-x86_64
#   - OVMF firmware
#   - swtpm (for TPM emulation)
#   - pancake-efi.img (built by: pancake bootstrap pancake-recipe.yaml)

set -eu

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EFI_IMG="${SCRIPT_DIR}/pancake-efi.img"
VM_DIR="${SCRIPT_DIR}/vm-state"
SWTPM_DIR="${VM_DIR}/tpm"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS_TEMPLATE="/usr/share/OVMF/OVMF_VARS_4M.fd"
OVMF_VARS="${VM_DIR}/OVMF_VARS.fd"
VM_CONSOLE="${VM_DIR}/vm.log"
VM_PID="${VM_DIR}/vm.pid"
SWTPM_SOCK="${SWTPM_DIR}/swtpm.sock"
SWTPM_PID="${SWTPM_DIR}/swtpm.pid"

# Ports (can override via env: SSH_PORT=3333 GRPC_PORT=7878 ./boot-vm.sh)
SSH_PORT="${SSH_PORT:-2222}"
GRPC_PORT="${GRPC_PORT:-7878}"

# Check requirements
for cmd in qemu-system-x86_64 swtpm swtpm_setup; do
    if ! command -v $cmd &>/dev/null; then
        echo "error: $cmd not found in PATH"
        exit 1
    fi
done

if [ ! -f "$OVMF_CODE" ] || [ ! -f "$OVMF_VARS_TEMPLATE" ]; then
    echo "error: OVMF firmware not found"
    echo "  Expected: $OVMF_CODE and $OVMF_VARS_TEMPLATE"
    echo "  Install with: sudo apt install ovmf"
    exit 1
fi

if [ ! -f "$EFI_IMG" ]; then
    echo "error: $EFI_IMG not found"
    echo "  Build it first with: source pancake-host-state/pancake.env && pancake bootstrap pancake-recipe.yaml"
    exit 1
fi

# Create VM state directory
mkdir -p "$VM_DIR" "$SWTPM_DIR"

# Copy OVMF vars template if needed
if [ ! -f "$OVMF_VARS" ]; then
    cp "$OVMF_VARS_TEMPLATE" "$OVMF_VARS"
    echo "[boot] created OVMF_VARS at $OVMF_VARS"
fi

# Stop existing VM if running
if [ -f "$VM_PID" ]; then
    if sudo kill -0 $(sudo cat "$VM_PID") 2>/dev/null; then
        echo "[boot] stopping existing VM (pid $(sudo cat "$VM_PID"))"
        sudo kill $(sudo cat "$VM_PID")
        sleep 1
    fi
    sudo rm -f "$VM_PID"
fi

# Stop existing swtpm if running
if [ -f "$SWTPM_PID" ]; then
    if kill -0 $(cat "$SWTPM_PID") 2>/dev/null; then
        echo "[boot] stopping existing swtpm (pid $(cat "$SWTPM_PID"))"
        kill $(cat "$SWTPM_PID")
        sleep 1
    fi
    rm -f "$SWTPM_PID"
fi

# Initialize TPM state if needed
if [ ! -d "$SWTPM_DIR/tpm2" ]; then
    echo "[boot] initializing TPM state"
    swtpm_setup --tpm2 \
        --tpmstate "$SWTPM_DIR" \
        --createek --decryption --create-ek-cert \
        --create-platform-cert \
        --lock-nvram \
        --not-overwrite \
        --display
fi

# Start swtpm
echo "[boot] starting swtpm at $SWTPM_SOCK"
swtpm socket --tpm2 \
    --tpmstate dir="$SWTPM_DIR" \
    --ctrl type=unixio,path="$SWTPM_SOCK" \
    --pid file="$SWTPM_PID" \
    --daemon

# Wait for socket
for i in $(seq 1 10); do
    [ -S "$SWTPM_SOCK" ] && break
    sleep 0.5
done

# Start QEMU
echo "[boot] starting QEMU"
echo "  EFI image:    $EFI_IMG"
echo "  Console log:  $VM_CONSOLE"
echo "  SSH:          ssh -p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost"
echo "  gRPC (pancaked): localhost:$GRPC_PORT"

sudo qemu-system-x86_64 -enable-kvm -cpu host -m 4G -smp 4 \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$OVMF_VARS" \
    -drive file="$EFI_IMG",format=raw,if=virtio \
    -netdev user,id=net0,hostfwd=tcp::"$SSH_PORT"-:22,hostfwd=tcp::"$GRPC_PORT"-:7878 \
    -device virtio-net,netdev=net0 \
    -chardev socket,id=tpmsock,path="$SWTPM_SOCK" \
    -tpmdev emulator,id=tpm0,chardev=tpmsock \
    -device tpm-crb,tpmdev=tpm0 \
    -display none -serial file:"$VM_CONSOLE" \
    -pidfile "$VM_PID" -daemonize

echo "[boot] VM started (pid $(sudo cat "$VM_PID"))"
echo ""
echo "To watch boot log:  sudo tail -f $VM_CONSOLE"
echo "To stop VM:         sudo kill \$(sudo cat $VM_PID)"
echo ""
echo "Waiting for SSH..."

# Wait for SSH
for i in $(seq 1 60); do
    if nc -z localhost "$SSH_PORT" 2>/dev/null; then
        echo "SSH port open after ${i}s"
        echo ""
        echo "Connect with: ssh -p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost"
        exit 0
    fi
    sleep 2
done

echo "warning: SSH didn't come up after 120s"
echo "Check: sudo tail -f $VM_CONSOLE"
