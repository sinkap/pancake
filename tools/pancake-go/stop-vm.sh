#!/bin/bash
# Stop running pancake-os VM

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="${SCRIPT_DIR}/vm-state"
VM_PID="${VM_DIR}/vm.pid"
SWTPM_PID="${VM_DIR}/tpm/swtpm.pid"

stopped=0

# Stop VM
if [ -f "$VM_PID" ]; then
    if sudo kill -0 $(sudo cat "$VM_PID") 2>/dev/null; then
        echo "[stop] stopping VM (pid $(sudo cat "$VM_PID"))"
        sudo kill $(sudo cat "$VM_PID")
        stopped=1
    fi
    sudo rm -f "$VM_PID"
fi

# Stop swtpm
if [ -f "$SWTPM_PID" ]; then
    if kill -0 $(cat "$SWTPM_PID") 2>/dev/null; then
        echo "[stop] stopping swtpm (pid $(cat "$SWTPM_PID"))"
        kill $(cat "$SWTPM_PID")
        stopped=1
    fi
    rm -f "$SWTPM_PID"
fi

if [ $stopped -eq 0 ]; then
    echo "[stop] no running VM found"
else
    echo "[stop] done"
fi
