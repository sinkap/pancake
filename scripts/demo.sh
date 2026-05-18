#!/bin/bash
# pancake-os end-to-end demo: bootstrap → boot → auto-enroll → attest

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[demo]${NC} $*"; }
warn() { echo -e "${YELLOW}[demo]${NC} $*"; }
error() { echo -e "${RED}[demo]${NC} $*"; exit 1; }

# Step 1: Initialize dev EK CA
log "Step 1/7: Initializing dev EK CA (one-time)..."
if [ ! -f "pancake-host-state/dev-ek-ca/ca.crt" ]; then
    ./init-dev-ek-ca.sh || error "Failed to initialize dev EK CA"
    log "✓ Dev EK CA created"
else
    log "✓ Dev EK CA already exists"
fi

# Step 2: Start Docker services
log "Step 2/7: Starting Docker services..."
if ! docker compose ps | grep -q "pancake-ca-server.*Up"; then
    docker compose up -d --wait || error "Failed to start Docker services"
fi
log "✓ Services running"

# Step 3: Initialize host certificates
log "Step 3/7: Initializing operator host certificates..."
if [ ! -f "pancake-host-state/pancake.env" ]; then
    pancake host-cert init || error "Failed to initialize host cert"
    log "✓ Host cert initialized"
else
    log "✓ Host cert already exists"
fi

# Step 4: Source environment
log "Step 4/7: Loading credentials..."
source pancake-host-state/pancake.env
log "✓ Credentials loaded"

# Step 5: Bootstrap VM image
log "Step 5/7: Bootstrapping VM image..."
if [ ! -f "pancake-efi.img" ]; then
    pancake bootstrap || error "Bootstrap failed"
    log "✓ Bootstrap complete"
else
    warn "EFI image exists, skipping bootstrap (run ./clean-state.sh to rebuild)"
fi

# Step 6: Boot VM
log "Step 6/7: Booting VM..."
./boot-vm.sh &
BOOT_PID=$!

# Wait for SSH with retries
SSH_PORT=2222
MAX_WAIT=60
log "Waiting for SSH (max ${MAX_WAIT}s)..."
for i in $(seq 1 $MAX_WAIT); do
    if nc -z localhost $SSH_PORT 2>/dev/null; then
        log "✓ SSH ready after ${i}s"
        break
    fi
    if [ $i -eq $MAX_WAIT ]; then
        error "SSH didn't come up after ${MAX_WAIT}s"
    fi
    sleep 1
done

# Wait for auto-enrollment to complete
log "Waiting for auto-enrollment..."
sleep 10
for i in $(seq 1 30); do
    if ssh -p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=2 root@localhost \
        "systemctl is-active pancaked" 2>/dev/null | grep -q "active"; then
        log "✓ Auto-enrollment complete, pancaked running"
        break
    fi
    if [ $i -eq 30 ]; then
        warn "pancaked not active after 30s, continuing anyway..."
        break
    fi
    sleep 1
done

# Step 7: Test attestation
log "Step 7/7: Testing TPM attestation..."
MAX_RETRIES=5
RETRY_DELAY=3
for attempt in $(seq 1 $MAX_RETRIES); do
    if pancake orchestrate attest --target localhost:7878 2>&1 | tee /tmp/attest-output.txt; then
        if grep -q "✓ Attestation successful" /tmp/attest-output.txt; then
            log "✓ Attestation successful"
            break
        fi
    fi
    if [ $attempt -eq $MAX_RETRIES ]; then
        error "Attestation failed after $MAX_RETRIES attempts"
    fi
    warn "Attestation attempt $attempt/$MAX_RETRIES failed, retrying in ${RETRY_DELAY}s..."
    sleep $RETRY_DELAY
done

echo ""
log "========================================="
log "Demo complete! VM is running."
log "========================================="
echo ""
echo "Useful commands:"
echo "  ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost"
echo "  pancake orchestrate attest --target localhost:7878"
echo "  pancake orchestrate get-current --target localhost:7878"
echo "  ./stop-vm.sh"
echo ""
