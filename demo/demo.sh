#!/usr/bin/env bash
# demo.sh — end-to-end pancake-os demo:
#   1. build pancake-build-server container
#   2. start container with persistent layer cache
#   3. bootstrap a signed UEFI kit via the build server
#   4. boot the kit in QEMU under OVMF + swtpm
#   5. run `pancake enroll` inside the VM (token + EK)
#   6. run `pancake attest` from the host (5 checks)
#
# All output land in /var/tmp/pancake-demo/. Re-run is idempotent —
# previous container, swtpm, VM, and artifacts are torn down first.
#
# Usage:
#   demo.sh --bzimage=PATH/to/bzImage          (required: kernel built from
#                                              bpf-next/for-next or any tree
#                                              with Brauner's nullfs series)
#   demo.sh --auth-key=PATH                    (default: ~/.ssh/id_ed25519.pub)
#   demo.sh --port=N                           (host SSH forward, default 2230)
#   demo.sh --skip-attest                      (boot only, leave running)
#   demo.sh --snp                              (launch as SEV-SNP confidential
#                                              guest; requires kvm_amd.sev_snp=1
#                                              and SEV-enabled OVMF on the host)
#
# Required tools on the host:
#   docker, qemu-system-x86_64, OVMF firmware (/usr/share/OVMF/OVMF_*.fd),
#   swtpm + swtpm_setup, tpm2-tools (for the verifier-side checks),
#   nc (for port readiness probes).

set -euo pipefail

# ---------- argument parsing ----------------------------------------
BZIMAGE=""
AUTH_KEY="${HOME}/.ssh/id_ed25519.pub"
SSH_PORT=2230
GRPC_PORT=7878
SKIP_ATTEST=0
SNP=0

for arg in "$@"; do
    case "$arg" in
        --bzimage=*)    BZIMAGE="${arg#*=}" ;;
        --auth-key=*)   AUTH_KEY="${arg#*=}" ;;
        --port=*)       SSH_PORT="${arg#*=}" ;;
        --skip-attest)  SKIP_ATTEST=1 ;;
        --snp)          SNP=1 ;;
        -h|--help)
            sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done
[ -n "$BZIMAGE" ] || { echo "demo.sh: --bzimage=PATH is required" >&2; exit 2; }
[ -r "$BZIMAGE" ] || { echo "demo.sh: --bzimage=$BZIMAGE not readable" >&2; exit 2; }
[ -r "$AUTH_KEY" ] || { echo "demo.sh: --auth-key=$AUTH_KEY not readable" >&2; exit 2; }

# ---------- paths ---------------------------------------------------
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PANCAKE_GO="$REPO/tools/pancake-go"
WORK=/var/tmp/pancake-demo
KIT="$WORK/kit"
EFI_IMG="$WORK/efi.img"
INITRAMFS="$WORK/initramfs.cpio.gz"
BZ_OUT="$WORK/bzImage"
KEY="$WORK/dev.key"
CERT="$WORK/dev.crt"
SWTPM_STATE="/var/lib/swtpm/pancake-demo"
SWTPM_SOCK="/tmp/pancake-demo-swtpm.sock"
OVMF_VARS="$WORK/OVMF_VARS.fd"
VM_CONSOLE="$WORK/vm.console"
VM_PID="$WORK/vm.pid"
EK_PUB="$WORK/ek.pub"
RECIPE="$WORK/recipe.toml"
CONTAINER=pancake-build-server-demo
CACHE_VOL=pancake-build-cache-demo

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

# ---------- preflight ----------------------------------------------
say "preflight"
for cmd in docker qemu-system-x86_64 swtpm swtpm_setup tpm2_makecredential nc go; do
    command -v "$cmd" >/dev/null || { echo "missing: $cmd" >&2; exit 1; }
done
[ -f /usr/share/OVMF/OVMF_CODE_4M.fd ] || { echo "missing OVMF firmware" >&2; exit 1; }

# ---------- build pancake binaries ---------------------------------
say "build pancake binaries"
( cd "$PANCAKE_GO" && CGO_ENABLED=0 go build -ldflags='-s -w' \
    -o bin/pancake              ./cmd/pancake \
    -o bin/pancaked             ./daemon/pancaked \
    -o bin/pancake-build-server ./server/cmd ) 2>&1 | sed 's/^/  /'
PANCAKE="$PANCAKE_GO/bin/pancake"

# ---------- tear down previous run ---------------------------------
say "tearing down previous demo state"
sudo kill "$(sudo cat "$VM_PID" 2>/dev/null)" 2>/dev/null || true
docker rm -f "$CONTAINER" 2>/dev/null || true
SWTPM_PIDS=$(pgrep -f "swtpm.*pancake-demo" 2>/dev/null | head -3 || true)
if [ -n "$SWTPM_PIDS" ]; then sudo kill $SWTPM_PIDS 2>/dev/null || true; fi
sudo rm -rf "$WORK" "$SWTPM_STATE" "$SWTPM_SOCK"
sudo mkdir -p "$WORK" "$SWTPM_STATE"
sudo chown "$USER" "$WORK"

# ---------- build + start build-server container -------------------
say "build pancake-build-server container image"
docker build -f "$PANCAKE_GO/server/Dockerfile" \
    -t pancake-build-server "$PANCAKE_GO" 2>&1 | tail -3 | sed 's/^/  /'

say "start build server (cache: docker volume $CACHE_VOL)"
docker volume inspect "$CACHE_VOL" >/dev/null 2>&1 || docker volume create "$CACHE_VOL"
docker run -d --name "$CONTAINER" --privileged \
    -p "${GRPC_PORT}:7879" \
    -v "$CACHE_VOL":/var/lib/pancake-build-server \
    pancake-build-server >/dev/null
for i in 1 2 3 4 5; do
    nc -z localhost "$GRPC_PORT" 2>/dev/null && break
    sleep 1
done

# ---------- recipe + bootstrap -------------------------------------
say "write recipe → $RECIPE"
cat > "$RECIPE" <<EOF
output   = "$KIT"
hostname = "pancake-demo"
packages = ["openssh-server", "chrony", "nano"]

[distro]
suite = "noble"

[ssh]
authorized-keys = "$AUTH_KEY"

[kernel]
version = "tree"
bzimage = "$BZIMAGE"

[outputs]
image     = ""
initramfs = "$INITRAMFS"
bzimage   = "$BZ_OUT"
efi       = "$EFI_IMG"

[signing]
key  = "$KEY"
cert = "$CERT"

[advanced]
src-root = "$REPO"
EOF

say "bootstrap kit via build server (this runs mmdebstrap server-side, ~3 min cold)"
sudo "$PANCAKE" bootstrap --builder=localhost:"$GRPC_PORT" "$RECIPE" \
    2>&1 | tail -10 | sed 's/^/  /'

# ---------- swtpm + OVMF + boot ------------------------------------
say "set up swtpm + OVMF vars"
sudo swtpm_setup --tpm2 --tpmstate "$SWTPM_STATE" \
    --create-ek-cert --create-platform-cert --lock-nvram >/dev/null 2>&1
sudo swtpm socket --tpm2 --tpmstate dir="$SWTPM_STATE" \
    --ctrl type=unixio,path="$SWTPM_SOCK" \
    --log file="$WORK/swtpm.log",level=20 --daemon
sudo cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS"
sleep 0.3

# Pick OVMF firmware. Plain 4M is fine for non-SNP. For --snp we
# prefer an SEV-built variant (OVMF.amdsev.fd / OVMF_CODE_4M_SEV.fd
# depending on the distro); fall back to the standard one if the SEV
# build isn't installed (the launch will likely fail then — caller
# will see the QEMU error and know to install ovmf.amdsev or build
# edk2 with -DSEV_ENABLE).
OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
if [ "$SNP" = 1 ]; then
    for c in /usr/share/OVMF/OVMF.amdsev.fd \
             /usr/share/OVMF/OVMF_CODE_4M_SEV.fd \
             /usr/share/edk2/x64/OVMF.amdsev.fd; do
        if [ -r "$c" ]; then OVMF_CODE="$c"; break; fi
    done
    say "SNP requested — using OVMF: $OVMF_CODE"
    [ -e /dev/sev ] || echo "  WARN: /dev/sev missing — host kernel may not have kvm_amd.sev_snp=1"
fi

# Assemble SNP-specific QEMU args (empty when --snp not set).
SNP_ARGS=()
if [ "$SNP" = 1 ]; then
    SNP_ARGS=(
        -machine "q35,confidential-guest-support=sev0,memory-backend=ram1,kernel-irqchip=split"
        -object  "memory-backend-memfd,id=ram1,size=4G,share=true,prealloc=false"
        -object  "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1"
    )
else
    SNP_ARGS=(-machine q35)
fi

say "boot pancake-os under OVMF + swtpm$([ "$SNP" = 1 ] && echo " + SEV-SNP") (sshd on host port $SSH_PORT)"
sudo qemu-system-x86_64 -enable-kvm -cpu host -m 4G -smp 4 \
    "${SNP_ARGS[@]}" \
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

say "wait for sshd"
SSH_KEY="${AUTH_KEY%.pub}"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=2 -o LogLevel=ERROR"
for i in $(seq 1 30); do
    if ssh $SSH_OPTS -p "$SSH_PORT" root@localhost true 2>/dev/null; then
        echo "  sshd up after ${i}s"; break
    fi
    sleep 2
done

if [ "$SKIP_ATTEST" = 1 ]; then
    say "VM up — ssh root@localhost -p $SSH_PORT"
    say "attest skipped (--skip-attest); kill VM with: sudo kill \$(sudo cat $VM_PID)"
    exit 0
fi

# ---------- enroll inside VM ---------------------------------------
say "pancake enroll inside VM (seal token + export EK)"
ssh $SSH_OPTS -p "$SSH_PORT" root@localhost \
    "pancake enroll 2>&1 | tail -20" | sed 's/^/  /'
ssh $SSH_OPTS -p "$SSH_PORT" root@localhost "cat /etc/pancake/ek.pub" > "$EK_PUB"
echo "  EK pulled to host: $EK_PUB ($(wc -c < "$EK_PUB") bytes)"

# ---------- attest from host ---------------------------------------
ATTEST_MODE=tpm
[ "$SNP" = 1 ] && ATTEST_MODE=both
say "pancake attest from host (--mode=$ATTEST_MODE)"
sudo "$PANCAKE" attest \
    --target=localhost:"$GRPC_PORT" \
    --ek-pub="$EK_PUB" \
    --kit="$KIT" \
    --gen=1 \
    --mode="$ATTEST_MODE" 2>&1 | sed 's/^/  /'

say "demo done"
echo "  artifacts:    $WORK"
echo "  ssh into VM:  ssh -i $SSH_KEY -p $SSH_PORT root@localhost"
echo "  kill VM:      sudo kill \$(sudo cat $VM_PID)"
echo "  stop server:  docker rm -f $CONTAINER"
