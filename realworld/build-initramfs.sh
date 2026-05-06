#!/usr/bin/env bash
# Build initramfs.cpio.gz: a minimal Debian rootfs with bash, mount,
# veritysetup, kmod (modprobe with .ko.zst support), plus the host kernel's
# modules under /lib/modules/$(uname -r), plus our /init.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
. ./lib.sh

STAGE="${STAGE:-staging/initramfs}"
OUT="${OUT:-images/assix-initramfs.cpio.gz}"
SUITE="${SUITE:-noble}"
MIRROR="${MIRROR:-http://archive.ubuntu.com/ubuntu/}"
COMPONENTS="${COMPONENTS:-main,universe}"
KVER="${KVER:-$(uname -r)}"

# Just enough to: modprobe, veritysetup, mount, busybox-style switch_root.
PKGS=(
    bash coreutils util-linux mount
    cryptsetup-bin
    kmod                 # modprobe with .ko.zst support
    libzstd1
    udev                 # for /dev/disk/by-id symlinks
)

if [ "${FORCE:-0}" = 1 ] || [ ! -d "$STAGE" ]; then
    log "mmdebstrap initramfs base → $STAGE"
    sudo rm -rf "$STAGE"
    sudo mmdebstrap --variant=essential \
        --components="$COMPONENTS" \
        --include="$(IFS=,; echo "${PKGS[*]}")" \
        "$SUITE" "$STAGE" "$MIRROR"
fi

log "installing /init"
sudo install -m 0755 init "$STAGE/init"

# Copy the running kernel's modules so modprobe can find them.
KMOD_SRC="/lib/modules/$KVER"
KMOD_DST="$STAGE/lib/modules/$KVER"
log "copying $KMOD_SRC → initramfs (this is a few MB compressed)"
sudo rm -rf "$KMOD_DST"
sudo mkdir -p "$KMOD_DST"
# Copy only what we plausibly need: dm + overlay + ext4 + crypto.
# Easier and more robust: copy the whole kernel/ subtree (~30-60 MB).
sudo cp -a "$KMOD_SRC/kernel" "$KMOD_DST/"
for f in modules.builtin modules.builtin.modinfo modules.order; do
    [ -f "$KMOD_SRC/$f" ] && sudo cp "$KMOD_SRC/$f" "$KMOD_DST/" || true
done
log "depmod -b $STAGE $KVER"
sudo depmod -b "$STAGE" "$KVER"

# Create the cpio archive (newc format, gzip).
log "packing cpio.gz → $OUT"
mkdir -p "$(dirname "$OUT")"
( cd "$STAGE" && sudo find . -print0 \
    | sudo cpio --null --create --format=newc --quiet ) \
    | gzip -1 > "$OUT"
log "wrote $OUT ($(du -h "$OUT" | awk '{print $1}'))"
