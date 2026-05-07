#!/usr/bin/env bash
# Build the pancake-os initramfs:
#   busybox + bash + cryptsetup-bin + kmod + ext4 tools
#   + the host's /lib/modules/$(uname -r)
#   + initramfs/init (manifest-driven boot)
#
#   tools/build-pancake-initramfs.sh <out.cpio.gz>
set -euo pipefail
ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
OUT="${1:?usage: $0 <out.cpio.gz>}"
STAGE="${STAGE:-/tmp/pancake-initramfs-stage}"
SUITE="${SUITE:-noble}"
MIRROR="${MIRROR:-http://archive.ubuntu.com/ubuntu/}"
KVER="${KVER:-$(uname -r)}"

PKGS=(
    bash coreutils util-linux mount
    cryptsetup-bin
    kmod libzstd1
    udev
    e2fsprogs                 # for blkid of the state partition
)

if [ "${FORCE:-0}" = 1 ] || [ ! -d "$STAGE" ]; then
    echo "[build-initramfs] mmdebstrap → $STAGE"
    sudo rm -rf "$STAGE"
    sudo mmdebstrap --variant=essential \
        --components=main,universe \
        --include="$(IFS=,; echo "${PKGS[*]}")" \
        "$SUITE" "$STAGE" "$MIRROR"
fi

echo "[build-initramfs] installing /init"
sudo install -m 0755 "$ROOT/initramfs/init" "$STAGE/init"

echo "[build-initramfs] compiling + installing /sbin/mount-overlay"
cc -O2 -Wall -Wextra -o /tmp/mount-overlay "$ROOT/initramfs/mount-overlay.c"
sudo install -m 0755 /tmp/mount-overlay "$STAGE/sbin/mount-overlay"
rm /tmp/mount-overlay

echo "[build-initramfs] copying /lib/modules/$KVER → initramfs"
sudo rm -rf "$STAGE/lib/modules/$KVER"
sudo mkdir -p "$STAGE/lib/modules/$KVER"
sudo cp -a "/lib/modules/$KVER/kernel" "$STAGE/lib/modules/$KVER/"
for f in modules.builtin modules.builtin.modinfo modules.order; do
    [ -f "/lib/modules/$KVER/$f" ] && sudo cp "/lib/modules/$KVER/$f" "$STAGE/lib/modules/$KVER/" || true
done
sudo depmod -b "$STAGE" "$KVER"

echo "[build-initramfs] cpio.gz → $OUT"
mkdir -p "$(dirname "$OUT")"
( cd "$STAGE" && sudo find . -print0 | sudo cpio --null --create --format=newc --quiet ) \
    | gzip -1 > "$OUT"
echo "[build-initramfs] wrote $OUT ($(du -h "$OUT" | awk '{print $1}'))"
