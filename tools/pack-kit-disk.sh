#!/usr/bin/env bash
# pack-kit-disk.sh — wrap a kit/ dir into a single ext4 disk image suitable
# for attaching to QEMU as the pancake state partition.
#
#   pack-kit-disk.sh <kit-dir> <out.img>
#
# The image label is "PANCAKE_STATE" so initramfs can find it via blkid;
# we also recommend wiring the disk's serial in QEMU for the SERIAL= path.

set -euo pipefail

KIT="${1:?usage: $0 <kit-dir> <out.img>}"
OUT="${2:?usage: $0 <kit-dir> <out.img>}"
[ -d "$KIT" ] || { echo "no such kit: $KIT" >&2; exit 1; }

# Size: kit du * 1.15 + 64 MiB headroom, rounded to 4 KiB.
size_kb=$(sudo du -sk "$KIT" | awk '{print $1}')
img_kb=$(( size_kb * 115 / 100 + 64 * 1024 ))
img_kb=$(( (img_kb + 3) / 4 * 4 ))

echo "[pack-kit-disk] $img_kb KiB ext4 image at $OUT"
rm -f "$OUT"
truncate -s "${img_kb}K" "$OUT"
sudo mkfs.ext4 -q -F -L PANCAKE_STATE -d "$KIT" -E no_copy_xattrs "$OUT"
sudo chown "$(id -u):$(id -g)" "$OUT"

echo "[pack-kit-disk] done. attach with:"
echo "  -drive file=$OUT,format=raw,if=none,id=pstate,readonly=on"
echo "  -device virtio-blk,drive=pstate,serial=pancake-state"
echo "  -append \"... pancake.state=SERIAL=pancake-state ...\""
