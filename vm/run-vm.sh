#!/usr/bin/env bash
# Boot the pancake VM under qemu/kvm.
#
# Each package contributes 2 virtio-blk disks (data + hash). They get serial
# numbers so the guest can find them via /dev/disk/by-id/virtio-<serial> —
# robust against vd[a-z] reordering.
#
# Lower order (leftmost wins): sshd → chronyd → base. So /etc/ssh comes from
# the sshd image, not base.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

# Default to the bpf-next/for-next build (Brauner's MOVE_MOUNT_BENEATH-on-rootfs
# fix is in this build; will land in 7.2 stable).
KERNEL="${KERNEL:-$HOME/projects/linux-bpf-for-next/arch/x86/boot/bzImage}"
INITRD="${INITRD:-images/pancake-initramfs.cpio.gz}"
MEM="${MEM:-2G}"
SMP="${SMP:-2}"
HOSTFWD_PORT="${HOSTFWD_PORT:-2222}"

# Order matters: leftmost wins in overlay lookup.
PKGS=(
    "sshd:images/sshd-v1"
    "chronyd:images/chronyd-v1"
    "base:images/base"
)

[ -r "$KERNEL" ] || { echo "cannot read $KERNEL" >&2; exit 1; }
[ -r "$INITRD" ] || { echo "no initrd at $INITRD — run build-initramfs.sh" >&2; exit 1; }

DRIVES=()
APPENDS=()
for spec in "${PKGS[@]}"; do
    name="${spec%%:*}"
    base_path="${spec#*:}"
    img="${base_path}.img"
    hashf="${base_path}.hash"
    rh_file="${base_path}.roothash"
    for f in "$img" "$hashf" "$rh_file"; do
        [ -r "$f" ] || { echo "missing $f — build with build-base.sh / build-pkg.sh" >&2; exit 1; }
    done
    rh=$(cat "$rh_file")

    DRIVES+=( -drive "file=${img},format=raw,if=none,id=d-${name}-d,readonly=on" )
    DRIVES+=( -device "virtio-blk,drive=d-${name}-d,serial=pancake-${name}-d" )
    DRIVES+=( -drive "file=${hashf},format=raw,if=none,id=d-${name}-h,readonly=on" )
    DRIVES+=( -device "virtio-blk,drive=d-${name}-h,serial=pancake-${name}-h" )

    # Pass serials only; /init resolves them via /sys/block/vd*/serial.
    APPENDS+=( "pancake.pkg=${name}:pancake-${name}-d:pancake-${name}-h:${rh}" )
done

mkdir -p share

set -x
exec qemu-system-x86_64 \
    -enable-kvm -cpu host -m "$MEM" -smp "$SMP" \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "console=ttyS0 rdinit=/init systemd.journald.forward_to_console=1 systemd.log_target=console ${APPENDS[*]}" \
    "${DRIVES[@]}" \
    -netdev "user,id=net0,hostfwd=tcp::${HOSTFWD_PORT}-:22" \
    -device "virtio-net,netdev=net0" \
    -virtfs "local,path=$(pwd)/share,mount_tag=hostshare,security_model=none,id=h0" \
    -nographic
