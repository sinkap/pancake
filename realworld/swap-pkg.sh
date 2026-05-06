#!/usr/bin/env bash
# Live-swap a daemon overlay LAYER inside the unified-rootfs overlay.
#
#   ./swap-pkg.sh sshd v2
#
# Requires kernel with Brauner's "MOVE_MOUNT_BENEATH on the rootfs" fix
# (in bpf-next/for-next; lands in 7.2). Workflow per his commit message:
#
#   1. Stage a complete new root tree at /run/newroot:
#      - overlay mount (lowerdir = new pkg + chronyd + base, fresh upper/work)
#      - /proc, /sys, /dev mounted as children so they survive the detach
#   2. open_tree(... OPEN_TREE_CLONE | AT_RECURSIVE) → detached subtree fd
#   3. move_mount(... MOVE_MOUNT_BENEATH) at /
#   4. chroot(".") + umount2(".", MNT_DETACH) — atomic root switch
#
# Caveat: only the calling process's fs.root is updated by chroot.
# systemd PID 1 and other running processes keep their old root view.
# Live update of those daemons is achieved by the per-mount swap pattern,
# not by a rootfs swap. Use this script as a research/demo tool.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

PKG="${1:?usage: $0 <pkg> <ver>}"
VER="${2:?need version label}"

IMG="images/${PKG}-${VER}.img"
HASH="images/${PKG}-${VER}.hash"
RH="images/${PKG}-${VER}.roothash"
for f in "$IMG" "$HASH" "$RH"; do
    [ -r "$f" ] || { echo "missing $f" >&2; exit 1; }
done

ASSIX_SWAP_ROOTFS="../assix-swap-rootfs"
[ -x "$ASSIX_SWAP_ROOTFS" ] || { echo "build $ASSIX_SWAP_ROOTFS first (cd .. && make)" >&2; exit 1; }

SSH_OPTS=( -i keys/assix_id_ed25519 -p 2222 -q
           -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
           -o LogLevel=ERROR )

echo "[swap-pkg] tar-piping ${PKG}-${VER} bits + assix-swap-rootfs into VM /run"
tar c \
    --transform="s|.*/assix-swap-rootfs$|assix-swap-rootfs|" \
    --transform="s|^images/||" \
    "$IMG" "$HASH" "$RH" "$ASSIX_SWAP_ROOTFS" \
  | ssh "${SSH_OPTS[@]}" root@127.0.0.1 \
        "tar x -C /run/ && chmod +x /run/assix-swap-rootfs"

ssh "${SSH_OPTS[@]}" root@127.0.0.1 bash -s "$PKG" "$VER" <<'IN_VM'
set -euo pipefail
PKG="$1"
VER="$2"
NAME="${PKG}-${VER}"
NEWROOT="/run/newroot"

cd /run
RH=$(cat "${NAME}.roothash")
LOWER_PATH="/run/lowers/${NAME}"

# Idempotent cleanup of any leftover state.
echo "[in-vm] cleanup of any prior state"
for m in "$NEWROOT/proc" "$NEWROOT/sys" "$NEWROOT/dev" "$NEWROOT" "$LOWER_PATH"; do
    mountpoint -q "$m" 2>/dev/null && umount -l "$m" || true
done
if veritysetup status "v_${NAME}" >/dev/null 2>&1; then
    veritysetup close "v_${NAME}"
fi
for L in $(losetup -a | awk -F: -v img="/run/${NAME}.img"  '$0 ~ img  {print $1}'); do
    losetup -d "$L" || true
done
for L in $(losetup -a | awk -F: -v hsh="/run/${NAME}.hash" '$0 ~ hsh  {print $1}'); do
    losetup -d "$L" || true
done
rm -rf "$NEWROOT" /run/newroot-upper /run/newroot-work

echo "[in-vm] losetup + veritysetup open ${NAME} (roothash=${RH:0:16}...)"
DATA_LOOP=$(losetup --show -fr "${NAME}.img")
HASH_LOOP=$(losetup --show -fr "${NAME}.hash")
veritysetup open "$DATA_LOOP" "v_${NAME}" "$HASH_LOOP" "$RH"
mkdir -p "$LOWER_PATH"
mount -o ro "/dev/mapper/v_${NAME}" "$LOWER_PATH"

# Build the new lower list. New pkg first (leftmost wins), then everything
# else from /lowers/* except the slot we're replacing.
LOWERS=( "$LOWER_PATH" )
for d in /lowers/*; do
    name=$(basename "$d")
    [ "$name" = "$PKG" ] && continue
    LOWERS+=( "$d" )
done
LOWERSPEC=$(IFS=:; echo "${LOWERS[*]}")

echo "[in-vm] BEFORE swap (target=/):"
echo "  banner:  $(cat /etc/issue.net 2>/dev/null || echo '(none)')"
echo "  marker:  $(cat /etc/assix-version-${PKG} 2>/dev/null || echo '(none)')"
echo "  PID 1 mountinfo / lines:"
grep -c " / " /proc/1/mountinfo | sed 's/^/    line count: /'

# Stage the complete new root tree at /run/newroot.
echo
echo "[in-vm] staging new root at $NEWROOT"
mkdir -p "$NEWROOT" /run/newroot-upper /run/newroot-work

echo "  overlay mount (lowerdir=$LOWERSPEC)"
mount -t overlay -o "lowerdir=$LOWERSPEC,upperdir=/run/newroot-upper,workdir=/run/newroot-work" \
    overlay "$NEWROOT"

# Mount proc/sys/dev as children of NEWROOT so they survive the rootfs swap.
# Use the merged tree's own /proc /sys /dev directories (inherited from base).
echo "  mounting proc/sys/dev as children of $NEWROOT"
mount -t proc  proc  "$NEWROOT/proc"
mount -t sysfs sys   "$NEWROOT/sys"
# devtmpfs is special — bind from existing /dev so we get the same dev nodes.
mount --rbind /dev   "$NEWROOT/dev"

echo "  prepared mount tree at $NEWROOT:"
findmnt -R "$NEWROOT" -o TARGET,SOURCE,FSTYPE 2>/dev/null | sed 's/^/    /'

# The actual swap.
echo
echo "[in-vm] invoking assix-swap-rootfs $NEWROOT"
/run/assix-swap-rootfs "$NEWROOT" || {
    rc=$?
    echo "[in-vm] assix-swap-rootfs FAILED (rc=$rc)"; dmesg | tail -10 | sed 's/^/  /'; exit $rc
}

echo
echo "[in-vm] AFTER swap (note: this shell still has OLD fs.root — see PID 1 below)"
# At this point the calling shell can't reliably read /proc anymore (its
# old root's /proc was lazy-detached). Probe via PID 1 which IS the namespace.
echo "  PID 1 (systemd) mountinfo (this shows the namespace's CURRENT view):"
cat /proc/1/mountinfo 2>&1 | head -10 | sed 's/^/    /'
IN_VM

echo
echo "[swap-pkg] done."
echo "[swap-pkg] To test from a fresh process (the only way to actually see new root):"
echo "  ssh -i keys/assix_id_ed25519 -p 2222 root@127.0.0.1 'cat /etc/issue.net'"
echo "    (will show OLD banner because sshd's fs.root is still the old root)"
