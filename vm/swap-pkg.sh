#!/usr/bin/env bash
# Live-swap the rootfs via pivot_root (which calls chroot_fs_refs internally
# to update EVERY task's fs.root atomically — this is the system-wide swap).
#
#   ./swap-pkg.sh sshd v2
#
# Workflow (in the VM):
#   1. losetup + veritysetup open the new pkg image, mount RO at /run/lowers/<NAME>
#   2. mkdir /run/newroot ; mount overlay there with the new lower stack
#   3. mount proc/sys/dev as children of /run/newroot
#   4. /run/pivot-root /run/newroot  → does pivot_root + lazy umount
#   5. systemctl restart ssh / chrony so they re-exec from new binaries
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

PIVOT_BIN="../pivot-root"
[ -x "$PIVOT_BIN" ] || { echo "build $PIVOT_BIN first (cc -o $PIVOT_BIN ../pivot-root.c)" >&2; exit 1; }

SSH_OPTS=( -i keys/pancake_id_ed25519 -p 2222 -q
           -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
           -o LogLevel=ERROR )

echo "[swap-pkg] tar-piping bits + pivot binary into VM /run"
tar c \
    --transform="s|.*/pivot-root$|pivot-root|" \
    --transform="s|^images/||" \
    "$IMG" "$HASH" "$RH" "$PIVOT_BIN" \
  | ssh "${SSH_OPTS[@]}" root@127.0.0.1 \
        "tar x -C /run/ && chmod +x /run/pivot-root"

ssh "${SSH_OPTS[@]}" root@127.0.0.1 bash -s "$PKG" "$VER" <<'IN_VM'
set -euo pipefail
PKG="$1"
VER="$2"
NAME="${PKG}-${VER}"
NEWROOT="/run/newroot"
LOWER_PATH="/run/lowers/${NAME}"

cd /run
RH=$(cat "${NAME}.roothash")

# Idempotent cleanup
echo "[in-vm] cleanup"
for m in "$NEWROOT/proc" "$NEWROOT/sys" "$NEWROOT/dev" "$NEWROOT" "$LOWER_PATH"; do
    mountpoint -q "$m" 2>/dev/null && umount -l "$m" || true
done
veritysetup status "v_${NAME}" >/dev/null 2>&1 && veritysetup close "v_${NAME}" || true
for L in $(losetup -a | awk -F: -v p="/run/${NAME}" '$0 ~ p {print $1}'); do losetup -d "$L" || true; done
rm -rf "$NEWROOT" /run/newroot-upper /run/newroot-work

echo "[in-vm] verity open ${NAME}"
DATA_LOOP=$(losetup --show -fr "${NAME}.img")
HASH_LOOP=$(losetup --show -fr "${NAME}.hash")
veritysetup open "$DATA_LOOP" "v_${NAME}" "$HASH_LOOP" "$RH"
mkdir -p "$LOWER_PATH"
mount -o ro "/dev/mapper/v_${NAME}" "$LOWER_PATH"

# Build new lower list — new pkg first, everything else from /lowers/* except old slot
LOWERS=( "$LOWER_PATH" )
for d in /lowers/*; do
    n=$(basename "$d")
    [ "$n" = "$PKG" ] && continue
    LOWERS+=( "$d" )
done
LOWERSPEC=$(IFS=:; echo "${LOWERS[*]}")

echo "[in-vm] BEFORE swap:"
echo "  banner:  $(cat /etc/issue.net 2>/dev/null || echo '(none)')"
echo "  marker:  $(cat /etc/pancake-version-${PKG} 2>/dev/null || echo '(none)')"
echo "  PID 1 mountinfo lines: $(wc -l < /proc/1/mountinfo)"

echo "[in-vm] make / and child mounts private (pivot_root rejects shared propagation)"
mount --make-rprivate /

# overlay won't accept overlay-on-overlay as upperdir, so put upper/work on
# /run (tmpfs). After we rbind /run into NEW the same paths remain visible
# inside the new root — that's fine because overlay holds inode refs, not paths.
mkdir -p /run/pancake-pivot/upper /run/pancake-pivot/work

echo "[in-vm] staging new root at ${NEWROOT}"
mkdir -p "$NEWROOT"
mount -t overlay -o "lowerdir=${LOWERSPEC},upperdir=/run/pancake-pivot/upper,workdir=/run/pancake-pivot/work" \
    overlay "$NEWROOT"
mount --make-private "$NEWROOT"

# Rbind the dynamic-state mounts so daemons keep their sockets, dev nodes,
# tmpfs, etc. across the pivot. systemd's /run/systemd/private etc. survive.
# /lowers also rbinds so subsequent swaps can still reference base/chronyd/etc.
for d in proc sys dev run tmp lowers; do
    [ -d "/$d" ] || continue
    mkdir -p "$NEWROOT/$d"
    mount --rbind "/$d" "$NEWROOT/$d"
    mount --make-rprivate "$NEWROOT/$d"
done

echo "[in-vm] /run/pivot-root ${NEWROOT}"
chmod +x /run/pivot-root
/run/pivot-root "$NEWROOT"

# Restore shared propagation — systemd hardcodes MS_REC|MS_SHARED on / at
# boot (mount-setup.c:520) and explicitly documents that things break if /
# isn't shared (Lennart, docs/CONTAINER_INTERFACE.md commit 32f4e30b).
echo "[in-vm] mount --make-rshared / (restore systemd-expected state)"
mount --make-rshared /

echo
echo "[in-vm] AFTER pivot_root (chroot_fs_refs should have updated all tasks):"
echo "  banner:  $(cat /etc/issue.net 2>/dev/null || echo '(none)')"
echo "  marker:  $(cat /etc/pancake-version-${PKG} 2>/dev/null || echo '(none)')"
echo "  PID 1 mountinfo lines: $(wc -l < /proc/1/mountinfo 2>&1)"
echo "  PID 1 first mount: $(head -1 /proc/1/mountinfo 2>&1)"

case "$PKG" in
    sshd)    UNIT=ssh ;;
    chronyd) UNIT=chrony ;;
    *)       UNIT="$PKG" ;;
esac
echo "[in-vm] systemctl restart ${UNIT}"
systemctl restart "$UNIT" 2>&1 || echo "  (restart returned $?)"
systemctl is-active "$UNIT" 2>&1
IN_VM

echo
echo "[swap-pkg] done. Probe with: ssh -i keys/pancake_id_ed25519 -p 2222 root@127.0.0.1"
