#!/usr/bin/env bash
# assix — overlay-on-dm-verity test harness.
#
# Builds N read-only dm-verity lowerdirs (each a small ext4 image with distinct
# content + a per-lower copy of /bin/sleep) plus a tmpfs upper/work, stacks them
# with overlayfs, and lets you exercise mount --move while a workload runs from
# the merged tree.
#
# This is the shell-script milestone — useful up to ~30-50 lowers before
# overlayfs's mount option-string limit bites. The follow-up will use the new
# mount API (fsopen/fsmount/move_mount) so we can blow past that.
#
# Usage:
#   sudo ./setup.sh up [N]           # default N=4
#   sudo ./setup.sh status
#   sudo ./setup.sh workload         # exec sleeper from merged, record pid
#   sudo ./setup.sh check            # sanity-check lower visibility + upper writes
#   sudo ./setup.sh move <new-path>  # mount --move and verify workload survives
#   sudo ./setup.sh down             # tear everything down
#
# Env knobs:
#   STATE_DIR      where to keep images/mountpoints/meta (default ~/ovl-verity-test)
#   LOWER_SIZE_MB  size of each ext4 lower image in MiB (default 16)
#   N_DEFAULT      default lower count when 'up' is called without N (default 4)

set -euo pipefail

STATE="${STATE_DIR:-$HOME/assix}"
N_DEFAULT="${N_DEFAULT:-4}"
LOWER_SIZE_MB="${LOWER_SIZE_MB:-16}"
DEV_PREFIX="assix"

MERGED="${STATE}/merged"
UPPER_TMPFS="${STATE}/rw"
UPPER="${UPPER_TMPFS}/upper"
WORK="${UPPER_TMPFS}/work"
LOWERS_DIR="${STATE}/lowers"
IMG_DIR="${STATE}/img"
META="${STATE}/meta"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { echo "error: $*" >&2; exit 1; }

need_root()  { [[ $EUID -eq 0 ]] || die "must run as root"; }
need_tool()  { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }
check_tools() {
    for t in veritysetup mkfs.ext4 losetup mount umount truncate awk findmnt nohup; do
        need_tool "$t"
    done
}

# Resolve current merged path (may have been moved).
merged_path() {
    if [[ -f "$META/merged_path" ]]; then
        cat "$META/merged_path"
    else
        echo "$MERGED"
    fi
}

# Build one verity-backed lower.
#   $1 name         e.g. "lower-1" or "alt-1"; used for img file, dm device, mountpoint
#   $2 slot         numeric slot for sleeper-$slot / info-$slot file names
#   $3 marker_value content of marker/which (visible iff this lower is leftmost)
#   $4 sleeper_src  path to a sleep-like binary to copy in
make_lower() {
    local name="$1" slot="$2" marker_value="$3" sleeper_src="$4"
    local img="$IMG_DIR/${name}.img"
    local hashf="$IMG_DIR/${name}.hash"
    local stage="$IMG_DIR/_stage-${name}"

    truncate -s "${LOWER_SIZE_MB}M" "$img"
    mkfs.ext4 -q -F -L "assix-${name}" "$img"
    mkdir -p "$stage"
    mount -o loop "$img" "$stage"
    mkdir -p "$stage/bin" "$stage/marker"
    cp "$sleeper_src" "$stage/bin/sleeper-${slot}"
    chmod 0755 "$stage/bin/sleeper-${slot}"
    echo "$marker_value" > "$stage/marker/which"
    echo "${name} ${marker_value} $(date -u +%FT%TZ)" > "$stage/marker/info-${slot}"
    sync
    umount "$stage"
    rmdir "$stage"

    : > "$hashf"
    local root_hash
    root_hash=$(veritysetup format "$img" "$hashf" \
                | awk '/Root hash/ {print $NF}')
    [[ -n "$root_hash" ]] || die "veritysetup format failed for ${name}"
    echo "${name} ${root_hash}" >> "$META/hashes"

    local data_loop hash_loop
    data_loop=$(losetup --show -fr "$img")
    hash_loop=$(losetup --show -fr "$hashf")
    echo "${name} data=${data_loop} hash=${hash_loop}" >> "$META/loops"

    veritysetup open "$data_loop" "${DEV_PREFIX}-${name}" "$hash_loop" "$root_hash"
    mkdir -p "$LOWERS_DIR/${name}"
    mount -o ro "/dev/mapper/${DEV_PREFIX}-${name}" "$LOWERS_DIR/${name}"

    echo "${name}" >> "$META/lowers_list"
}

cmd_up() {
    need_root
    check_tools
    local N="${1:-$N_DEFAULT}"
    [[ "$N" =~ ^[0-9]+$ && "$N" -ge 1 ]] || die "bad N: $N"

    [[ -e "$META/active" ]] && die "already up — run 'down' first"

    mkdir -p "$STATE"
    # MS_MOVE / MOVE_MOUNT_BENEATH refuse if the source's parent mount is
    # shared. `/` is shared on systemd distros, so anything under $STATE
    # inherits that. Root the whole tree in a private subtree by self-binding
    # $STATE and marking it private — every mount we create below is parented
    # to a non-shared mount.
    if ! findmnt -no TARGET "$STATE" >/dev/null 2>&1; then
        mount --bind "$STATE" "$STATE"
    fi
    mount --make-private "$STATE"

    mkdir -p "$IMG_DIR" "$LOWERS_DIR" "$META" "$MERGED" "$UPPER_TMPFS"
    echo "$N" > "$META/N"
    : > "$META/loops"
    : > "$META/hashes"
    : > "$META/lowers_list"
    rm -f "$META/merged_path"

    local sleeper
    sleeper="$(command -v sleep)" || die "no sleep binary"
    [[ -x "$sleeper" ]] || die "sleep not executable"

    log "building $N lower images + 1 alt (${LOWER_SIZE_MB} MiB each)"
    for i in $(seq 1 "$N"); do
        make_lower "lower-${i}" "${i}" "lower-${i}" "$sleeper"
    done
    # alt-1: a swap-target for slot 1. Same sleeper-1 path so a *new* exec of
    # /merged/bin/sleeper-1 after swap lands on the alt image.
    make_lower "alt-1" "1" "alt-1 (v2)" "$sleeper"

    log "mounting tmpfs for upper/work"
    mount -t tmpfs -o size=512M tmpfs "$UPPER_TMPFS"
    mkdir -p "$UPPER" "$WORK"

    # Build lowerdir list — leftmost = highest priority.
    local lower_list=""
    for i in $(seq 1 "$N"); do
        [[ -n "$lower_list" ]] && lower_list+=":"
        lower_list+="$LOWERS_DIR/lower-$i"
    done

    log "stacking overlay (${#lower_list} chars of lowerdir=)"
    mount -t overlay -o "lowerdir=${lower_list},upperdir=${UPPER},workdir=${WORK}" \
        overlay "$MERGED"

    # Required so we can later 'mount --move' it; shared propagation refuses MS_MOVE.
    mount --make-private "$MERGED"

    touch "$META/active"
    log "up: N=$N merged=$MERGED"
}

cmd_status() {
    if [[ ! -e "$META/active" ]]; then
        echo "down"
        return
    fi
    local m; m=$(merged_path)
    echo "merged: $m"
    findmnt "$m" 2>/dev/null || echo "  (not mounted?)"
    echo
    echo "lowers:"
    findmnt -R "$LOWERS_DIR" 2>/dev/null || ls "$LOWERS_DIR"
    echo
    echo "verity devs:"
    ls /dev/mapper 2>/dev/null | grep "^${DEV_PREFIX}-" || echo "  (none)"
    echo
    echo "loops:"
    cat "$META/loops" 2>/dev/null || true
    echo
    if [[ -f "$META/workload.pid" ]]; then
        local p; p=$(cat "$META/workload.pid")
        if kill -0 "$p" 2>/dev/null; then
            echo "workload: pid=$p ALIVE  exe=$(readlink /proc/$p/exe 2>/dev/null || echo '?')"
        else
            echo "workload: pid=$p DEAD"
        fi
    else
        echo "workload: none"
    fi
}

cmd_check() {
    [[ -e "$META/active" ]] || die "not up"
    local m; m=$(merged_path)
    local N; N=$(cat "$META/N")

    echo "== marker/which (should be 'lower-1' — leftmost wins) =="
    cat "$m/marker/which"

    echo "== per-lower marker files visible =="
    for i in $(seq 1 "$N"); do
        if [[ -f "$m/marker/info-$i" ]]; then
            printf "  lower-%-3d  %s\n" "$i" "$(cat "$m/marker/info-$i")"
        else
            printf "  lower-%-3d  MISSING\n" "$i"
        fi
    done

    echo "== per-lower sleeper binaries =="
    for i in $(seq 1 "$N"); do
        [[ -x "$m/bin/sleeper-$i" ]] || { echo "  sleeper-$i MISSING"; continue; }
    done
    echo "  all $N present"

    echo "== upperdir write test =="
    local stamp="ephemeral-$(date +%s)-$$"
    echo "$stamp" > "$m/$stamp"
    [[ "$(cat "$m/$stamp")" == "$stamp" ]] && echo "  upper write OK"
    [[ -f "$UPPER/$stamp" ]] && echo "  landed in upper: $UPPER/$stamp"
    rm -f "$m/$stamp"

    echo "== lower is read-only =="
    # Subshell so the redirection-time error (printed by bash before the
    # command's own 2>/dev/null can take effect) is suppressed by the outer
    # 2>/dev/null.
    if (echo x > "$LOWERS_DIR/lower-1/marker/which") 2>/dev/null; then
        echo "  WARN: lower-1 was writable!"
    else
        echo "  lower-1 rejects writes (expected)"
    fi
}

cmd_workload() {
    [[ -e "$META/active" ]] || die "not up"
    local m; m=$(merged_path)
    local bin="$m/bin/sleeper-1"
    [[ -x "$bin" ]] || die "no $bin"

    if [[ -f "$META/workload.pid" ]]; then
        local p; p=$(cat "$META/workload.pid")
        if kill -0 "$p" 2>/dev/null; then
            die "workload already running pid=$p"
        fi
    fi

    nohup "$bin" 99999 >"$STATE/workload.log" 2>&1 &
    local p=$!
    echo "$p" > "$META/workload.pid"
    sleep 0.2
    kill -0 "$p" 2>/dev/null || die "workload failed to start"
    echo "workload pid=$p"
    echo "  exe=$(readlink /proc/$p/exe)"
    echo "  cwd=$(readlink /proc/$p/cwd)"
}

cmd_move() {
    [[ -e "$META/active" ]] || die "not up"
    local newp="${1:-}"
    [[ -n "$newp" ]] || die "usage: move <new-path>"
    mkdir -p "$newp"
    local oldp; oldp=$(merged_path)

    local pid="" exe_before=""
    if [[ -f "$META/workload.pid" ]]; then
        pid=$(cat "$META/workload.pid")
        exe_before=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "<gone>")
    fi
    log "before move: workload pid=${pid:-none} exe=${exe_before:-n/a}"

    mount --move "$oldp" "$newp"
    echo "$newp" > "$META/merged_path"

    log "after move:"
    findmnt "$newp" || true
    if [[ -n "$pid" ]]; then
        if kill -0 "$pid" 2>/dev/null; then
            local exe_after; exe_after=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "<gone>")
            log "workload pid=$pid ALIVE  exe=$exe_after"
            [[ "$exe_after" == "${exe_before/$oldp/$newp}" ]] \
                && log "exe path tracked the move (good)" \
                || log "exe path differs unexpectedly"
        else
            log "workload DIED across move"
            return 1
        fi
    fi
    log "old path '$oldp' should now be empty:"
    ls -A "$oldp" 2>/dev/null || true
}

cmd_down() {
    need_root
    local m; m=$(merged_path)

    if [[ -f "$META/workload.pid" ]]; then
        local p; p=$(cat "$META/workload.pid")
        kill "$p" 2>/dev/null || true
        # Give it a beat to release fds before we umount.
        for _ in 1 2 3 4 5; do
            kill -0 "$p" 2>/dev/null || break
            sleep 0.1
        done
        rm -f "$META/workload.pid"
    fi

    # $m may carry multiple stacked overlays after 'swap --keep-top'; drain.
    while findmnt "$m" >/dev/null 2>&1; do
        umount "$m" 2>/dev/null || break
    done
    umount "$UPPER_TMPFS" 2>/dev/null || true

    if [[ -f "$META/lowers_list" ]]; then
        # Reverse-iterate in case of any layering between names.
        tac "$META/lowers_list" | while read -r name; do
            [[ -n "$name" ]] || continue
            umount "$LOWERS_DIR/${name}" 2>/dev/null || true
            veritysetup close "${DEV_PREFIX}-${name}" 2>/dev/null || true
        done
    fi
    if [[ -f "$META/loops" ]]; then
        awk '{for(i=2;i<=NF;i++){split($i,a,"="); print a[2]}}' "$META/loops" \
            | while read -r d; do [[ -n "$d" ]] && losetup -d "$d" 2>/dev/null || true; done
    fi

    rm -rf "$LOWERS_DIR" "$IMG_DIR" "$META" "$MERGED" "$UPPER_TMPFS"
    # Drop the private self-bind on $STATE last (created by 'up' for MS_MOVE).
    umount "$STATE" 2>/dev/null || true
    log "down"
}

cmd_swap() {
    need_root
    [[ -e "$META/active" ]] || die "not up"
    local m; m=$(merged_path)
    local N; N=$(cat "$META/N")
    [[ -d "$LOWERS_DIR/alt-1" ]] || die "no alt-1 lower; rebuild with 'down' then 'up'"

    local helper
    helper="$(dirname "$(readlink -f "$0")")/assix-swap"
    [[ -x "$helper" ]] || die "missing helper $helper — run 'make' in $(dirname "$helper")"

    # Fresh upper/work for v2 on the same tmpfs (overlay refuses to share).
    local upper2="$UPPER_TMPFS/upper-v2"
    local work2="$UPPER_TMPFS/work-v2"
    mkdir -p "$upper2" "$work2"

    local pid="" exe_before=""
    if [[ -f "$META/workload.pid" ]]; then
        pid=$(cat "$META/workload.pid")
        exe_before=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "<gone>")
    fi
    local which_before; which_before=$(cat "$m/marker/which" 2>/dev/null || echo "<n/a>")
    log "before swap: which='${which_before}' workload pid=${pid:-none} exe=${exe_before:-n/a}"

    # v2 lowers: alt-1 in slot 1, then unchanged lower-2 .. lower-N.
    local args=(--target "$m" --upper "$upper2" --work "$work2" -v)
    args+=(--lower "$LOWERS_DIR/alt-1")
    for i in $(seq 2 "$N"); do
        args+=(--lower "$LOWERS_DIR/lower-${i}")
    done
    "$helper" "${args[@]}"

    local which_after; which_after=$(cat "$m/marker/which" 2>/dev/null || echo "<n/a>")
    if [[ -n "$pid" ]]; then
        if kill -0 "$pid" 2>/dev/null; then
            local exe_after; exe_after=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "<gone>")
            log "workload pid=$pid ALIVE  exe=${exe_after}"
            if [[ "$exe_before" == "$exe_after" ]]; then
                log "  exe path unchanged (kernel kept the v1 inode pinned — expected)"
            else
                log "  exe path changed: ${exe_before} -> ${exe_after}"
            fi
        else
            log "workload DIED across swap"
            return 1
        fi
    fi
    log "after swap:  which='${which_after}'"
    if [[ "$which_before" != "$which_after" ]]; then
        log "  marker changed (good — new path lookups now hit v2)"
    else
        log "  marker unchanged — swap may not have taken effect; check status/dmesg"
    fi
}

case "${1:-}" in
    up)       shift; cmd_up "$@";;
    status)   cmd_status;;
    check)    cmd_check;;
    workload) cmd_workload;;
    move)     shift; cmd_move "$@";;
    swap)     cmd_swap;;
    down)     cmd_down;;
    *) cat >&2 <<EOF
usage: $0 <cmd>
  up [N]            build N verity lowers (+ alt-1) + overlay (default $N_DEFAULT)
  status            show current mounts / verity devs / workload
  check             verify lower visibility, upper writes, RO enforcement
  workload          exec sleeper from merged tree, record pid
  move <new-path>   mount --move overlay; verify workload survives
  swap              atomically swap to v2 (alt-1 in slot 1) via MOVE_MOUNT_BENEATH
  down              tear everything down

env: STATE_DIR=$STATE  LOWER_SIZE_MB=$LOWER_SIZE_MB  N_DEFAULT=$N_DEFAULT
EOF
       exit 1;;
esac
