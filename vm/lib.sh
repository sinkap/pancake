# Shared helpers for pancake realworld build scripts. Source from each build-*.sh.

log() { printf '[%s] %s\n' "$(basename "$0" .sh)" "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Build an ext4 image populated from a directory tree, then format dm-verity
# hash tree into a SEPARATE file. Output: ${out}.img + ${out}.hash + ${out}.roothash
mk_verity_image_from_dir() {
    local stage="$1"   # source directory (must be readable by us; sudo if needed)
    local out="$2"     # output base path; produces ${out}.{img,hash,roothash}
    local label="${3:-${out##*/}}"

    # Size: tree size * 1.4 + 32 MiB slack, rounded to 4 KiB.
    local size_kib
    size_kib=$(sudo du -sk "$stage" | awk '{print $1}')
    local img_kib=$(( size_kib * 14 / 10 + 32768 ))
    img_kib=$(( (img_kib + 3) / 4 * 4 ))

    log "  ext4 image $(basename "$out").img (${img_kib} KiB) populated from $stage"
    rm -f "${out}.img" "${out}.hash" "${out}.roothash"
    truncate -s ${img_kib}K "${out}.img"
    # mkfs.ext4 -d copies the tree in; -E no_copy_xattrs avoids capability nags.
    sudo mkfs.ext4 -q -F -L "${label:0:16}" -d "$stage" -E no_copy_xattrs "${out}.img" >/dev/null
    sudo chown "$(id -u):$(id -g)" "${out}.img"

    log "  veritysetup format → $(basename "$out").hash"
    : > "${out}.hash"
    veritysetup format "${out}.img" "${out}.hash" \
        | awk '/Root hash/ {print $NF}' > "${out}.roothash"

    [ -s "${out}.roothash" ] || die "veritysetup format produced no root hash for ${out}"
    log "  $(basename "$out") roothash=$(cat "${out}.roothash")"
}

# Ensure the test SSH keypair exists. Used to log into the VM as root.
ensure_ssh_key() {
    local key="keys/pancake_id_ed25519"
    if [ ! -f "$key" ]; then
        log "generating $key"
        mkdir -p keys
        ssh-keygen -t ed25519 -N '' -C pancake-test -f "$key" >/dev/null
    fi
}

# Ensure persistent SSH host keys for the VM exist (so v1 and v2 sshd images
# both ship the same host identity → no client-side warnings on reconnect).
ensure_host_keys() {
    local d="keys/host_keys"
    if [ ! -d "$d" ] || [ -z "$(ls -A "$d" 2>/dev/null)" ]; then
        log "generating SSH host keys in $d"
        mkdir -p "$d"
        ssh-keygen -t rsa     -b 3072 -N '' -f "$d/ssh_host_rsa_key"     -C pancake-vm >/dev/null
        ssh-keygen -t ecdsa   -b 256  -N '' -f "$d/ssh_host_ecdsa_key"   -C pancake-vm >/dev/null
        ssh-keygen -t ed25519         -N '' -f "$d/ssh_host_ed25519_key" -C pancake-vm >/dev/null
    fi
}
