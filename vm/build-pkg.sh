#!/usr/bin/env bash
# Build a daemon overlay image from one or more .debs.
#
#   build-pkg.sh sshd    v1
#   build-pkg.sh sshd    v2
#   build-pkg.sh chronyd v1
#   build-pkg.sh chronyd v2
#
# This image is one of the lowerdirs of the merged-rootfs overlay. Its files
# appear at standard paths (/usr/sbin/sshd, /etc/ssh/, /lib/systemd/system/...).
# The systemd unit symlink in /etc/systemd/system/multi-user.target.wants makes
# it autostart at boot.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
. ./lib.sh

PKG="${1:?usage: $0 <pkg> <ver>}"
VER="${2:?need v1 or v2}"
case "$PKG" in
    sshd)    DEBS=(openssh-server) ;;
    chronyd) DEBS=(chrony) ;;
    *) die "unknown pkg $PKG" ;;
esac

STAGE="staging/${PKG}-${VER}"
OUT="images/${PKG}-${VER}"
DEB_CACHE="staging/_debs"

mkdir -p "$DEB_CACHE"
( cd "$DEB_CACHE" && apt-get -q -q download "${DEBS[@]}" 2>/dev/null ) || \
    die "apt-get download failed for ${DEBS[*]}"

if [ "${FORCE:-0}" = 1 ] || [ ! -d "$STAGE" ]; then
    log "rebuilding $STAGE"
    sudo rm -rf "$STAGE"
    mkdir -p "$STAGE"
    for pkg in "${DEBS[@]}"; do
        deb=$(ls -1t "$DEB_CACHE/${pkg}"_*.deb 2>/dev/null | head -1)
        [ -n "$deb" ] || die "no .deb for $pkg"
        log "  extract $deb"
        sudo dpkg-deb -x "$deb" "$STAGE"
    done
fi

# Marker
sudo install -d -m 0755 "$STAGE/etc"
sudo tee "$STAGE/etc/pancake-version-${PKG}" >/dev/null <<<"${PKG}-${VER}"

# Wire systemd autostart symlink — postinst would normally do `systemctl enable`.
sudo install -d -m 0755 "$STAGE/etc/systemd/system/multi-user.target.wants"

case "$PKG" in
    sshd)
        # Self-contained sshd_config — the .deb's postinst (debconf) was skipped.
        sudo install -d -m 0755 "$STAGE/etc/ssh/sshd_config.d"
        sudo install -m 0600 keys/host_keys/ssh_host_rsa_key      "$STAGE/etc/ssh/"
        sudo install -m 0600 keys/host_keys/ssh_host_ecdsa_key    "$STAGE/etc/ssh/"
        sudo install -m 0600 keys/host_keys/ssh_host_ed25519_key  "$STAGE/etc/ssh/"
        sudo install -m 0644 keys/host_keys/ssh_host_rsa_key.pub      "$STAGE/etc/ssh/"
        sudo install -m 0644 keys/host_keys/ssh_host_ecdsa_key.pub    "$STAGE/etc/ssh/"
        sudo install -m 0644 keys/host_keys/ssh_host_ed25519_key.pub  "$STAGE/etc/ssh/"

        sudo tee "$STAGE/etc/ssh/sshd_config" >/dev/null <<EOF
# pancake sshd-${VER}
Include /etc/ssh/sshd_config.d/*.conf
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/sshd.pid
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
EOF
        sudo tee "$STAGE/etc/ssh/sshd_config.d/00-pancake.conf" >/dev/null <<EOF
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
Banner /etc/issue.net
EOF
        sudo tee "$STAGE/etc/issue.net" >/dev/null <<<"pancake sshd ${VER}"

        sudo ln -sfT /lib/systemd/system/ssh.service \
            "$STAGE/etc/systemd/system/multi-user.target.wants/ssh.service"
        ;;
    chronyd)
        # Stock unit drops privs to _chrony, which can't write the default
        # driftfile in /var/lib/chrony (RO ext4 base). Use /run instead.
        sudo install -d -m 0755 "$STAGE/etc/chrony"
        sudo tee "$STAGE/etc/chrony/chrony.conf" >/dev/null <<EOF
# pancake chronyd-${VER}
pool pool.ntp.org iburst
driftfile /run/chrony/drift
makestep 1.0 3
EOF
        sudo ln -sfT /lib/systemd/system/chrony.service \
            "$STAGE/etc/systemd/system/multi-user.target.wants/chrony.service"
        ;;
esac

mk_verity_image_from_dir "$STAGE" "$OUT" "${PKG}-${VER}"
