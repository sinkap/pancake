#!/usr/bin/env bash
# Build base.img — the rootfs lower in the merged overlay. RO ext4 over
# dm-verity. Contains: init/systemd, libc, libs the daemon overlays dlopen,
# networking, our SSH authorized_keys. NO daemon binaries / units (those come
# from per-pkg overlay images).
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
. ./lib.sh

STAGE="${STAGE:-staging/base}"
OUT="${OUT:-images/base}"
SUITE="${SUITE:-noble}"
MIRROR="${MIRROR:-http://archive.ubuntu.com/ubuntu/}"
COMPONENTS="${COMPONENTS:-main,universe}"

PKGS=(
    init systemd systemd-sysv libpam-systemd dbus udev
    bash coreutils util-linux mount kmod
    iproute2 iputils-ping netbase ca-certificates
    less procps nano
    cryptsetup-bin dmsetup
    libssl3 libpam-modules libcrypt1
    openssh-client
    # Shared libs daemon binaries (in overlays) dlopen at runtime:
    libwrap0                                   # sshd
    libgnutls30t64 libnettle8t64               # chronyd
)

ensure_ssh_key
ensure_host_keys

if [ "${FORCE:-0}" = 1 ] || [ ! -d "$STAGE" ]; then
    log "mmdebstrap → $STAGE (suite=$SUITE)"
    sudo rm -rf "$STAGE"
    sudo mmdebstrap \
        --variant=minbase \
        --components="$COMPONENTS" \
        --include="$(IFS=,; echo "${PKGS[*]}")" \
        "$SUITE" "$STAGE" "$MIRROR"
fi

log "customizing $STAGE"
sudo tee "$STAGE/etc/hostname" >/dev/null <<<'pancake-vm'

sudo install -d -m 0755 "$STAGE/etc/systemd/network"
sudo tee "$STAGE/etc/systemd/network/10-wired.network" >/dev/null <<'EOF'
[Match]
Type=ether

[Network]
DHCP=yes
EOF

sudo chroot "$STAGE" systemctl enable systemd-networkd >/dev/null
sudo tee "$STAGE/etc/resolv.conf" >/dev/null <<<'nameserver 10.0.2.3'

# Diagnostic dump at end of boot. With ssh broken there's no way in, so this
# is our only window into VM state.
sudo tee "$STAGE/etc/systemd/system/pancake-debug.service" >/dev/null <<'EOF'
[Unit]
Description=Pancake end-of-boot diagnostic dump
DefaultDependencies=no

[Service]
Type=oneshot
StandardOutput=journal+console
ExecStart=/bin/bash -c '\
    echo "=== PANCAKE DEBUG ==="; \
    echo "--- ip addr ---"; ip -4 addr; \
    echo "--- mounts at / ---"; grep " / / " /proc/self/mountinfo; \
    echo "--- markers ---"; cat /etc/pancake-version /etc/pancake-version-sshd /etc/pancake-version-chronyd 2>&1; \
    echo "--- ssh status ---"; systemctl status ssh.service --no-pager -l 2>&1 | head -20; \
    echo "--- chrony status ---"; systemctl status chrony.service --no-pager -l 2>&1 | head -20; \
    echo "--- listening sockets ---"; ss -tlnp 2>&1 | head; \
    echo "=== END DEBUG ==="'

[Install]
WantedBy=multi-user.target
EOF
sudo chroot "$STAGE" systemctl enable pancake-debug.service >/dev/null

# Root login by SSH key only.
sudo install -d -m 0700 "$STAGE/root/.ssh"
sudo install -m 0600 keys/pancake_id_ed25519.pub "$STAGE/root/.ssh/authorized_keys"

# Daemon system users — postinst would normally create these. /etc/passwd is
# ONE FILE per overlay layer (not directory) and overlay leftmost wins, so
# whichever layer carries /etc/passwd shadows all others. Put it in base.
sudo chroot "$STAGE" addgroup --system --quiet sshd 2>/dev/null || true
sudo chroot "$STAGE" adduser  --system --quiet --no-create-home \
    --home /run/sshd --shell /usr/sbin/nologin --ingroup sshd sshd 2>/dev/null || true
sudo chroot "$STAGE" addgroup --system --quiet _chrony 2>/dev/null || true
sudo chroot "$STAGE" adduser  --system --quiet --no-create-home \
    --home /var/lib/chrony --shell /usr/sbin/nologin --ingroup _chrony _chrony 2>/dev/null || true

# Marker
sudo tee "$STAGE/etc/pancake-version" >/dev/null <<<'base v1'

mk_verity_image_from_dir "$STAGE" "$OUT" base
