#!/usr/bin/env bash
# install.sh — drop the SEV-SNP GRUB script into /etc/grub.d/ so a
# "SEV-SNP boot variants" submenu appears at the next boot, with one
# entry per installed kernel. The script auto-runs on every kernel
# install/upgrade, so the menu stays in sync.
#
# Run with sudo:
#   sudo ./demo/snp-grub/install.sh
#
# Uninstall:
#   sudo rm /etc/grub.d/12_sev_snp && sudo update-grub

set -e

[ "$(id -u)" = 0 ] || { echo "needs sudo" >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/12_sev_snp"
DST=/etc/grub.d/12_sev_snp

[ -f "$SRC" ] || { echo "missing $SRC" >&2; exit 1; }

install -m 0755 "$SRC" "$DST"
echo "[install] copied → $DST"

update-grub
echo "[install] update-grub done; reboot and pick a 'SEV-SNP boot variants' entry"
echo "[install] check after boot: cat /sys/module/kvm_amd/parameters/sev_snp"
