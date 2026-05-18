#!/bin/bash
# Clean all pancake-os state: VMs, build artifacts, caches

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[clean] stopping VMs and TPM"
sudo pkill -f qemu-system-x86_64 2>/dev/null || true
pkill -f swtpm 2>/dev/null || true
sleep 1

echo "[clean] removing VM state and build artifacts"
sudo rm -rf vm-state
rm -rf pancake-kit pancake-*.img pancake-*.cpio.gz pancake-bzImage

echo "[clean] clearing build server cache"
docker compose exec pancake-build-server rm -rf /var/lib/pancake-build-server/layers/* /var/lib/pancake-build-server/work/* 2>/dev/null || true

echo "[clean] cleaning Go cache"
go clean -cache -modcache -testcache 2>/dev/null || true

echo "[clean] removing temp files"
rm -rf /tmp/pancake-modules-* /tmp/modules-*.tar /tmp/vm-cert.pem 2>/dev/null || true

echo "[clean] state cleaned"
