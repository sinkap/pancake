#!/usr/bin/env bash
# smoketest-local.sh — local dev-mode regression test for the bootstrap path.
#
# Run this before any commit that touches:
#   cli/pancake/, backends/build-server/build_image.go,
#   backends/build-server/buildimage_handler.go, common/go/layer/,
#   common/protos/build.proto, common/go/initramfs/, tools/initramfs/init
#
# Prereqs:
#   - docker compose + the local stack defined in deployment/docker/compose.yaml
#     (the repo-root compose.yaml shim brings it in too)
#   - pancake-recipe.yaml at repo root (platform: dev, points at a kernel tree)
#   - the kernel tree at recipe.kernel.bzimage exists locally
#
# What it does:
#   1. brings up docker compose (build-server, ca-server, sign-server)
#   2. wipes any stale pancake-state.img / pancake-efi.img / etc.
#   3. runs `pancake bootstrap --builder=localhost:7879 pancake-recipe.yaml`
#   4. asserts all four artifacts exist and are non-empty
#   5. spot-checks an internal layer image is squashfs (magic 'hsqs')
#
# Doesn't tear compose down on exit — leaves it warm so you can iterate.

set -euo pipefail

cd "$(dirname "$0")/.."

RECIPE="${1:-pancake-recipe.yaml}"
if [[ ! -f "$RECIPE" ]]; then
  echo "FAIL: recipe not found: $RECIPE" >&2
  exit 1
fi

echo "[smoketest] bringing up local docker compose stack"
docker compose up -d --wait >/dev/null

echo "[smoketest] cleaning prior outputs"
rm -f pancake-state.img pancake-efi.img pancake-initramfs.cpio.gz pancake-bzImage

if [[ ! -x ./pancake ]]; then
  echo "[smoketest] building local pancake CLI"
  go build -o ./pancake ./cli/pancake
fi

echo "[smoketest] running bootstrap"
./pancake bootstrap --builder=localhost:7879 "$RECIPE"

echo "[smoketest] checking artifacts"
fail=0
for f in pancake-state.img pancake-efi.img pancake-initramfs.cpio.gz pancake-bzImage; do
  if [[ ! -s "$f" ]]; then
    echo "FAIL: $f missing or empty"
    fail=1
  else
    printf "  %-30s %s\n" "$f" "$(stat -c%s "$f" | numfmt --to=iec --suffix=B)"
  fi
done

echo "[smoketest] sampling a layer image — should be squashfs"
sample_magic=$(docker exec pancake-build-server bash -c '
  for d in /var/lib/pancake-build-server/layers/*/; do
    head -c 4 "$d/image.img" 2>/dev/null && exit 0
  done
' | od -An -c | tr -d ' \n')
if [[ "$sample_magic" != "hsqs" ]]; then
  echo "FAIL: layer image magic = $sample_magic, want 'hsqs' (squashfs)"
  fail=1
else
  echo "  layer magic = hsqs (squashfs) ✓"
fi

if (( fail )); then
  echo "[smoketest] FAIL"
  exit 1
fi
echo "[smoketest] OK — local dev bootstrap works end to end"
