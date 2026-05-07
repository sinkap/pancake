"""Shared helpers for pancake-build / pancake-bootstrap / pancake."""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path


def run(cmd, *, check=True, capture=False, env=None, sudo=False):
    """Run a command. Logs to stderr; optional sudo prefix."""
    if sudo and os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    print(f"  ▸ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.run(
        cmd, check=check, capture_output=capture, text=True, env=env,
    )


def file_sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def slugify_version(v: str) -> str:
    """Reduce a Debian version string to chars safe for dm-mapper device
    names and TOML tags: keep [A-Za-z0-9._-], replace anything else with _."""
    out = []
    for c in v:
        if c.isalnum() or c in "-_.":
            out.append(c)
        else:
            out.append("_")
    return "".join(out)


def parse_depends(deps_field: str) -> list[str]:
    if not deps_field:
        return []
    return [d.strip() for d in deps_field.split(",") if d.strip()]


def deb_metadata(deb_path: Path) -> dict:
    """Read package/version/arch/description/depends from a .deb's control."""
    fields = ("Package", "Version", "Architecture", "Description",
              "Depends", "Pre-Depends")
    raw = run(["dpkg-deb", "-f", str(deb_path), *fields], capture=True).stdout
    md: dict[str, str] = {}
    cur = None
    for line in raw.splitlines():
        if line.startswith(" ") and cur:
            if cur != "Description":
                md[cur] += " " + line.strip()
        elif ":" in line:
            cur, _, val = line.partition(":")
            md[cur.strip()] = val.strip()
    return md


def make_verity_image(
    staging: Path, out_img: Path, label: str, *, min_mib: int = 8,
) -> tuple[str, int]:
    """
    Build an ext4 image from staging/, plus a separate verity hash file at
    out_img.with_suffix('.hash'). Returns (roothash_hex, data_size_bytes).
    """
    du_kb = int(run(["du", "-sk", str(staging)],
                    capture=True, sudo=True).stdout.split()[0])
    data_kb = (du_kb * 14 // 10 + 32 * 1024 + 3) // 4 * 4
    if data_kb < min_mib * 1024:
        data_kb = min_mib * 1024
    data_size = data_kb * 1024

    out_img.parent.mkdir(parents=True, exist_ok=True)
    if out_img.exists():
        out_img.unlink()
    out_hash = out_img.with_suffix(".hash")
    if out_hash.exists():
        out_hash.unlink()

    run(["truncate", "-s", f"{data_kb}K", str(out_img)])
    run(["mkfs.ext4", "-q", "-F", "-L", label[:16],
         "-d", str(staging), "-E", "no_copy_xattrs", str(out_img)], sudo=True)
    run(["chown", f"{os.getuid()}:{os.getgid()}", str(out_img)], sudo=True)

    out_hash.touch()
    fmt = run(["veritysetup", "format", str(out_img), str(out_hash)],
              capture=True).stdout
    m = re.search(r"Root hash:\s+([0-9a-f]+)", fmt)
    if not m:
        raise RuntimeError(f"veritysetup format produced no root hash:\n{fmt}")
    return m.group(1), data_size


def write_manifest(
    out_dir: Path, *, name: str, version: str, arch: str = "amd64",
    description: str = "", depends: list[str] | None = None,
    deb_name: str | None = None, deb_sha256: str | None = None,
    roothash: str, data_size: int,
) -> None:
    """Write manifest.toml + image.roothash."""
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    lines = [
        "schema = 1",
        "",
        "[package]",
        f'name        = "{name}"',
        f'version     = "{version}"',
        f'arch        = "{arch}"',
        f'description = "{description}"',
        "",
        "[image]",
        'data        = "image.img"',
        'hash        = "image.hash"',
        f"data-size   = {data_size}",
        f'roothash    = "{roothash}"',
        'hash-algo   = "sha256"',
        "",
        "[depends]",
        "runtime = [",
    ]
    for d in (depends or []):
        lines.append(f'    "{d}",')
    lines += [
        "]",
        "",
        "[provenance]",
        f'deb-name   = "{deb_name or ""}"',
        f'deb-sha256 = "{deb_sha256 or ""}"',
        f'built-at   = "{now}"',
        f'built-with = "pancake 0.1"',
        "",
        "[hooks]",
        "post-extract  = []",
        "post-activate = []",
        "",
    ]
    (out_dir / "manifest.toml").write_text("\n".join(lines))
    (out_dir / "image.roothash").write_text(roothash + "\n")
