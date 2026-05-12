# pancake-os — design

A Debian-derived distribution where every package is a verity-signed image and
the entire rootfs is reassembled atomically via `pivot_root(2)`.

## Principles

1. **Pure .deb provenance.** Every layer is built from exactly one upstream .deb.
   No special "base" layer. The system is the *set* of currently-installed
   packages, each as its own pancake image.
2. **Postinst is honored.** Each `pancake-build` runs the .deb's `dpkg --unpack`
   and `dpkg --configure` (which fires postinst, postrm, etc.) inside an overlay
   sandbox, then captures the upper-layer diff as the package's contribution.
3. **Atomic generations.** A "generation" is an immutable, ordered list of
   pancake images. Changing the system = creating a new generation and
   `pivot_root`-ing into it.
4. **Trivial rollback.** Generations are kept; `current` is just a symlink.
5. **No mutable rootfs.** All on-disk writes go to a per-generation tmpfs upper.
   State that survives a reboot must live on an explicit data partition.

## On-disk layout

```
/boot/                                   (or a small dedicated partition)
├── kernel
├── initramfs.cpio.gz
└── pancake-current → ../var/lib/pancake/current   (initramfs reads this)

/var/lib/pancake/                        (control plane state)
├── repo/
│   └── <pkg>-<version>/
│       ├── image.img                    ext4 + dm-verity (data + hash one file)
│       ├── image.roothash               hex root hash
│       └── manifest.toml                see schema below
├── generations/
│   ├── 1/manifest.toml                  initial generation
│   ├── 2/manifest.toml                  after first install
│   └── ...
└── current → generations/N              symlink to active generation
```

`/var/lib/pancake/` lives on a writable data partition (ext4, btrfs, etc.) —
NOT on the verity rootfs. It's the only persistent mutable state pancake-os
manages.

## Manifest schemas (TOML)

### Per-package manifest (`repo/<pkg>-<ver>/manifest.toml`)

```toml
schema = 1

[package]
name        = "openssh-server"
version     = "1:9.6p1-3ubuntu13.16"
arch        = "amd64"
description = "secure shell (SSH) server"

[image]
file        = "image.img"
size        = 36700160
roothash    = "454c8b9b80f06bf8ee8ad88436781bd70613d484baf0e099acbf7ac3cd9e7509"
hash-algo   = "sha256"

[depends]
# parsed from the .deb's Depends: field, version-pinned at build time
runtime = [
    "libc6 (= 2.39-0ubuntu8.4)",
    "libpam0g (= 1.5.3-5ubuntu5.1)",
    "libssl3 (= 3.0.13-0ubuntu3.5)",
    "openssh-client (= 1:9.6p1-3ubuntu13.16)",
]

[provenance]
# the .deb this image was built from
deb-name   = "openssh-server_9.6p1-3ubuntu13.16_amd64.deb"
deb-sha256 = "abc...123"
built-at   = "2026-05-07T12:34:56Z"
built-with = "pancake-build 0.1"

[hooks]
# run inside the sandbox during pancake-build, BEFORE diff capture
# (covers things postinst expects but the sandbox can't always do, e.g.
#  systemctl daemon-reload — postinst already ran by this point)
post-extract = []
# run on the live system AFTER pivot_root activates a generation containing
# this layer (may be empty for libraries; non-empty for daemons)
post-activate = ["systemctl restart ssh.service"]
```

### Generation manifest (`generations/<n>/manifest.toml`)

```toml
schema = 1

[generation]
id          = 2
parent      = 1
created     = "2026-05-07T12:35:42Z"
description = "+openssh-server 9.6p1-3ubuntu13.16"

# Layers in OVERLAY ORDER (leftmost = topmost = wins).
# Convention: dependency-ordered (most-specific / leaf packages first,
# foundational packages last).
[[layer]]
name     = "openssh-server"
version  = "1:9.6p1-3ubuntu13.16"
manifest = "repo/openssh-server-1%3a9.6p1-3ubuntu13.16/manifest.toml"

[[layer]]
name     = "libpam0g"
version  = "1.5.3-5ubuntu5.1"
manifest = "repo/libpam0g-1.5.3-5ubuntu5.1/manifest.toml"

# ... 50-100 more layers ...

[[layer]]
name     = "libc6"
version  = "2.39-0ubuntu8.4"
manifest = "repo/libc6-2.39-0ubuntu8.4/manifest.toml"

# (manifest paths are relative to /var/lib/pancake/)
```

## Workflows

### Bootstrap (creating an initial pancake-os)

```
pancake-bootstrap --suite noble --packages openssh-server,chrony,nano \
                  --output /tmp/pancake-kit/

  1. mmdebstrap into /tmp/sandbox/ — pulls package set + transitive deps
  2. for each package P in dpkg topo order:
       a. set up an overlay: lower = sandbox-without-P, upper = scratch
       b. dpkg --unpack P + dpkg --configure P inside the overlay
       c. diff = upper-layer contents → pancake-build → P's image+manifest
       d. promote upper into "sandbox" for next iteration
  3. write generations/1/manifest.toml with all P's
  4. emit initramfs + kernel into boot/

  Result: /tmp/pancake-kit/ is a complete pancake-os disk image
```

Note: step 2's overlay-diff approach is the canonical way to capture
per-package state including postinst side effects (new users in /etc/passwd,
systemd unit symlinks, etc.).

### Install on a running system

```
pancake install <pkg-or-deb-path>

  1. resolve dependencies, fetch missing .debs
  2. for each new .deb: pancake-build against current generation's union
  3. write generations/N+1/manifest.toml (current + new layers)
  4. atomic swap:
     a. stage = construct overlay with N+1's lowers + new tmpfs upper
     b. rbind /proc /sys /dev /run /tmp /var/lib/pancake into stage
     c. mount --make-rprivate /
     d. pivot_root + chroot_fs_refs (every task's fs.root flips)
     e. umount old, mount --make-rshared /
  5. update current → generations/N+1
  6. run post-activate hooks (systemctl restart ...)
```

### Rollback

```
pancake rollback

  Same swap procedure with the *previous* generation's manifest.
  Trivial because nothing was destroyed — just a different stack.
```

### Update (security patch on existing package)

```
pancake update [pkg]

  Same as install but for already-installed packages with newer versions.
  Old version's image stays in repo/ until `pancake gc` collects it.
```

## Boot-time integrity (signing + measurement)

When `pancake bootstrap` is invoked with `--sign-key` and `--sign-cert`:

- The UKI is signed via `ukify --secureboot-private-key/--secureboot-certificate`,
  which chains to `sbsign`. UEFI Secure Boot will refuse to load the UKI
  unless the cert is enrolled in `db`.
- `generations/N/manifest.toml` gets a sibling `manifest.toml.sig` —
  a raw RSA-PKCS1v15-SHA256 signature over the manifest bytes.
- The cert's public key is extracted (PKIX `PUBLIC KEY` PEM) and baked
  into the initramfs at `/etc/pancake/manifest.pubkey`.

`initramfs/init` then enforces the gate: if `/etc/pancake/manifest.pubkey`
is present, the matching `.sig` MUST validate before any `veritysetup
open` happens. A failed signature drops to an emergency shell rather
than mounting a tampered layer set.

### What's measured into which TPM PCR

When booting via `--efi` (UKI), the chain is:

| PCR | Content | Measured by | Stage |
|---|---|---|---|
| 0–3 | Firmware + option ROMs | UEFI | pre-boot |
| 4 | `systemd-bootx64.efi` binary | UEFI | UKI selection |
| 5 | `loader.conf` + entries | systemd-boot | before UKI |
| 7 | Secure Boot policy + cert chain (PK/KEK/db/dbx) | UEFI | sealing target |
| **11** | **UKI sections: `.linux` + `.initrd` + `.cmdline` + `.osrel` + `.uname`** | **systemd-stub** | UKI entry |
| 12 | `.cmdline` only (auxiliary) | systemd-stub | UKI entry |
| **13** | **`generations/<id>/manifest.toml` SHA-256** | **pancake initramfs** | before overlay mount (best-effort, requires `tpm2_pcrextend` in initramfs) |

The user's natural question — *"do we measure the kernel and command line
separately?"* — is answered by PCR 11: systemd-stub measures every PE
section of the UKI before jumping to the kernel, so PCR 11 uniquely
binds the (kernel, initramfs, cmdline) tuple. Sealing an LUKS key
against PCR 11 is the standard mechanism for "encrypted state unlockable
only by this exact boot chain". For finer cmdline-only policies, PCR 12
is also written by systemd-stub.

### Status (this document is alive)

- [x] `pancake build` (one .deb → verity layer)
- [x] `pancake bootstrap` (mmdebstrap → kit + disk image + initramfs + EFI disk)
- [x] `pancake` CLI (list / history / show / install / activate / rollback / swap)
- [x] `initramfs/init` (manifest-driven boot, signature verification)
- [x] UEFI Secure Boot via signed UKI (Step 1 of TPM/signing story)
- [x] Signed `generations/N/manifest.toml` + initramfs verification (Step 2)
- [ ] TPM NV monotonic counter for rollback resistance (Step 3 — needs
      `tpm2-tools` in initramfs and a `counter` field in the generation
      manifest)
- [ ] LUKS2 encryption of the state partition with TPM-sealed key
      (Step 4 — needs `systemd-cryptenroll` with PCR 7 + 11 sealing)
- [ ] Auto-enroll dev cert into OVMF's `db` for one-command Secure Boot
      verification in QEMU (Step 5 — convenience; today it's a manual
      `ovmf-vars-generator` invocation)
