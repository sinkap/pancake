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
- [x] TPM NV monotonic counter for rollback resistance (Step 3) —
      `counter = N` field in `[generation]`, signed as part of
      `manifest.toml`. Initramfs uses `tpm2_nvread` / `tpm2_nvwrite` on
      NV index `0x01400001` (8-byte ordinary, no auth). Refuses to boot
      if `manifest.counter < tpm.counter`; advances TPM to manifest
      counter on success. Soft-fails if no TPM is present (signature
      check is still enforced).
- [x] TPM-sealed orchestrator-update auth token (Step 4) —
      `pancake enroll` generates a random 256-bit bearer token and
      seals it via `systemd-creds encrypt --tpm2-pcrs=7+11` to
      `/etc/pancake/orch-token.creds`. The `pancaked` daemon
      (separate binary, separate verity layer, systemd-managed)
      decrypts at startup via `--tpm-token=auto`; PCR mismatch
      (kernel/initrd swap → different PCR 11) → `Operation not
      permitted` → daemon refuses to start. Effectively quarantines a
      tampered fleet member from accepting pushes. Re-enrollment is
      required after any boot-chain change.
- [x] Per-host identity layer (`pancake-host`) — `/etc/hostname`,
      `/etc/ssh/ssh_host_*_key{,.pub}`, `/root/.ssh/authorized_keys`,
      `/etc/ssh/sshd_config`, `/etc/resolv.conf`,
      `/etc/systemd/network/10-wired.network`, `/etc/machine-id` (placeholder)
      live in their own verity layer, carved out of base-files /
      openssh-server / pancake-state by an `isPerHostPath` filter in
      bootstrap. Pinned at the TOP of the overlay stack so its files
      win. Effect: every other layer's roothash is a function of the
      .deb set + recipe, not the host. Precondition for the orchestrator
      shipping one fleetwide manifest while each node keeps its own
      pancake-host pinned.
- [x] Build server (`pancake-build-server`) — gRPC service that
      runs mmdebstrap + per-package layer construction once, caches
      every layer keyed by its dm-verity roothash, and serves canonical
      bytes via `GetLayer` to clients. Recipe-driven `pancake bootstrap
      --builder=…` clients send a `BuildGeneration(packages, base
      recipe)` request; server returns N `LayerHandle`s plus a signed
      generation manifest. Internal-layer recipes (`base`, `runtime`,
      `kernel`, `modules`, `pancaked`) are data-driven via a text-proto
      catalog (`internal/buildpb/internal_layers.textproto`) — adding
      a new internal layer kind is a data change + Go handler, no
      `.proto` edit. Container image at `tools/pancake-go/server/Dockerfile`
      ships with a `VOLUME /var/lib/pancake-build-server` so layer
      cache persists across container restarts.
- [x] PCR 14 = sha256(lowers TSV) — initramfs/init extends PCR 14
      with the hash of the lowers file before opening any verity device.
      Binds every layer's roothash into one quotable PCR; one value
      covers the entire layer set for attestation. Hard-fail discipline
      (matching PCR 13) when TPM is present.
- [x] Remote attestation (`pancake attest`, Step 5) — pancaked
      provisions a per-boot AK at startup, bound to a stable EK.
      EK lifecycle follows the TCG TPM 2.0 EK Credential Profile:
      `pancake enroll` runs `tpm2_createek` + `tpm2_evictcontrol`
      to persist the EK at canonical handle `0x81010002` (idempotent;
      re-running on the same TPM is a no-op). pancaked startup
      then does `tpm2_readpublic -c 0x81010002` (instant, no key
      derivation), with a fallback to transient `tpm2_createek`
      for hosts not yet enrolled. AK is fresh per boot via
      `tpm2_createak`. New `Attest(nonce, pcrs[])` RPC returns:
      tpm2_quote bytes + ECDSA signature, AK + EK pubkeys, AK name,
      per-PCR digests, raw `pcrs.bin`, and the firmware event log.
      `pancake enroll` now also exports `/etc/pancake/ek.pub` (EK
      extraction is decoupled from systemd-creds — works on direct
      `-kernel` boots too, with a warning that token sealing is
      skipped). Verifier (`pancake attest --target=… --ek-pub=… --kit=…`)
      runs five checks:
        1. EK pubkey byte-match vs the file shipped at enroll time.
        2. **Credential activation**: verifier generates random secret,
           `tpm2_makecredential -T none` encrypts it to AK-name under
           EK; `ActivateCredential` RPC asks the VM's TPM to decrypt;
           verifier compares secrets. Cryptographic proof AK is in the
           same TPM as the enrolled EK.
        3. Quote signature: `tpm2_checkquote` against AK pubkey + nonce.
        4. PCR 13 = `extend(0×32, sha256(generation manifest.toml))`.
        5. PCR 14 = `extend(0×32, sha256(lowers TSV))`.
      Plus an INFO-level PCR 11 firmware-event-log replay: parse
      `/sys/kernel/security/tpm0/binary_bios_measurements` (TCG_PCR_EVENT
      + TCG_PCR_EVENT2 records), replay sha256 extends, print the
      UKI section measurements (`.linux .osrel .cmdline .initrd .uname`)
      so operators can confirm the loaded UKI. Live PCR 11 typically
      diverges from firmware-replay because systemd-pcrextend appends
      `sysinit`/`ready`/etc. from userspace — flagged INFO with both
      values, not FAIL.
- [ ] LUKS2 encryption of the state partition with TPM-sealed key
      (Step 5, deferred — kit is mostly public-FOSS so confidentiality
      isn't the most valuable next thing; integrity gates are already
      in place).
- [ ] Full reproducible-build pin for `pancake serve`'s auto-rebuild
      path. Today `layer.MakeVerity` pins UUID + hash_seed + verity salt
      + verity UUID + SOURCE_DATE_EPOCH (all derived from the layer
      slug), but two builds of the same package on the same VM still
      produce different verity roothashes — likely `metadata_csum_seed`
      or directory-entry ordering noise. Until this is pinned the VM
      will refuse most pushed manifests with new layers, falling back
      to the "ship layers out-of-band" model. Tracking the exact
      remaining sources of non-determinism in e2fsprogs is a task on
      its own.
- [ ] Auto-enroll dev cert into OVMF's `db` for one-command Secure Boot
      verification in QEMU (Step 5 — convenience; today it's a manual
      `ovmf-vars-generator` invocation)
- [ ] `pancake install` should re-sign the new generation manifest
      with the kit's signing key (today, in-VM-created generations are
      unsigned and fail verification on reboot — the live-pivoted
      running system trusts them transitively from its boot chain, but
      a reboot reverts to the last bootstrap-time signed gen). Likely
      requires the signing key to live alongside the kit on disk
      (production model is "build new kit on the build host, ship it"
      rather than in-VM mutation).
