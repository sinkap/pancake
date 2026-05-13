---
marp: true
theme: default
paginate: true
size: 16:9
style: |
  section { font-size: 26px; padding: 50px 60px; }
  h1 { color: #1a1a1a; }
  h2 { color: #2a2a2a; border-bottom: 2px solid #ddd; padding-bottom: 6px; }
  pre { font-size: 20px; line-height: 1.4; }
  code { font-size: 0.95em; }
  table { font-size: 0.9em; margin: 10px auto; }
  th, td { padding: 6px 12px; }
  .small { font-size: 18px; color: #666; }
  .right { text-align: right; }
---

<!-- _class: lead -->

# pancake-os
## image-based Linux · atomic updates · remote attestation

<br>

KP Singh · [github.com/sinkap/pancake](https://github.com/sinkap/pancake)

---

## The pancake

```
            ┌──────────────────────────────────┐
            │  upperdir  (tmpfs, ephemeral)    │  writes
            ├──────────────────────────────────┤
       /    │  pancake-host    (per-host)      │  ← top
   overlay  ├──────────────────────────────────┤
            │  pancake-runtime (CLI + units)   │
            ├──────────────────────────────────┤
            │  pancake-base    (passwd/PAM/…)  │
            ├──────────────────────────────────┤
            │  ~150 .deb-derived layers        │
            ╞══════════════════════════════════╡
            │  nullfs   (immutable, empty)     │  real rootfs
            └──────────────────────────────────┘
```

Every layer is a dm-verity-signed ext4 image. Rootfs = `mount -t overlay`.

---

## Layer roles

| Layer | What's in it | Built where |
|---|---|---|
| **`<deb>-<ver>`** × N | one .deb's payload (no dpkg metadata, no docs) | server |
| **`pancake-base`** | identity tables, PAM common-*, `/etc/hosts`, `/etc/profile`, … | server |
| **`pancake-runtime`** | pancake CLI + `mount-overlay`/`pivot-root` + systemd generator | server (blob inputs) |
| **`pancake-kernel`** + **`pancake-modules`** | bzImage + `/lib/modules/<v>/` | server (blob inputs) |
| **`pancaked`** | the in-VM agent daemon | server (blob input) |
| **`pancake-host`** | hostname, ssh keys, sshd_config, resolv.conf, machine-id | **client** |

`pancake-host` is per-host; everything else is shared across the fleet.

---

## How a kit gets built

```
  recipe.toml ────────────────►  pancake bootstrap --builder=…
                                          │
                                          │ gRPC: BuildGeneration
                                          ▼
                                  pancake-build-server
                                  (containerized, persistent
                                   roothash-keyed cache)
                                          │
                                          │ gRPC: GetLayer × N
                                          ▼
                                  kit/repo/<roothash>/
                                  └── manifest.toml + .sig
```

One mmdebstrap on the server; clients only download canonical layer bytes.

<span class="small">Same `(suite, sorted package set)` → same roothashes across the fleet.</span>

---

## Boot

```
  qemu/kvm
     │
     ▼
  signed UKI (kernel + initramfs + cmdline + manifest.pubkey)
     │     ← UEFI Secure Boot verifies
     │     ← systemd-stub measures into PCR 11
     ▼
  /init
     │   verify generations/<id>/manifest.toml.sig
     │   compare manifest.counter vs TPM NV index 0x01400001
     │   extend PCR 13 = sha256(manifest.toml)
     │   extend PCR 14 = sha256(lowers TSV)
     │   veritysetup open  (one per layer)
     │   mount overlay /sysroot   (fsopen + N × fsconfig "lowerdir+")
     ▼
  switch_root /sysroot /sbin/init
```

Tampering anywhere on the chain → wrong PCR → unseal/decrypt fails → won't boot.

---

## Required kernel: Brauner's nullfs series (Linux 7.2)

```
576ee5dfd459  fs: add immutable rootfs
313c47f4fe4d  fs: use nullfs unconditionally as the real rootfs
3c1b73fc6a4d  fs: add init_pivot_root()
ccfac16e0be5  move_mount: allow MOVE_MOUNT_BENEATH on the rootfs
c62a4766937e  move_mount: transfer MNT_LOCKED
```

Together: `pivot_root(2)` legal on a running multi-process system.

---

## The atomic primitive

```c
// fs/fs_struct.c — invoked by pivot_root(2)
void chroot_fs_refs(const struct path *old, const struct path *new) {
    for_each_process_thread(g, p) {
        replace_path(&p->fs->root, old, new);
        replace_path(&p->fs->pwd,  old, new);
    }
}
```

<br>

**Every running task's `fs.root` is rebased atomically.**
systemd, sshd, chrony — all running, all keep running, all see the new tree.

---

## Live-swap recipe

1. Stage new rootfs at `/run/newroot` (overlay of new layers)
2. rbind `/proc /sys /dev /run /tmp /lowers` (preserves systemd sockets)
3. `mount --make-rprivate /` (pivot_root requires private propagation)
4. `pivot_root(".", "./oldroot")`  ← the atomic moment
5. `umount2("/oldroot", MNT_DETACH)`
6. `mount --make-rshared /` (restore systemd's nspawn assumption)

<br>

~30 lines of shell + 5 lines of C. No daemon cooperation needed.

---

## Live demo · sshd v1 → v2

```
[in-vm]  pancake list
  → openssh-server-9.6p1-3ubuntu13.16

[in-vm]  pancake install ./openssh-server-9.6p1-3ubuntu13.20.deb
[in-vm]  pancake swap                  ← pivot_root(2)

[in-vm]  pancake list
  → openssh-server-9.6p1-3ubuntu13.20

# from another shell:
$ ssh root@vm                          ← still works, same connection
```

systemd, chrony, ssh.socket — all kept their PIDs. No reboot.

---

## Trust chain

```
  build server      ┌───────────────────────────────────────┐
  ──────────────    │  signs manifest.toml with kit's key   │
                    └───────────────────┬───────────────────┘
                                        │
  initramfs/init    ┌───────────────────▼───────────────────┐
  ──────────────    │  verifies sig with baked-in pubkey    │
                    │  TPM NV counter ≥ manifest.counter ?  │
                    │  extend PCR 13 + PCR 14               │
                    └───────────────────┬───────────────────┘
                                        │
  pancaked          ┌───────────────────▼───────────────────┐
  ──────────────    │  bearer token unsealed (PCR 7+11)     │
                    │  per-boot AK + EK provisioned         │
                    │  Attest RPC ready                     │
                    └───────────────────────────────────────┘
```

---

## Remote attestation

```
   verifier                                   pancaked (in VM)
   ────────                                   ────────────────
   Attest(nonce) ──────────────────────────►
                                              tpm2_quote → quote, sig
                                              read /sys/.../bios_measurements
                       ◄────── quote, sig, AK pub, EK pub, AK name,
                                PCRs, event log, pcrs.bin

   tpm2_makecredential
        ─e ek.pub  ─n ak.name  ─s SECRET ─o blob
   ActivateCredential(blob) ─────────────►
                                              tpm2_activatecredential
                                              ─C ek.ctx  ─c ak.ctx  ─i blob
                       ◄────── secret′
   SECRET == secret′  ⇒  AK is in the same TPM as enrolled EK
```

---

## Five checks per attest

```
[attest] OK    EK pubkey matches enrolled
[attest] OK    credential activation (AK is in same TPM as enrolled EK)
[attest] OK    quote signature valid (AK signed nonce + PCRs)
[attest] OK    PCR 13 = extend(sha256(manifest.toml))
[attest] OK    PCR 14 = extend(sha256(lowers))
[attest] INFO  PCR 11 firmware-event-log replay (12 firmware entries):
  [34] PCR11 sha256=0da293e3… event=".linux"
  [35] PCR11 sha256=04b7730f… event=".linux"
  [36] PCR11 sha256=3fb9e4e3… event=".osrel"
  [37..] event=".cmdline" .initrd .uname
[attest] OVERALL PASS
```

Tamper the kit → PCR 13/14 mismatch. Swap the kernel → PCR 11 chain breaks.

---

## Demo: `demo/demo.sh`

```bash
demo/demo.sh --bzimage=~/linux/arch/x86/boot/bzImage \
             --auth-key=~/.ssh/id_ed25519.pub
```

Does, end-to-end:

1. Build pancake binaries
2. Build + start `pancake-build-server` container (cache volume)
3. Bootstrap a signed UEFI kit via the build server
4. Boot under OVMF + swtpm
5. `pancake enroll` inside VM → seal token + export EK
6. `pancake attest` from host → all 5 checks PASS

~3 minutes cold; <30 s on cache hit.

---

## Containers on the same host

`chroot_fs_refs` only matches tasks whose root is the *host's* old root.
Container processes have their own `fs.root` (set by the runtime's own
`pivot_root`) — **untouched** by a host swap.

| Setup | Impact |
|---|---|
| Docker / Podman (private propagation by default) | None |
| `systemd-nspawn --bind=…` | Bind mounts intact; future host events stop reaching |
| Containers with rbound `/lowers`, `/run`, `/dev` | Still work (same superblock) |

---

<!-- _class: lead -->

# Wrap-up

Verity-imaged rootfs · live atomic swap · remote attestation

<br>

[github.com/sinkap/pancake](https://github.com/sinkap/pancake) · `demo/demo.sh`

<br>

<span class="small">Kernel: bpf-next/for-next (lands in 7.2) · systemd: 255+, unmodified</span>

<br>

KP Singh
