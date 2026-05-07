# fs-pancake / pancake-os

A Debian-derived OS where every package is its own dm-verity image and the
rootfs is reassembled atomically via `pivot_root(2)`.

```
                            ┌──────────────────────────────────┐
                            │  upperdir  (tmpfs, ephemeral)    │  writes
                            ├──────────────────────────────────┤
                       /    │  nano                            │  ← layered
                   overlay  ├──────────────────────────────────┤
                            │  openssh-server                  │
                            ├──────────────────────────────────┤
                            │  systemd                         │
                            ├──────────────────────────────────┤
                            │  libc6                           │
                            ├──────────────────────────────────┤
                            │  ... ~140 .deb-derived layers    │
                            ╞══════════════════════════════════╡
                            │  nullfs    (immutable, empty)    │  real rootfs
                            └──────────────────────────────────┘
```

Built on Christian Brauner's vfs work (lands in Linux 7.2): the immutable
`nullfs` rootfs gives `/` a real parent, making `pivot_root(2)` legal on a
running multi-process system. `pivot_root` then calls `chroot_fs_refs()`
in-kernel, which atomically rebases every running task's `fs.root` to the
new tree. systemd and every daemon keep running and immediately see the new
content. No reboot, no systemd cooperation, no per-daemon hooks.

## Layout

```
fs-pancake/
├── pivot-root.c              the kernel-syscall helper for the live swap
├── slides.md                 walkthrough deck (Marp markdown)
├── DESIGN.md                 architecture + manifest schema + workflows
│
├── tools/                    pancake-os tooling (Python + bash)
│   ├── pancake_lib.py            shared helpers (verity image, manifest)
│   ├── pancake-build             one .deb → one verity image + manifest
│   │                             (overlay sandbox + dpkg --install + diff)
│   ├── pancake-bootstrap         mmdebstrap + per-package snapshot →
│   │                             complete kit (~140 layers + gen 1)
│   ├── pancake                   list / history / show / add / activate /
│   │                             rollback (operates on a kit dir)
│   ├── pack-kit-disk.sh          wrap a kit dir into an ext4 disk image
│   └── build-pancake-initramfs.sh    build the manifest-driven initramfs
│
├── initramfs/                manifest-driven /init
│   ├── init                      reads /var/lib/pancake/current/lowers,
│   │                             opens verity for each layer, mounts
│   │                             overlay via fsconfig, switch_root
│   └── mount-overlay.c           fsopen + N × fsconfig(lowerdir+) + fsmount
│                                 — bypasses mount(2)'s 4 KiB option-string
│                                 cap (essential for 100+ lowerdirs)
│
└── vm/                       earlier-generation harness (curated base +
                              per-daemon overlay; kept as the swap-only
                              demo. The newer pancake-os tooling above
                              supersedes it.)
```

## Required kernel

`bpf-next/for-next` or any tree containing Brauner's series:

| Commit | What |
|--------|------|
| `576ee5dfd459` | `fs: add immutable rootfs` (nullfs) |
| `313c47f4fe4d` | `fs: use nullfs unconditionally as the real rootfs` |
| `3c1b73fc6a4d` | `fs: add init_pivot_root()` |
| `ccfac16e0be5` | `move_mount: allow MOVE_MOUNT_BENEATH on the rootfs` |
| `c62a4766937e` | `move_mount: transfer MNT_LOCKED` |

Lands in Linux 7.2.

## Quick start

### Build a kit + boot pancake-os in QEMU

```sh
# 1. build a complete pancake-os kit (~140 .deb-derived layers + initial generation)
sudo tools/pancake-bootstrap \
    --suite noble \
    --packages openssh-server,chrony,nano \
    --output /tmp/pancake-kit \
    --keep-sandbox                 # needed for `pancake add` later

# 2. wrap the kit into a virtio-blk disk image
tools/pack-kit-disk.sh /tmp/pancake-kit /tmp/pancake-state.img

# 3. build the initramfs (manifest-driven /init)
KVER=7.0.0-g9f5b3ffc3f1d \
    tools/build-pancake-initramfs.sh /tmp/pancake-initramfs.cpio.gz

# 4. boot
qemu-system-x86_64 -enable-kvm -cpu host -m 2G -smp 2 \
    -kernel ~/projects/linux-bpf-for-next/arch/x86/boot/bzImage \
    -initrd /tmp/pancake-initramfs.cpio.gz \
    -append "console=ttyS0 rdinit=/init pancake.state=SERIAL=pancake-state" \
    -drive file=/tmp/pancake-state.img,format=raw,if=none,id=pstate,readonly=on \
    -device virtio-blk,drive=pstate,serial=pancake-state \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \
    -device virtio-net,netdev=net0 \
    -nographic
# → systemd up, multi-user.target reached in ~3s, 140 verity layers stacked
```

### Use the `pancake` CLI on a kit

```sh
$ tools/pancake --kit /tmp/pancake-kit list
generation 1  (initial generation (140 layers))
  layers : 140
  pancake-state           1.0.0
  systemd                 255.4-1ubuntu8
  libc6                   2.39-0ubuntu8
  openssh-server          1:9.6p1-3ubuntu13.16
  ...

$ apt-get download nano && \
  sudo tools/pancake --kit /tmp/pancake-kit add nano_*.deb --activate
[pancake] building layer from nano_7.2-2ubuntu0.1_amd64.deb
[pancake-build] nano 7.2-2ubuntu0.1
  → /tmp/pancake-kit/repo/nano-7.2-2ubuntu0.1/image.img  roothash=ab12cd34…
[pancake] activated generation 2

$ tools/pancake --kit /tmp/pancake-kit history
    id  created                    layers  description
     1  2026-05-07T23:36:26+00:00     140  initial generation (140 layers)
 *   2  2026-05-07T23:36:26+00:00     141  +nano 7.2-2ubuntu0.1

$ sudo tools/pancake --kit /tmp/pancake-kit rollback
[pancake] current → generations/1
```

## Architecture cheat sheet

| Concept | Storage / location |
|---|---|
| One package | `kit/repo/<name>-<ver>/image.img` (ext4) + `image.hash` (verity) + `manifest.toml` |
| One installed system snapshot ("generation") | `kit/generations/<n>/manifest.toml` + `lowers` (TSV sidecar) |
| The active snapshot | `kit/current` symlink → `generations/<n>` |
| Boot | initramfs reads `/var/lib/pancake/current/lowers`, verity-opens each layer, mounts overlay via `fsconfig(... lowerdir+ ...)`, `switch_root` |
| Live swap | `pancake add foo.deb --activate` → builds layer → writes new generation → updates `current` → (live) `pivot_root` (via `pivot-root.c`) |

See `DESIGN.md` for the full manifest schema and the bootstrap / install /
rollback workflows.

## Slides

```
github.com/sinkap/fs-pancake/blob/main/slides.md   # source
github.com/sinkap/fs-pancake/blob/main/slides.pdf  # rendered
```
