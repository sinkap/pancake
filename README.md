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
├── tools/                    pancake-os tooling
│   ├── pancake-go/               Go module — single static binary per tool
│   │   ├── cmd/pancake               list / history / show / install /
│   │   │                             activate / rollback / swap
│   │   ├── cmd/pancake-build         one .deb → one verity image + manifest
│   │   ├── cmd/pancake-bootstrap     mmdebstrap + per-package snapshot →
│   │   │                             complete kit (~150 layers + gen 1)
│   │   └── internal/{runner,kit,deb,layer,sandbox}
│   │                                 shared library code
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

### 0. Build the Go tooling (one-time per checkout)

```sh
cd tools/pancake-go
go build -ldflags="-s -w" -o ./bin/ ./cmd/...
# → bin/pancake  bin/pancake-build  bin/pancake-bootstrap
# Each is a self-contained ~2 MB statically-linked ELF — no runtime deps,
# no python in the kit.
```

### 1. Build a kit + boot pancake-os in QEMU

```sh
# 1. build a complete pancake-os kit (~150 .deb-derived layers + initial generation)
sudo tools/pancake-go/bin/pancake-bootstrap \
    --suite noble \
    --packages openssh-server,chrony,nano \
    --output /var/tmp/pancake-kit \
    --hostname pancake \
    --src-root $(pwd) \
    --ssh-authorized-keys ~/.ssh/authorized_keys

# 2. wrap the kit into a virtio-blk disk image
sudo tools/pack-kit-disk.sh /var/tmp/pancake-kit /var/tmp/pancake-state.img

# 3. build the initramfs (manifest-driven /init)
sudo KVER=7.0.0-g9f5b3ffc3f1d \
    tools/build-pancake-initramfs.sh /var/tmp/pancake-initramfs.cpio.gz

# 4. boot — `format=raw,readonly=off` so `pancake install` / `pancake swap`
#    can write back into the kit at runtime.
sudo qemu-system-x86_64 -enable-kvm -cpu host -m 4G -smp 4 \
    -kernel ~/projects/linux-bpf-for-next/arch/x86/boot/bzImage \
    -initrd /var/tmp/pancake-initramfs.cpio.gz \
    -append "console=ttyS0 rdinit=/init pancake.state=SERIAL=pancake-state" \
    -drive file=/var/tmp/pancake-state.img,format=raw,if=none,id=pstate \
    -device virtio-blk,drive=pstate,serial=pancake-state \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \
    -device virtio-net,netdev=net0 \
    -nographic
# → systemd up, multi-user.target reached in ~3s, ~150 verity layers stacked
```

### 2. Use the `pancake` CLI

The same binary runs on the host (operating on a kit dir on disk) and inside
the booted VM (where it can also do `install` and `swap`).

```sh
# Host side: just inspect the kit
$ tools/pancake-go/bin/pancake --kit /var/tmp/pancake-kit list
generation 1  (initial generation (149 layers))
  layers : 149
  pancake-state           1.0.0
  systemd                 255.4-1ubuntu8
  ...

# Inside the booted VM (ssh -p 2222 root@localhost):

$ pancake history
    id  created                    layers  description
 *   1  2026-05-11T09:56:03+00:00     149  initial generation (149 layers)

$ pancake install vim --activate     # apt resolves deps; each becomes a verity layer
[pancake] apt update + install [vim]
...
[pancake] 12 new packages (after dep resolution)
  → vim 2:9.1.0016-1ubuntu7
  → vim-runtime 2:9.1.0016-1ubuntu7
  ...
[pancake] activated generation 2

$ pancake swap                        # live atomic rootfs replacement, no reboot
[swap] preparing 161 layers (12 new, 0 to retire)
[swap] current → generations/2 (committed)
[step 3] pivot_root(".", "./oldroot")
         this calls chroot_fs_refs internally to update EVERY task fs.root
  pivot_root OK
[swap] live swap complete — running generation 2

$ which vim                           # vim is now usable; uptime didn't change
/usr/bin/vim
$ uptime
 12:02:29 up 3 min,  0 user

$ pancake rollback                    # set current → previous generation (offline);
                                      # next `pancake swap` will pivot back
```

## Architecture cheat sheet

| Concept | Storage / location |
|---|---|
| One package | `kit/repo/<name>-<ver>/image.img` (ext4) + `image.hash` (verity) + `manifest.toml` |
| One installed system snapshot ("generation") | `kit/generations/<n>/manifest.toml` + `lowers` (TSV sidecar) |
| The active snapshot | `kit/current` symlink → `generations/<n>` |
| Boot | initramfs reads `/var/lib/pancake/current/lowers`, verity-opens each layer, mounts overlay via `fsconfig(... lowerdir+ ...)`, `switch_root` |
| Live swap | `pancake install <pkg>` (or `add <foo.deb>`) → builds layer(s) → writes new generation; then `pancake swap` opens new lowers, builds new overlay at `/pancake-newroot`, calls `pivot_root(2)` which calls `chroot_fs_refs()` to atomically rebase every running task's `fs.root` |

See `DESIGN.md` for the full manifest schema and the bootstrap / install /
rollback workflows.

## Slides

```
github.com/sinkap/fs-pancake/blob/main/slides.md   # source
github.com/sinkap/fs-pancake/blob/main/slides.pdf  # rendered
```
