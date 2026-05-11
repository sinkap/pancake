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
└── tools/pancake-go/         Go module — ONE static binary, all subcommands
    ├── cmd/pancake               list / history / show / activate / rollback /
    │                             install / swap / build / bootstrap
    └── internal/                 runner, kit, deb, layer, sandbox, pack,
                                  initramfs (shared library code)
│
└── initramfs/                manifest-driven /init
    ├── init                      reads /var/lib/pancake/current/lowers,
    │                             opens verity for each layer, mounts
    │                             overlay via fsconfig, switch_root
    └── mount-overlay.c           fsopen + N × fsconfig(lowerdir+) + fsmount
                                  — bypasses mount(2)'s 4 KiB option-string
                                  cap (essential for 100+ lowerdirs)
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

### 0. Build the CLI (one-time per checkout)

```sh
cd tools/pancake-go
go build -ldflags="-s -w" -o ./bin/ ./cmd/pancake
# → ONE 2.6 MB statically-linked ELF: bin/pancake
# All subcommands live under it: list, history, show, activate, rollback,
# install, swap, build, bootstrap. No python, no runtime deps.
```

### 1. Build a kit + disk image + initramfs in one command

```sh
sudo tools/pancake-go/bin/pancake bootstrap \
    --suite      noble \
    --packages   openssh-server,chrony,nano \
    --output     /var/tmp/pancake-kit \
    --hostname   pancake \
    --src-root   $(pwd) \
    --ssh-authorized-keys ~/.ssh/authorized_keys \
    --image      /var/tmp/pancake-state.img \
    --initramfs  /var/tmp/pancake-initramfs.cpio.gz \
    --kernel     7.0.0-g9f5b3ffc3f1d \
    --bzimage    ~/projects/linux-bpf-for-next/arch/x86/boot/bzImage \
    --bzimage-out /var/tmp/pancake-bzImage
```

**Outputs (all defaults to current directory):**

| flag | default | what it produces |
|---|---|---|
| `--output` | (required) | the kit dir (repo/, generations/, current symlink) |
| `--image` | `./pancake-state.img` | ext4 disk image of the kit, for QEMU `-drive` |
| `--initramfs` | `./pancake-initramfs.cpio.gz` | manifest-driven initramfs, for QEMU `-initrd` |
| `--bzimage-out` | `./pancake-bzImage` | the kernel binary, for QEMU `-kernel` |
| `--efi` | `""` (off) | UEFI-bootable disk image (GPT + ESP + rootfs, systemd-boot + UKI). When set, QEMU needs only OVMF + this image — no `-kernel`/`-initrd`. |
| `--cmdline` | `console=ttyS0 rdinit=/init pancake.state=LABEL=PANCAKE_STATE` | kernel cmdline baked into the UKI for `--efi` |

Pass an empty string to skip any one step (e.g. `--image=""`).

### EFI boot (no `-kernel` arg)

When `--efi PATH` is set, bootstrap also writes:

- a Unified Kernel Image (UKI) at `<PATH>.uki.efi` — bzImage + initrd + cmdline as one signable PE binary, built via `systemd-ukify`
- a GPT disk at `PATH` with two partitions:
  - p1: ESP (vfat, ~256 MB) holding `systemd-bootx64.efi` + `/EFI/Linux/pancake-1.efi` (the UKI) + `/loader/loader.conf`
  - p2: ext4 with the kit, label `PANCAKE_STATE`

Boot:

```sh
sudo cp /usr/share/OVMF/OVMF_VARS_4M.fd /var/tmp/OVMF_VARS-pancake.fd
sudo chmod 666 /var/tmp/OVMF_VARS-pancake.fd
sudo qemu-system-x86_64 -enable-kvm -cpu host -m 4G \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=/var/tmp/OVMF_VARS-pancake.fd \
    -drive file=/var/tmp/pancake-efi.img,format=raw,if=virtio \
    -netdev user,id=n,hostfwd=tcp::2222-:22 -device virtio-net,netdev=n \
    -nographic
```

OVMF reads the ESP, loads systemd-boot, autodiscovers the UKI in
`/EFI/Linux/`, jumps to the kernel; initramfs finds `LABEL=PANCAKE_STATE`,
mounts the overlay, switches root. Whole boot chain is one disk file plus
the firmware.

This path is also where the future TPM signing story lands: the UKI is a
single file that `sbsign` / `cosign` can sign, and UEFI Secure Boot
verifies before loading. Each generation can ship its own signed UKI.

**Kernel selection:**

| flag | meaning |
|---|---|
| `--kernel` | VERSION suffix of `/lib/modules/<value>` on the build host. Modules baked into the initramfs come from there. Default: `uname -r`. |
| `--bzimage PATH` | path to a custom-built bzImage. When set, bootstrap **skips `linux-image-generic`** and instead packs two synthetic verity layers: `pancake-kernel` (`/boot/vmlinuz` from PATH) and `pancake-modules` (`/lib/modules/<--kernel>/` from the host). Use this for kernels not in any apt repo (bpf-next, linux-next, your own builds). |

**Without `--bzimage`** the suite's `linux-image-generic` is pulled by
mmdebstrap, which lands as natural `linux-image-X.Y.Z` and
`linux-modules-X.Y.Z` pancake layers (one per .deb).

The bootstrap-side `--kernel` and the binary at `--bzimage` must obviously
be the same kernel version, but the build tools don't enforce that — the
user is responsible for `make modules_install` having matched the
bzImage they're shipping.

### 2. Boot

```sh
# format=raw,readonly=off so `pancake install` / `pancake swap` can write
# back into the kit at runtime.
sudo qemu-system-x86_64 -enable-kvm -cpu host -m 4G -smp 4 \
    -kernel ~/projects/linux-bpf-for-next/arch/x86/boot/bzImage \
    -initrd /var/tmp/pancake-initramfs.cpio.gz \
    -append "console=ttyS0 rdinit=/init pancake.state=SERIAL=pancake-state" \
    -drive file=/var/tmp/pancake-state.img,format=raw,if=none,id=pstate \
    -device virtio-blk,drive=pstate,serial=pancake-state \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \
    -device virtio-net,netdev=net0 \
    -nographic
# → systemd up, multi-user.target reached in ~3 s, ~150 verity layers stacked
```

### 3. Use the `pancake` CLI

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
