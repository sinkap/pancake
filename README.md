# fs-pancake

Live, atomic rootfs swap on a running multi-process Linux system.

```
                            ┌──────────────────────────────────┐
                            │  upperdir  (tmpfs, ephemeral)    │  writes
                            ├──────────────────────────────────┤
                       /    │  sshd-v1     (dm-verity ext4)    │  lowerdir, leftmost wins
                   overlay  ├──────────────────────────────────┤
                            │  chronyd-v1  (dm-verity ext4)    │
                            ├──────────────────────────────────┤
                            │  base v1     (dm-verity ext4)    │
                            ╞══════════════════════════════════╡
                            │  nullfs      (immutable, empty)  │  real rootfs
                            └──────────────────────────────────┘
```

Built on Christian Brauner's vfs work merging into Linux 7.2:
the immutable `nullfs` rootfs gives the user-visible `/` a real parent,
making `pivot_root(2)` legal on a running multi-process system.
`pivot_root` then calls `chroot_fs_refs()` in-kernel, which atomically
rebases every running task's `fs.root` to the new tree. systemd, sshd,
chrony, etc. keep running and immediately see the new content.

## Layout

```
fs-pancake/
├── pivot-root.c          ★ the syscall-level helper (5 essential lines)
├── Makefile                builds pivot-root
├── slides.md               walkthrough deck (Marp markdown)
└── vm/                     QEMU/KVM end-to-end harness
    ├── build-base.sh           mmdebstrap → ext4 + dm-verity (rootfs base)
    ├── build-pkg.sh            dpkg-deb -x → ext4 + dm-verity (per-daemon)
    ├── build-initramfs.sh      busybox + veritysetup + modules → cpio.gz
    ├── init                    /init for the initramfs
    ├── run-vm.sh               qemu-system-x86_64 launcher
    ├── swap-pkg.sh           ★ stage new tree + pivot_root + lazy umount
    ├── lib.sh                  shared bash helpers
    └── Makefile                build / boot / ssh
```

## Required kernel

Any tree containing Brauner's series (lands in 7.2):

| Commit | What |
|--------|------|
| `576ee5dfd459` | `fs: add immutable rootfs` — nullfs |
| `313c47f4fe4d` | `fs: use nullfs unconditionally as the real rootfs` |
| `3c1b73fc6a4d` | `fs: add init_pivot_root()` |
| `ccfac16e0be5` | `move_mount: allow MOVE_MOUNT_BENEATH on the rootfs` |
| `c62a4766937e` | `move_mount: transfer MNT_LOCKED` |

`bpf-next/for-next` works today.

## Quick start

```sh
# 1. build the helper
make

# 2. build VM images (mmdebstrap pulls a Debian/Ubuntu base; dpkg-deb
#    extracts daemon .debs and stamps each into a verity-signed ext4 image)
cd vm
make all

# 3. boot the VM
make boot              # qemu-system-x86_64 with -kernel = host kernel,
                       # -initrd = our initramfs, virtio-blk per image

# 4. ssh in (port 2222 on host → 22 in guest)
make ssh

# 5. live-swap the rootfs to v2 (in another terminal, on the host)
./swap-pkg.sh sshd v2  # banner / marker / mountinfo flip to v2,
                       # systemd & sshd & chrony stay running
```

## The recipe (in one place)

```c
/* pivot-root.c — the kernel-side magic in 5 lines */
chdir("/run/newroot");
mkdir("oldroot", 0755);
syscall(SYS_pivot_root, ".", "./oldroot");   /* chroot_fs_refs runs here */
chdir("/");
umount2("/oldroot", MNT_DETACH);
```

```sh
# the userspace dance around it (vm/swap-pkg.sh)

# 1. stage the new rootfs
mount -t overlay overlay /run/newroot \
    -o lowerdir=NEW_PKG:base:CHRONYD,\
       upperdir=/run/scratch/upper,\
       workdir=/run/scratch/work

# 2. rbind dynamic-state mounts so daemons keep their sockets / dev nodes
for d in proc sys dev run tmp lowers; do
    mount --rbind "/$d" "/run/newroot/$d"
    mount --make-rprivate "/run/newroot/$d"
done

# 3. flip / private (pivot_root rejects shared propagation)
mount --make-rprivate /

# 4. the swap (pivot-root binary)
./pivot-root /run/newroot

# 5. restore systemd's expected MS_SHARED state
mount --make-rshared /
```

## Caveats

- Existing daemon processes keep executing the **old binary** (their pages
  are loaded into memory, immune to filesystem changes). To run the new
  code, `systemctl restart $svc` so it `execve`s through the new tree.
- Open file descriptors on old content stay valid (graceful drain).
- New connections / fresh `exec`s land on the new tree.
- Containers on the host: their processes are untouched (their `fs.root` is
  inside their own mount namespace), but mount propagation between host and
  container is severed by the `make-rprivate /` step. See `slides.md`.

## Slides

```
github.com/sinkap/fs-pancake/blob/main/slides.md   # source
github.com/sinkap/fs-pancake/blob/main/slides.pdf  # rendered
```
