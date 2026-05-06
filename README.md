# fs-pancake

Atomic, live rootfs swap on a running multi-process Linux system, using
Christian Brauner's vfs work merging into 7.2 — `nullfs` immutable rootfs
+ `pivot_root(2)` + `chroot_fs_refs`.

A test harness that:
- Builds a Debian (Ubuntu Noble) base + per-daemon (sshd, chrony) overlay
  images on dm-verity.
- Boots them under QEMU/KVM via a custom initramfs that stacks an overlay
  rootfs at `/sysroot` and `switch_root`s into it.
- Live-swaps the rootfs (or any single daemon overlay) on the running VM
  via `pivot_root(2)`. systemd, sshd, chrony all keep running; new
  connections see the new content. No reboot, no systemd cooperation.

## Layout

```
fs-pancake/
├── slides.md              the deck (Marp markdown)
├── assix.sh               original generic many-lowerdir overlay test (host)
├── assix-swap.c           MOVE_MOUNT_BENEATH helper (caller-only swap)
├── assix-swap-rootfs.c    BENEATH on rootfs (caller-only)
├── test-pivot-root.c      ★ pivot_root(2) helper — system-wide swap
├── test-beneath-rootfs.c  selftest port
├── test-beneath-keep-proc.c  variant that keeps proc/sys/dev alive
└── realworld/
    ├── build-base.sh           mmdebstrap → ext4 + dm-verity (rootfs base)
    ├── build-pkg.sh            dpkg-deb -x → ext4 + dm-verity (per-daemon)
    ├── build-initramfs.sh      busybox + veritysetup + modules → cpio.gz
    ├── init                    /init for the initramfs
    ├── run-vm.sh               qemu-system-x86_64 launcher
    ├── swap-pkg.sh             swap via MOVE_MOUNT_BENEATH (per-daemon /opt model)
    ├── swap-pkg-pivot.sh       ★ swap via pivot_root + chroot_fs_refs
    └── lib.sh                  shared bash helpers
```

## Quick start (on a host with the new kernel + dm-verity)

```sh
cd realworld
make all                    # build base.img, sshd-{v1,v2}.img, chronyd-{v1,v2}.img, initramfs
make boot                   # launch the VM under qemu/kvm
make ssh                    # ssh into the VM (port 2222 → guest 22)

./swap-pkg-pivot.sh sshd v2 # live-swap the rootfs to v2
```

## Required kernel

bpf-next/for-next or any tree containing Brauner's series:

| Commit | What |
|--------|------|
| `576ee5dfd459` | fs: add immutable rootfs (nullfs) |
| `313c47f4fe4d` | fs: use nullfs unconditionally as the real rootfs |
| `3c1b73fc6a4d` | fs: add init_pivot_root() |
| `ccfac16e0be5` | move_mount: allow MOVE_MOUNT_BENEATH on the rootfs |
| `c62a4766937e` | move_mount: transfer MNT_LOCKED |

Lands in 7.2.

## The recipe

```c
chdir("/run/newroot");
mkdir("oldroot", 0755);
syscall(SYS_pivot_root, ".", "./oldroot");   // chroot_fs_refs runs in-kernel
chdir("/");
umount2("/oldroot", MNT_DETACH);
```

```sh
mount -t overlay overlay /run/newroot \
    -o lowerdir=NEW_PKG:base:CHRONYD,\
       upperdir=/run/scratch/upper,\
       workdir=/run/scratch/work
for d in proc sys dev run tmp lowers; do
    mount --rbind "/$d" "/run/newroot/$d"
    mount --make-rprivate "/run/newroot/$d"
done
mount --make-rprivate /
# ... pivot_root + umount as above ...
mount --make-rshared /                # restore systemd's expected MS_SHARED
```

See `slides.md` (rendered: `slides.pdf`) for the full walkthrough.
