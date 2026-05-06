---
marp: true
theme: default
paginate: true
size: 16:9
---

# Live rootfs swap on Linux 7.x

Atomically replace the running rootfs of a multi-process system
without any per-daemon cooperation.

`assix` empirical results on `bpf-next/for-next` (`7.0.0-g9f5b3ffc3f1d`).

---

## The pancake — new mount model

```
                ┌──────────────────────────────────┐
   user view →  │ rootfs (overlay, daemon images)  │  ← swappable
                ├──────────────────────────────────┤
                │ nullfs                           │  ← immutable, empty
                │ (mount id 2, makes / have a      │     gives / a real parent
                │  real parent for pivot_root)     │
                └──────────────────────────────────┘
                     PID 1's fs.root.mnt = top
```

`nullfs`: a permanent empty `S_IMMUTABLE` directory.
`fs/nullfs.c` — single inode, no operations, present in every namespace.

---

## Brauner's series (vfs, will land in 7.2)

| Commit | What |
|---|---|
| `576ee5dfd459` | `fs: add immutable rootfs` (nullfs) |
| `313c47f4fe4d` | `fs: use nullfs unconditionally as the real rootfs` |
| `3c1b73fc6a4d` | `fs: add init_pivot_root()` |
| `ccfac16e0be5` | `move_mount: allow MOVE_MOUNT_BENEATH on the rootfs` |
| `c62a4766937e` | `move_mount: transfer MNT_LOCKED` |
| `9b8a0ba68246` | `mount: add OPEN_TREE_NAMESPACE` |
| `5e8969bd1927` | `mount: add FSMOUNT_NAMESPACE` |

---

## Two primitives, two semantics

```
                 caller-only                       system-wide
                 ───────────                       ───────────
                 MOVE_MOUNT_BENEATH                pivot_root
                 + chroot + umount2                + chroot_fs_refs
                                                  
                 only the calling                  every task's fs.root
                 process's fs.root                 atomically rebased
                 changes                           
                                                  
                 → container init bootstrap        → live rootfs replace
```

`chroot_fs_refs()` in `fs/fs_struct.c`:
```c
for_each_process_thread(g, p) {
    replace_path(&fs->root, old_root, new_root);
    replace_path(&fs->pwd,  old_root, new_root);
}
```

---

## MOVE_MOUNT_BENEATH on /

```
  [ OLD ]           [ OLD ]               (gone)
                       │                     
                    [ NEW ]              [ NEW ]    ← visible
     │                 │                    │       
  [nullfs]          [nullfs]             [nullfs]   
                                                    
  before        after BENEATH       after MNT_DETACH
                                                    
  PID 1.fs.root → OLD ──────────────────► OLD (limbo)
                                          /proc cascaded ✗
```

System breaks: every existing process's `fs.root` still points at OLD.

By design — Christian's words: *"individually atomic, locally-scoped steps."*

---

## pivot_root — the actual swap

```
  [ OLD rootfs ]    move_mount    [ OLD ] ── put_old
                    ──────────►       ╲
                                       ╲ chroot_fs_refs
                                        ╲ rewrites every
                                         ▼ fs.root pointer
  [ NEW rootfs ]                    [ NEW rootfs ]    ← / for everyone
       │                                  │
  [   nullfs   ]                    [   nullfs   ]
```

Then `umount2("/oldroot", MNT_DETACH)` drops the old.

---

## The recipe

```c
// test-pivot-root.c — works on a running multi-process system
chdir("/run/newroot");
mkdir("oldroot", 0755);
syscall(SYS_pivot_root, ".", "./oldroot");   // chroot_fs_refs runs here
chdir("/");
umount2("/oldroot", MNT_DETACH);
```

```sh
# shell preamble: stage the new tree with submounts daemons need
mount -t overlay overlay /run/newroot \
    -o lowerdir=NEW_PKG:base:CHRONYD,upperdir=...,workdir=...
for d in proc sys dev run tmp lowers; do
    mount --rbind "/$d" "/run/newroot/$d"
    mount --make-rprivate "/run/newroot/$d"
done
mount --make-rprivate /
```

---

## Demo: sshd v1 → v2 on a live VM

```
[in-vm] BEFORE swap:
  banner: assix sshd v1
  PID 1 mountinfo: 23 lines (lowerdir=/lowers/sshd:...)

[in-vm] pivot_root(".", "./oldroot")
  → kernel: chroot_fs_refs walks all tasks
[in-vm] umount2("/oldroot", MNT_DETACH)

[in-vm] AFTER:
  banner: assix sshd v2
  PID 1 first mount: lowerdir=/run/lowers/sshd-v2:/lowers/base:/lowers/chronyd
  systemctl is-active ssh chrony → active / active

# fresh ssh from outside:
$ cat /etc/issue.net    →  assix sshd v2
$ chronyc tracking      →  syncing
```

---

## Why this is interesting

- No per-daemon cooperation needed — daemons unaware
- No systemd-side magic — vanilla Ubuntu Noble systemd
- `nullfs` removes the "rootfs has no parent" obstacle
- Same primitive used by initramfs `pivot_root`, now usable post-boot
- Verity-stacked overlay rootfs can be **atomically replaced** while running

```
  Old workflow                New workflow
  ────────────                ────────────
  reboot → kexec              pivot_root + chroot_fs_refs
  systemd soft-reboot         (no PID 1 re-exec)
  per-daemon overlays         (rootfs as one unit)
```

---

## What it does NOT solve

- Existing processes still **execute the OLD binary** (their `/proc/PID/exe` pins the old inode). Need `systemctl restart $svc` to re-exec.
- Open file descriptors on OLD content stay valid (good — graceful)
- New connections / new exec'd processes get NEW.

So pivot_root + restart per service = real "rolling update of a verity-image rootfs without rebooting."
