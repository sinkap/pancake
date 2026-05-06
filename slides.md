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
---

<!-- _class: lead -->

# FS Pancake: Atomic Updates

<br>

KP Singh · [github.com/sinkap](https://github.com/sinkap)

---

## The pancake

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

Each daemon ships as its own verity-signed image; `base` carries init/systemd/libs.

---

## How we get there · boot

```
  qemu/kvm
     │
     ▼
  kernel + embedded initramfs
     │  mount nullfs               (immutable real rootfs)
     │  mount tmpfs on top         (initramfs)
     ▼
  /init  (PID 1)
     │  veritysetup open  base, sshd, chronyd
     │  mount  /lowers/<pkg>  ro          (one per pkg)
     │  mount  overlay /sysroot           (lowerdir = sshd:chronyd:base,
     │                                     upperdir = tmpfs)
     │  move   /proc /sys /dev /lowers → /sysroot
     ▼
  switch_root /sysroot /sbin/init
     │
     ▼
  systemd  →  ssh.service · chrony.service · …
```

---

## Why it works now

| Commit | What |
|--------|------|
| `576ee5dfd459` | **`fs: add immutable rootfs`** <br> <span class="small">Introduces `nullfs` — a permanently-empty `S_IMMUTABLE` single-inode filesystem. Designed to sit at the bottom of every namespace's mount tree as a placeholder.</span> |
| `313c47f4fe4d` | **`fs: use nullfs unconditionally as the real rootfs`** <br> <span class="small">Removes the boot-time opt-in. Every namespace now actually roots at nullfs, with the user-visible rootfs (initramfs / real /) mounted on top of it.</span> |
| `3c1b73fc6a4d` | **`fs: add init_pivot_root()`** <br> <span class="small">Kernel-internal `pivot_root(2)` helper used during early boot to set up the namespace mount tree.</span> |
| `ccfac16e0be5` | **`move_mount: allow MOVE_MOUNT_BENEATH on the rootfs`** <br> <span class="small">Drops the "must not be a root of some namespace" rejection. Now legal because nullfs is always the real parent.</span> |
| `c62a4766937e` | **`move_mount: transfer MNT_LOCKED`** <br> <span class="small">When BENEATH-stacking under a locked mount, hand the lock to the new mount so the old one becomes unlockable and can be detached.</span> |

<br>

<span class="small">Together: `pivot_root(2)` works on a running multi-process system; no `switch_root` workarounds.</span>

---

## The atomic primitive

```c
// fs/fs_struct.c
void chroot_fs_refs(const struct path *old, const struct path *new) {
    for_each_process_thread(g, p) {
        replace_path(&p->fs->root, old, new);
        replace_path(&p->fs->pwd,  old, new);
    }
}
```

<br>

Called by `pivot_root(2)` at `fs/namespace.c:4727`.

**Every running task's `fs.root` is rebased atomically.**

---

## The workflow

<br>

1. Stage new rootfs at `/run/newroot`
2. Rbind dynamic-state mounts
3. Make propagation private
4. `pivot_root(2)`
5. Unmount old
6. Restore shared propagation

<br>

<span class="small">~30 lines of shell + 5 lines of C.</span>

---

## Step 1 · Stage new rootfs

```
                         ┌──────────────────────┐
   /run/newroot     →    │  overlay             │
                         │  lowerdir = NEW:base │
                         │  upperdir = tmpfs    │
                         └──────────────────────┘
                              (no submounts yet)
```

```bash
mount -t overlay overlay /run/newroot \
    -o lowerdir=NEW_PKG:base:CHRONYD,\
       upperdir=/run/scratch/upper,\
       workdir=/run/scratch/work
```

---

## Step 2 · Rbind dynamic-state mounts

```
/run/newroot/
├─ proc    ← rbind  /proc
├─ sys     ← rbind  /sys
├─ dev     ← rbind  /dev
├─ run     ← rbind  /run         (systemd's sockets!)
├─ tmp     ← rbind  /tmp
└─ lowers  ← rbind  /lowers      (verity images)
```

```bash
for d in proc sys dev run tmp lowers; do
    mount --rbind "/$d" "/run/newroot/$d"
    mount --make-rprivate "/run/newroot/$d"
done
```

---

## Step 3 · Make propagation private

```bash
mount --make-rprivate /
```

<br>

Why: `pivot_root(2)` rejects shared propagation on `old_mnt`,
`new_mnt`'s parent, or `root_mnt`'s parent (`fs/namespace.c:4690`).

systemd hardcodes `mount(NULL, "/", NULL, MS_REC|MS_SHARED, NULL)` at boot
(`src/shared/mount-setup.c:520`, identical in latest 261-devel). No config
knob; only the re-exec path skips it. We flip `/` private at swap time
and restore in step 6.

---

## Step 4 · the `pivot_root(2)` syscall

```c
#include <sys/syscall.h>          // no glibc wrapper exists —
#include <unistd.h>                // we invoke it via syscall(2) directly

chdir("/run/newroot");
mkdir("oldroot", 0755);

syscall(SYS_pivot_root, ".", "./oldroot");   // ← kernel syscall
//   │
//   └─→  inside the kernel:
//        chroot_fs_refs(old_root, new_root)
//        for_each_process_thread → rebase fs.root + fs.pwd
```

```
   Before                          After
   ──────                          ─────
   /        OLD overlay            /         NEW overlay
   /run/    ...                    /oldroot  OLD overlay (moved)
            └─ /newroot/ NEW       /...      (everything else
                                              already rbound)
```

---

## Step 5 · Drop the old root

```c
chdir("/");
umount2("/oldroot", MNT_DETACH);
```

```
   Before                          After
   ──────                          ─────
   /         NEW overlay           /         NEW overlay
   /oldroot  OLD overlay           (gone)
```

<br>

`MNT_DETACH` because daemons may still hold open fds on OLD.
The kernel keeps OLD alive in memory until the last ref drops.

---

## Step 6 · Restore shared propagation

```bash
mount --make-rshared /
```

<br>

Lennart, `docs/CONTAINER_INTERFACE.md` (commit `32f4e30b`):

> *"The mount hierarchy of the container should be mounted MS_SHARED
> before invoking systemd as PID 1. **Things will break at various places**
> if this is not done."*

Symmetric with Step 3. Restores nspawn / sandboxing / propagation behavior.

---

## Live demo · sshd v1 → v2

```
[in-vm] BEFORE
  banner: pancake sshd v1
  PID 1 mountinfo: lowerdir=/lowers/sshd:...

[in-vm] pivot_root(".", "./oldroot")
[in-vm] umount2("/oldroot", MNT_DETACH)

[in-vm] AFTER
  banner: pancake sshd v2
  PID 1 mountinfo: lowerdir=/run/lowers/sshd-v2:...
  ssh / chrony: active

# fresh ssh from outside:
$ cat /etc/issue.net    →  pancake sshd v2
$ chronyc tracking      →  syncing
```

---

## Containers on the same host

Container processes have their **own** `fs.root` (set by their runtime's own
`pivot_root`). `chroot_fs_refs` only matches tasks whose root is the host's
old root → **container processes are untouched**.

But mount propagation severs:

```
   host /              shared peer group P
   container /         slave of P  →  receives host events

   make-rprivate /     →  P destroyed; container becomes orphaned slave
   pivot_root          →  host rootfs swapped (container ns unaffected)
   make-rshared /      →  host joins NEW peer group P'
                          container is NOT in P'
```

| Setup | Impact |
|---|---|
| Docker / Podman (private by default) | None |
| `systemd-nspawn --bind=…` | Bind mounts work; future host events stop reaching container |
| Containers using rbound `/lowers`, `/run`, `/dev` | Still work (same superblock) |

---

<!-- _class: lead -->

# Wrap-up

Verity-imaged rootfs · live atomic swap · no reboot · no systemd cooperation.

<br>

Code & slides: **[github.com/sinkap/fs-pancake](https://github.com/sinkap/fs-pancake)**

<br>

<span class="small">Kernel: bpf-next/for-next (lands in 7.2) · systemd: 255+, unmodified</span>

<br>

KP Singh · [github.com/sinkap](https://github.com/sinkap)
