// assix-swap-rootfs — atomically swap the rootfs.
//
// The caller is responsible for preparing a fully-equipped new root tree at
// --staging:  /<staging>/{proc,sys,dev,...} should already be mounted before
// invoking this tool. open_tree(...AT_RECURSIVE) clones the entire subtree
// including submounts; move_mount(...MOVE_MOUNT_BENEATH) brings it in beneath
// the current rootfs; chroot(".") + umount2(".", MNT_DETACH) drops the old.
//
// This is the workflow Christian Brauner described in the kernel commit
// ccfac16e0be5 "move_mount: allow MOVE_MOUNT_BENEATH on the rootfs":
//
//   fd_tree = open_tree(-EBADF, "/newroot",
//                       OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
//   move_mount(fd_tree, "", AT_FDCWD, "/",
//              MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH);
//   chroot(".");
//   umount2(".", MNT_DETACH);
//
// We add AT_RECURSIVE so submounts (proc/sys/dev) come along.
//
// Build: gcc -O2 -Wall -Wextra -o assix-swap-rootfs assix-swap-rootfs.c

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/mount.h>

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

static int sys_open_tree(int dfd, const char *path, unsigned flags) {
    return (int)syscall(SYS_open_tree, dfd, path, flags);
}
static int sys_move_mount(int from_dfd, const char *from_pathname,
                          int to_dfd, const char *to_pathname,
                          unsigned flags) {
    return (int)syscall(SYS_move_mount, from_dfd, from_pathname,
                        to_dfd, to_pathname, flags);
}

static void die(const char *what) {
    fprintf(stderr, "assix-swap-rootfs: %s: %s\n", what, strerror(errno));
    exit(1);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr,
            "usage: %s <staging-path>\n"
            "\n"
            "<staging-path> must be a fully-prepared root tree:\n"
            "  - the merged content (overlay/ext4/whatever) mounted at the path\n"
            "  - /proc, /sys, /dev (and any other rootfs-essential mounts)\n"
            "    already mounted as children of <staging-path>\n",
            argv[0]);
        return 2;
    }
    const char *staging = argv[1];

    fprintf(stderr, "open_tree(CLONE|RECURSIVE) on %s\n", staging);
    int fd = sys_open_tree(-EBADF, staging,
                           OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE);
    if (fd < 0) die("open_tree");

    // The exact workflow from Christian's commit message
    // (ccfac16e0be5 in fs/namespace.c):
    //
    //   fd_tree = open_tree(...);
    //   fchdir(fd_tree);                  ← anchor cwd to the cloned tree's root
    //   move_mount(... BENEATH /);
    //   chroot(".");                      ← caller's root now == cwd == new root
    //   umount2(".", MNT_DETACH);         ← umount detects "." has an overmount
    //                                       (the OLD root, BENEATH'd above by us)
    //                                       and detaches the OVERMOUNT, not "."
    //
    // This is the key: we are not unmounting the new root we just installed,
    // we are unmounting the OLD root which is the OVERMOUNT of "." after the
    // BENEATH. Submounts of OLD cascade-detach, but submounts of NEW (which
    // we prepared) become the new namespace's /proc, /sys, /dev.

    if (fchdir(fd) < 0) die("fchdir(fd_tree)");
    fprintf(stderr, "fchdir into the cloned tree\n");

    fprintf(stderr, "move_mount(BENEATH) into /\n");
    if (sys_move_mount(fd, "", AT_FDCWD, "/",
                       MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH) < 0)
        die("move_mount(BENEATH /)");

    if (chroot(".") < 0) die("chroot(.)");
    fprintf(stderr, "chroot to .\n");

    if (umount2(".", MNT_DETACH) < 0) die("umount2(., MNT_DETACH)");

    fprintf(stderr, "rootfs swap complete (overmount detached)\n");
    close(fd);
    return 0;
}
