// Verbatim port of the kernel selftest "beneath_rootfs_success" from
// tools/testing/selftests/filesystems/move_mount/move_mount_test.c
//
// Sequence:
//   fd_tree = open_tree(AT_FDCWD, "/", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
//   fchdir(fd_tree);
//   move_mount(fd_tree, "", AT_FDCWD, "/", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH);
//   chroot(".");
//   umount2(".", MNT_DETACH);
//
// Then this process exits — leaving the system to be probed from outside.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/mount.h>

static int sys_open_tree(int dfd, const char *path, unsigned flags) {
    return (int)syscall(SYS_open_tree, dfd, path, flags);
}
static int sys_move_mount(int from_dfd, const char *from_pathname,
                          int to_dfd, const char *to_pathname, unsigned flags) {
    return (int)syscall(SYS_move_mount, from_dfd, from_pathname,
                        to_dfd, to_pathname, flags);
}

#define check(call) do { \
    fprintf(stderr, "  " #call " ... "); \
    if ((call) < 0) { fprintf(stderr, "FAIL: %s\n", strerror(errno)); return 1; } \
    fprintf(stderr, "ok\n"); \
} while(0)

int main(void) {
    fprintf(stderr, "running the selftest's beneath_rootfs_success sequence\n");

    int fd = sys_open_tree(AT_FDCWD, "/",
                           OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open_tree failed: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "  open_tree(AT_FDCWD, \"/\", CLONE|CLOEXEC) -> fd=%d\n", fd);

    check(fchdir(fd));
    check(sys_move_mount(fd, "", AT_FDCWD, "/",
                         MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH));
    check(chroot("."));
    check(umount2(".", MNT_DETACH));

    fprintf(stderr, "selftest sequence complete\n");
    return 0;
}
