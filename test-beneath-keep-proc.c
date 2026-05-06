// test-beneath-keep-proc: Christian's selftest workflow + mount-move
// /proc, /sys, /dev to the clone before umount, so OLD has nothing to cascade.
// Then exec a shell in the new namespace so we can interactively verify.

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
static int sys_move_mount(int fd, const char *fp, int td, const char *tp,
                          unsigned flags) {
    return (int)syscall(SYS_move_mount, fd, fp, td, tp, flags);
}

#define check(call) do { \
    int _rc = (call); \
    fprintf(stderr, "  " #call " -> rc=%d errno=%s\n", _rc, _rc<0?strerror(errno):"-"); \
    if (_rc < 0) return 1; \
} while(0)

int main(int argc, char **argv) {
    fprintf(stderr, "[step 1] open_tree(AT_FDCWD, \"/\", CLONE | CLOEXEC)\n");
    int fd = sys_open_tree(AT_FDCWD, "/",
                           OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    if (fd < 0) { perror("open_tree"); return 1; }
    fprintf(stderr, "  fd=%d\n", fd);

    fprintf(stderr, "[step 2] fchdir into clone\n");
    check(fchdir(fd));

    fprintf(stderr, "[step 3] move_mount(BENEATH) — clone goes under /\n");
    check(sys_move_mount(fd, "", AT_FDCWD, "/",
                         MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH));

    // mount-move proc/sys/dev from OLD's children to be children of the clone
    // (cwd, addressed by relative path) before we detach OLD. After move,
    // OLD has no children to cascade-detach.
    fprintf(stderr, "[step 5] chroot(\".\") — caller's fs.root = clone\n");
    check(chroot("."));

    fprintf(stderr, "[step 6] umount2(\".\", MNT_DETACH) — detach overmount (OLD)\n");
    check(umount2(".", MNT_DETACH));

    fprintf(stderr, "[step 6b] mount fresh proc/sys/dev in NEW (caller's view)\n");
    check(mount("proc", "/proc", "proc", 0, NULL));
    check(mount("sys",  "/sys",  "sysfs", 0, NULL));
    check(mount("dev",  "/dev",  "devtmpfs", 0, NULL));

    fprintf(stderr, "[step 7] exec bash to probe the new namespace state\n");
    fflush(stderr);
    char *script =
        "echo === inside chrooted shell ===;"
        "echo --- mountinfo ---; cat /proc/self/mountinfo;"
        "echo --- ls / ---; ls /;"
        "echo --- issue.net ---; cat /etc/issue.net 2>&1;"
        "echo --- ps -p 1 ---; ps -p 1 -o pid,comm 2>&1;"
        "echo --- stat / ---; stat -c \"dev=%d ino=%i\" /";
    execl("/bin/bash", "bash", "-c", script, (char*)NULL);
    perror("execl bash");
    return 1;
}
