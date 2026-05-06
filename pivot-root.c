// test-pivot-root: live rootfs swap via pivot_root.
//
// Caller has prepared <staging> as a complete rootfs:
//   - overlay (or whatever) mounted at <staging>
//   - /proc, /sys, /dev mounted as children of <staging>
//
// Sequence:
//   chdir(<staging>)
//   mkdir("./oldroot")
//   pivot_root(".", "./oldroot")    ← calls chroot_fs_refs which updates EVERY task's fs.root
//   chdir("/")
//   umount2("/oldroot", MNT_DETACH)
//
// Because chroot_fs_refs walks the task list, this is genuinely a system-wide swap.

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

#define check(call) do { \
    int _rc = (call); \
    fprintf(stderr, "  " #call " -> rc=%d errno=%s\n", _rc, _rc<0?strerror(errno):"-"); \
    if (_rc < 0) return 1; \
} while(0)

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr,
            "usage: %s <staging>\n"
            "  <staging> is a complete prepared rootfs with /proc /sys /dev mounted as children\n",
            argv[0]);
        return 2;
    }
    const char *staging = argv[1];

    fprintf(stderr, "[step 1] chdir(%s)\n", staging);
    check(chdir(staging));

    fprintf(stderr, "[step 2] mkdir ./oldroot (for put_old)\n");
    if (mkdir("oldroot", 0755) < 0 && errno != EEXIST) {
        perror("mkdir oldroot");
        return 1;
    }

    fprintf(stderr, "[step 3] pivot_root(\".\", \"./oldroot\")\n");
    fprintf(stderr, "         this calls chroot_fs_refs internally to update EVERY task's fs.root\n");
    if (syscall(SYS_pivot_root, ".", "./oldroot") < 0) {
        fprintf(stderr, "  pivot_root: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "  pivot_root OK\n");

    fprintf(stderr, "[step 4] chdir(\"/\")\n");
    check(chdir("/"));

    fprintf(stderr, "[step 5] umount2(\"/oldroot\", MNT_DETACH)\n");
    check(umount2("/oldroot", MNT_DETACH));

    fprintf(stderr, "live rootfs swap complete — all tasks now see the new root\n");
    return 0;
}
