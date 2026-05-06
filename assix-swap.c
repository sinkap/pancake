// assix-swap — atomic overlay swap via the new mount API.
//
// Builds an overlay v2 with fsopen("overlay") + fsconfig() + fsmount(), then
// uses move_mount(MOVE_MOUNT_BENEATH) to stack v2 underneath an existing top
// mount at --target, and finally umount2()s the top so v2 is revealed.
//
// Why not mount(2): the old mount call packs lowerdir into a single options
// string, capped at one page (~30-90 lowers depending on path length). The
// fsconfig SET_STRING form of "lowerdir+" appends one path per call — no cap.
// MOVE_MOUNT_BENEATH gives a true atomic swap: no window where /target is
// missing or wrong; running processes pinned to v1 keep working until they
// release; new path lookups go to v2 the moment we umount the top.
//
// Build: make assix-swap     (or: gcc -O2 -Wall -Wextra -o assix-swap assix-swap.c)

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/mount.h>
#include <sys/stat.h>

// Direct syscall wrappers — glibc only added these recently and we want to
// build cleanly on any libc that has the kernel headers.
static int sys_fsopen(const char *fsname, unsigned int flags) {
    return (int)syscall(SYS_fsopen, fsname, flags);
}
static int sys_fsconfig(int fd, unsigned int cmd, const char *key,
                        const void *value, int aux) {
    return (int)syscall(SYS_fsconfig, fd, cmd, key, value, aux);
}
static int sys_fsmount(int fd, unsigned int flags, unsigned int attr_flags) {
    return (int)syscall(SYS_fsmount, fd, flags, attr_flags);
}
static int sys_move_mount(int from_dfd, const char *from_pathname,
                          int to_dfd, const char *to_pathname,
                          unsigned int flags) {
    return (int)syscall(SYS_move_mount, from_dfd, from_pathname,
                        to_dfd, to_pathname, flags);
}

#define MAX_LOWERS 512

struct opts {
    const char *target;
    const char *upper;
    const char *work;
    const char *lowers[MAX_LOWERS];
    int nlowers;
    int keep_top;
    int verbose;
};

static void die(const char *what) {
    fprintf(stderr, "assix-swap: %s: %s\n", what, strerror(errno));
    exit(1);
}

static void usage(void) {
    fputs(
"usage: assix-swap --target PATH --upper PATH --work PATH \\\n"
"                  --lower DIR [--lower DIR ...] [--keep-top] [-v]\n"
"\n"
"Builds an overlay from the given lowers/upper/work via the new mount API\n"
"(no lowerdir option-string limit), stacks it BENEATH the existing top mount\n"
"at --target with move_mount(MOVE_MOUNT_BENEATH), then unmounts the top so\n"
"the new overlay is revealed. With --keep-top the top mount is left in place\n"
"(useful for inspecting both layers via /proc/self/mountinfo).\n",
        stderr);
    exit(2);
}

int main(int argc, char **argv) {
    struct opts o = {0};
    static struct option longopts[] = {
        {"target",   required_argument, 0, 't'},
        {"upper",    required_argument, 0, 'u'},
        {"work",     required_argument, 0, 'w'},
        {"lower",    required_argument, 0, 'l'},
        {"keep-top", no_argument,       0, 'k'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "t:u:w:l:kvh", longopts, NULL)) != -1) {
        switch (c) {
        case 't': o.target = optarg; break;
        case 'u': o.upper = optarg; break;
        case 'w': o.work = optarg; break;
        case 'l':
            if (o.nlowers >= MAX_LOWERS) {
                fprintf(stderr, "assix-swap: too many lowers (max %d)\n", MAX_LOWERS);
                return 2;
            }
            o.lowers[o.nlowers++] = optarg;
            break;
        case 'k': o.keep_top = 1; break;
        case 'v': o.verbose = 1; break;
        case 'h':
        default:  usage();
        }
    }
    if (!o.target || !o.upper || !o.work || o.nlowers == 0) usage();

    int fsfd = sys_fsopen("overlay", 0);
    if (fsfd < 0) die("fsopen(overlay)");

    for (int i = 0; i < o.nlowers; i++) {
        if (sys_fsconfig(fsfd, FSCONFIG_SET_STRING, "lowerdir+",
                         o.lowers[i], 0) < 0) {
            fprintf(stderr, "assix-swap: fsconfig(lowerdir+=%s): %s\n",
                    o.lowers[i], strerror(errno));
            return 1;
        }
        if (o.verbose) fprintf(stderr, "  lowerdir+= %s\n", o.lowers[i]);
    }
    if (sys_fsconfig(fsfd, FSCONFIG_SET_STRING, "upperdir", o.upper, 0) < 0)
        die("fsconfig(upperdir)");
    if (sys_fsconfig(fsfd, FSCONFIG_SET_STRING, "workdir", o.work, 0) < 0)
        die("fsconfig(workdir)");
    if (sys_fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0)
        die("fsconfig(CREATE)");

    int mfd = sys_fsmount(fsfd, 0, 0);
    if (mfd < 0) die("fsmount");

    if (sys_move_mount(mfd, "", AT_FDCWD, o.target,
                       MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH) < 0)
        die("move_mount(BENEATH)");
    if (o.verbose) fprintf(stderr, "v2 stacked beneath %s\n", o.target);

    if (!o.keep_top) {
        // For BENEATH-on-rootfs we need an extra step before the umount:
        // the calling process's fs.root still points at the OLD root mount
        // even after BENEATH inserts the new one beneath. Per Christian's
        // commit message (kernel commit ccfac16e0be5):
        //
        //   mount-beneath inserts the new root under the old one,
        //   chroot(".") switches the caller's root,
        //   and umount2(".", MNT_DETACH) removes the old root.
        //
        // Without the chroot, umount2 detaches the old root + all its
        // submounts (proc/sys/dev) from the namespace tree, leaving processes
        // that haven't been re-rooted (effectively all of them) reading from
        // a detached subtree.
        //
        // For non-rootfs targets, chroot(".") would change the caller's view
        // unexpectedly. Detect rootfs-target and only chroot in that case.
        struct stat tgt_st, root_st;
        int is_rootfs_target = 0;
        if (stat(o.target, &tgt_st) == 0 && stat("/", &root_st) == 0 &&
            tgt_st.st_dev == root_st.st_dev && tgt_st.st_ino == root_st.st_ino) {
            is_rootfs_target = 1;
        }

        if (is_rootfs_target) {
            if (chdir(o.target) < 0) die("chdir(target)");
            if (chroot(".") < 0) die("chroot(\".\")");
            if (umount2(".", MNT_DETACH) < 0) die("umount2(\".\", MNT_DETACH)");
            if (o.verbose) fprintf(stderr, "rootfs swap: chrooted, top lazy-unmounted\n");
        } else {
            if (umount2(o.target, MNT_DETACH) < 0) die("umount2(top, MNT_DETACH)");
            if (o.verbose) fprintf(stderr, "top lazy-unmounted; v2 is now visible\n");
        }
    }

    close(mfd);
    close(fsfd);
    return 0;
}
