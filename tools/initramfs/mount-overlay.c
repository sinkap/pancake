// mount-overlay — mount an overlayfs with arbitrarily many lowerdirs.
//
// The classic mount(2) syscall packs options into a single page-sized
// buffer; a few dozen lowerdirs blow past that limit. The new mount API
// sets each option as a separate fsconfig call, so we can attach hundreds
// of lowers via repeated `fsconfig(SET_STRING, "lowerdir+", path)`.
//
// Usage: mount-overlay --upper UP --work WK --target T --lower L1 [--lower L2 ...]

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/mount.h>

static int sys_fsopen(const char *fsname, unsigned flags) {
    return (int)syscall(SYS_fsopen, fsname, flags);
}
static int sys_fsconfig(int fd, unsigned cmd, const char *key,
                        const void *value, int aux) {
    return (int)syscall(SYS_fsconfig, fd, cmd, key, value, aux);
}
static int sys_fsmount(int fd, unsigned flags, unsigned attr_flags) {
    return (int)syscall(SYS_fsmount, fd, flags, attr_flags);
}
static int sys_move_mount(int from_dfd, const char *from_pathname,
                          int to_dfd, const char *to_pathname,
                          unsigned flags) {
    return (int)syscall(SYS_move_mount, from_dfd, from_pathname,
                        to_dfd, to_pathname, flags);
}

#define MAX_LOWERS 1024
static const char *lowers[MAX_LOWERS];
static int n_lowers;

static void die(const char *what) {
    fprintf(stderr, "mount-overlay: %s: %s\n", what, strerror(errno));
    exit(1);
}

int main(int argc, char **argv) {
    const char *upper = NULL, *work = NULL, *target = NULL;
    static struct option opts[] = {
        {"upper",  required_argument, 0, 'u'},
        {"work",   required_argument, 0, 'w'},
        {"target", required_argument, 0, 't'},
        {"lower",  required_argument, 0, 'l'},
        {0,0,0,0},
    };
    int c;
    while ((c = getopt_long(argc, argv, "u:w:t:l:", opts, NULL)) != -1) {
        switch (c) {
        case 'u': upper = optarg; break;
        case 'w': work = optarg; break;
        case 't': target = optarg; break;
        case 'l':
            if (n_lowers >= MAX_LOWERS) {
                fprintf(stderr, "too many lowers (max %d)\n", MAX_LOWERS);
                return 2;
            }
            lowers[n_lowers++] = optarg;
            break;
        default:
            fprintf(stderr,
                "usage: %s --upper UP --work WK --target T --lower L1 [--lower L2 ...]\n",
                argv[0]);
            return 2;
        }
    }
    if (!upper || !work || !target || n_lowers == 0) {
        fprintf(stderr, "missing required args\n"); return 2;
    }

    int fs = sys_fsopen("overlay", 0);
    if (fs < 0) die("fsopen(overlay)");

    for (int i = 0; i < n_lowers; i++) {
        if (sys_fsconfig(fs, FSCONFIG_SET_STRING, "lowerdir+",
                         lowers[i], 0) < 0) {
            fprintf(stderr, "fsconfig(lowerdir+=%s): %s\n",
                    lowers[i], strerror(errno));
            return 1;
        }
    }
    if (sys_fsconfig(fs, FSCONFIG_SET_STRING, "upperdir", upper, 0) < 0)
        die("fsconfig(upperdir)");
    if (sys_fsconfig(fs, FSCONFIG_SET_STRING, "workdir", work, 0) < 0)
        die("fsconfig(workdir)");
    if (sys_fsconfig(fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0)
        die("fsconfig(CREATE)");

    int mfd = sys_fsmount(fs, 0, 0);
    if (mfd < 0) die("fsmount");

    if (sys_move_mount(mfd, "", AT_FDCWD, target,
                       MOVE_MOUNT_F_EMPTY_PATH) < 0)
        die("move_mount");

    fprintf(stderr, "mount-overlay: %d lowers → %s\n", n_lowers, target);
    close(mfd);
    close(fs);
    return 0;
}
