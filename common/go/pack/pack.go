// Package pack wraps a kit dir into a single ext4 disk image suitable for
// attaching to QEMU as the pancake state partition. Port of pack-kit-disk.sh.
//
// Image label is "PANCAKE_STATE" so the initramfs can find it via blkid;
// callers should also wire the disk's serial in QEMU and pass
// `pancake.state=SERIAL=<serial>` on the kernel command line.
package pack

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"
)

// Disk turns kitDir into a single ext4 image at outImg.
//
// Sizing: kit `du -sk` * 1.15 + 64 MiB headroom, rounded to 4 KiB. Same
// formula the shell version used (the 15% slack covers ext4 metadata + a
// little room for in-VM kit growth from `pancake install`; the 64 MiB
// headroom is dominated by ext4 superblock + journal allocations).
func Disk(kitDir, outImg string) error {
	if fi, err := os.Stat(kitDir); err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("pack: not a directory: %s", kitDir)
	}

	duOut, err := runner.Capture(runner.Cmd{
		Argv: []string{"du", "-sk", kitDir}, Sudo: true,
	})
	if err != nil {
		return err
	}
	sizeKB, err := strconv.Atoi(strings.Fields(strings.TrimSpace(duOut))[0])
	if err != nil {
		return fmt.Errorf("pack: parse du output: %w", err)
	}
	imgKB := (sizeKB*115/100 + 64*1024 + 3) / 4 * 4

	fmt.Fprintf(os.Stderr, "[pack] %d KiB ext4 image at %s\n", imgKB, outImg)

	if err := os.MkdirAll(filepath.Dir(outImg), 0o755); err != nil {
		return err
	}
	_ = os.Remove(outImg)
	if err := runner.Run(runner.Cmd{
		Argv: []string{"truncate", "-s", fmt.Sprintf("%dK", imgKB), outImg},
	}); err != nil {
		return err
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mkfs.ext4", "-q", "-F", "-L", "PANCAKE_STATE",
			"-d", kitDir, "-E", "no_copy_xattrs", outImg},
		Sudo: true,
	}); err != nil {
		return err
	}
	uid := strconv.Itoa(syscall.Getuid())
	gid := strconv.Itoa(syscall.Getgid())
	if err := runner.Run(runner.Cmd{
		Argv: []string{"chown", uid + ":" + gid, outImg}, Sudo: true,
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr,
		"[pack] done. attach with:\n"+
			"  -drive file=%s,format=raw,if=none,id=pstate\n"+
			"  -device virtio-blk,drive=pstate,serial=pancake-state\n"+
			"  -append \"... pancake.state=SERIAL=pancake-state ...\"\n",
		outImg)
	return nil
}
