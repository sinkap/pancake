// Package layer turns a staged directory into one verity layer:
//
//	staging/    →  out_img (ext4) + out_img.with_suffix(".hash") + roothash
//
// Mirrors pancake_lib.make_verity_image. We don't activate dm-verity here
// (that's a runtime concern, handled by sandbox.MaterializeCurrent and the
// initramfs); we just produce the image+hash files.
package layer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/runner"
)

var roothashRe = regexp.MustCompile(`Root hash:\s+([0-9a-f]+)`)

// MakeVerity builds an ext4 image at outImg containing staging/, then runs
// veritysetup format to produce the sidecar outImg+".hash" file. Returns
// the verity root hash (hex) and the data partition size in bytes (for
// the manifest's data-size field).
//
// Sizing: take `du -sk staging`, scale up 1.4x to leave overlay slack,
// add 32MB for ext4 metadata, round to 4K. Floor at minMiB if non-zero.
func MakeVerity(staging, outImg, label string, minMiB int) (string, int64, error) {
	duOut, err := runner.Capture(runner.Cmd{
		Argv: []string{"du", "-sk", staging}, Sudo: true,
	})
	if err != nil {
		return "", 0, err
	}
	duKB, err := strconv.Atoi(strings.Fields(strings.TrimSpace(duOut))[0])
	if err != nil {
		return "", 0, fmt.Errorf("parse du output: %w", err)
	}
	dataKB := ((duKB*14/10 + 32*1024) + 3) / 4 * 4
	if minMiB > 0 && dataKB < minMiB*1024 {
		dataKB = minMiB * 1024
	}
	dataSize := int64(dataKB) * 1024

	if err := os.MkdirAll(filepath.Dir(outImg), 0o755); err != nil {
		return "", 0, err
	}
	_ = os.Remove(outImg)
	outHash := strings.TrimSuffix(outImg, filepath.Ext(outImg)) + ".hash"
	_ = os.Remove(outHash)

	if err := runner.Run(runner.Cmd{
		Argv: []string{"truncate", "-s", fmt.Sprintf("%dK", dataKB), outImg},
	}); err != nil {
		return "", 0, err
	}
	// labels are limited to 16 chars on ext4
	if len(label) > 16 {
		label = label[:16]
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mkfs.ext4", "-q", "-F", "-L", label,
			"-d", staging, "-E", "no_copy_xattrs", outImg},
		Sudo: true,
	}); err != nil {
		return "", 0, err
	}
	// hand the image back to the invoking user so subsequent ops (TOML
	// writes, repo-dir packaging) don't need sudo.
	uid := strconv.Itoa(syscall.Getuid())
	gid := strconv.Itoa(syscall.Getgid())
	if err := runner.Run(runner.Cmd{
		Argv: []string{"chown", uid + ":" + gid, outImg}, Sudo: true,
	}); err != nil {
		return "", 0, err
	}
	if f, err := os.Create(outHash); err != nil {
		return "", 0, err
	} else {
		f.Close()
	}

	out, err := runner.Capture(runner.Cmd{
		Argv: []string{"veritysetup", "format", outImg, outHash},
	})
	if err != nil {
		return "", 0, err
	}
	m := roothashRe.FindStringSubmatch(out)
	if len(m) != 2 {
		return "", 0, fmt.Errorf("veritysetup format produced no root hash:\n%s", out)
	}
	return m[1], dataSize, nil
}
