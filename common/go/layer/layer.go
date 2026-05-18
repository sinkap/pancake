// Package layer turns a staged directory into one verity layer:
//
//	staging/    →  out_img (squashfs) + out_img.with_suffix(".hash") + roothash
//
// We don't activate dm-verity here (that's a runtime concern, handled
// by sandbox.MaterializeCurrent and the initramfs); we just produce
// the image + hash files. dm-verity is filesystem-agnostic — it
// operates on the underlying block device — so squashfs works
// identically to ext4 for the integrity story, with the added benefit
// of zstd compression (typically 30-50% smaller layers).
package layer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"
)

var roothashRe = regexp.MustCompile(`Root hash:\s+([0-9a-f]+)`)

// MakeVerity builds a squashfs image at outImg from the contents of
// staging/, then runs veritysetup format to produce the sidecar
// outImg+".hash". Returns the verity root hash (hex) and the data
// partition size in bytes (for the manifest's data-size field).
//
// No sizing math: mksquashfs writes exactly the bytes it needs. The
// minMiB argument is kept for API compatibility but ignored (the old
// ext4 path inflated to leave overlay slack; squashfs is read-only so
// the inflation was always meaningless for layer images).
//
// If seed != "", deterministic squashfs + veritysetup flags are
// derived from it: SOURCE_DATE_EPOCH + verity salt/UUID. With these
// and identical input files, mksquashfs produces a bit-identical
// image — which is what `pancake serve`'s auto-install path needs so
// the local rebuild's verity roothash matches the orchestrator-pushed
// manifest's claim.
//
// seed == "" preserves the legacy non-deterministic behavior for
// callers that don't care about reproducibility (e.g., one-off
// `pancake build`).
//
// The `label` argument is unused (ext4 supported volume labels;
// squashfs doesn't). Kept for API compatibility.
func MakeVerity(staging, outImg, label string, minMiB int, seed string) (string, int64, error) {
	_ = label // squashfs has no volume label; keep arg for ABI compat
	_ = minMiB

	if err := os.MkdirAll(filepath.Dir(outImg), 0o755); err != nil {
		return "", 0, err
	}
	_ = os.Remove(outImg)
	outHash := strings.TrimSuffix(outImg, filepath.Ext(outImg)) + ".hash"
	_ = os.Remove(outHash)

	// mksquashfs reads everything under staging/, compresses with zstd
	// (best size/speed trade-off for the read-mostly workload), strips
	// ownership and timestamps so the output is bit-deterministic for
	// identical inputs.
	mkArgs := []string{
		"mksquashfs", staging, outImg,
		"-no-progress",
		"-quiet",
		"-noappend",     // overwrite outImg (we removed it but be explicit)
		"-all-root",     // uid/gid -> 0
		"-no-xattrs",    // mirrors old ext4 no_copy_xattrs
		"-comp", "zstd",
		"-Xcompression-level", "9",
	}
	// 2020-01-01T00:00:00Z, pinned because file CONTENT is what verity
	// covers; timestamps just need to match byte-for-byte across host
	// and VM. mksquashfs 4.6+ refuses if both SOURCE_DATE_EPOCH and
	// the -mkfs-time/-all-time flags are set — we use the flags
	// directly and DO NOT set the env to keep that conflict away.
	mkfsTime := "1577836800"
	if seed != "" {
		mkArgs = append(mkArgs,
			"-mkfs-time", mkfsTime,
			"-all-time", mkfsTime,
		)
	}
	if err := runner.Run(runner.Cmd{Argv: mkArgs, Sudo: true}); err != nil {
		return "", 0, err
	}

	// Hand the image back to the invoking user so subsequent ops (TOML
	// writes, repo-dir packaging) don't need sudo.
	uid := strconv.Itoa(syscall.Getuid())
	gid := strconv.Itoa(syscall.Getgid())
	if err := runner.Run(runner.Cmd{
		Argv: []string{"chown", uid + ":" + gid, outImg}, Sudo: true,
	}); err != nil {
		return "", 0, err
	}
	// veritysetup wants the hash file to exist before format.
	if f, err := os.Create(outHash); err != nil {
		return "", 0, err
	} else {
		f.Close()
	}

	// dataSize = bytes of the squashfs blob (the data device verity covers).
	fi, err := os.Stat(outImg)
	if err != nil {
		return "", 0, err
	}
	dataSize := fi.Size()

	verityArgs := []string{"veritysetup", "format"}
	if seed != "" {
		// Deterministic verity tree: UUID + salt derived from the same
		// seed. Default veritysetup picks both at random.
		h := sha256.Sum256([]byte(seed + "\x00verity"))
		verityArgs = append(verityArgs,
			"--uuid="+formatUUID(h[:16]),
			"--salt="+hex.EncodeToString(h[16:32]),
		)
	}
	verityArgs = append(verityArgs, outImg, outHash)
	out, err := runner.Capture(runner.Cmd{Argv: verityArgs})
	if err != nil {
		return "", 0, err
	}
	m := roothashRe.FindStringSubmatch(out)
	if len(m) != 2 {
		return "", 0, fmt.Errorf("veritysetup format produced no root hash:\n%s", out)
	}
	return m[1], dataSize, nil
}

// formatUUID renders 16 bytes in canonical 8-4-4-4-12 hex form.
func formatUUID(b []byte) string {
	if len(b) != 16 {
		// pad/truncate to 16 bytes; defensive
		x := make([]byte, 16)
		copy(x, b)
		b = x
	}
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" +
		s[16:20] + "-" + s[20:32]
}
