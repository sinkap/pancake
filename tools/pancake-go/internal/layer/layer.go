// Package layer turns a staged directory into one verity layer:
//
//	staging/    →  out_img (ext4) + out_img.with_suffix(".hash") + roothash
//
// Mirrors pancake_lib.make_verity_image. We don't activate dm-verity here
// (that's a runtime concern, handled by sandbox.MaterializeCurrent and the
// initramfs); we just produce the image+hash files.
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

// MakeVerity builds an ext4 image at outImg containing staging/, then runs
// veritysetup format to produce the sidecar outImg+".hash" file. Returns
// the verity root hash (hex) and the data partition size in bytes (for
// the manifest's data-size field).
//
// Sizing: take `du -sk staging`, scale up 1.4x to leave overlay slack,
// add 32MB for ext4 metadata, round to 4K. Floor at minMiB if non-zero.
//
// If seed != "", deterministic mkfs.ext4 + veritysetup flags are derived
// from it: the ext4 filesystem UUID and directory hash seed, and the
// verity hash-tree salt + UUID. Callers should pass the layer slug
// (name + slugified-version) so two machines building the same package
// produce identical bytes → identical verity roothash. This is the
// foundation for "VM reconstructs missing layers from apt and the
// orchestrator-pushed manifest still validates".
//
// seed == "" preserves the legacy non-deterministic behavior for callers
// that don't care about reproducibility (e.g., one-off `pancake build`).
func MakeVerity(staging, outImg, label string, minMiB int, seed string) (string, int64, error) {
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
	mkfsArgs := []string{"mkfs.ext4", "-q", "-F", "-L", label,
		"-d", staging}
	eOpts := "no_copy_xattrs"
	if seed != "" {
		// Deterministic UUID + dir-hash seed, both derived from the
		// caller-supplied seed (typically the layer slug). With these
		// flags + identical input files, mkfs.ext4 produces a bytewise
		// identical image — which is what `pancake serve`'s auto-install
		// path needs so the local rebuild's verity roothash matches the
		// orchestrator-pushed manifest's claim.
		h := sha256.Sum256([]byte(seed))
		uuid := formatUUID(h[:16])
		hashSeed := formatUUID(h[16:32])
		mkfsArgs = append(mkfsArgs, "-U", uuid)
		eOpts += ",hash_seed=" + hashSeed
	}
	mkfsArgs = append(mkfsArgs, "-E", eOpts, outImg)
	mkfsCmd := runner.Cmd{Argv: mkfsArgs, Sudo: true}
	if seed != "" {
		// SOURCE_DATE_EPOCH is the cross-tool reproducibility convention
		// (https://reproducible-builds.org/docs/source-date-epoch/).
		// e2fsprogs honors it for all inode timestamps, which is the
		// last common source of mkfs.ext4 non-determinism beyond UUID
		// and hash_seed. Pin to 1577836800 (2020-01-01T00:00:00Z) — a
		// fixed value works because file CONTENT is what dm-verity
		// covers; the timestamps are just metadata that needs to match
		// byte-for-byte across host and VM.
		mkfsCmd.Env = []string{"SOURCE_DATE_EPOCH=1577836800"}
	}
	if err := runner.Run(mkfsCmd); err != nil {
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
