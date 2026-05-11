// `pancake swap [<id>]`: live atomic rootfs replacement on a running
// pancake-os via pivot_root(2). The target generation's overlay is
// constructed at /pancake-newroot, the runtime mounts (/proc /sys /dev
// /run /lowers /var/lib/pancake) are brought along, the kit's `current`
// symlink is flipped, then /sbin/pivot-root invokes pivot_root(2) which
// calls chroot_fs_refs() in-kernel to rebase EVERY task's fs.root.
//
// Requires Brauner's nullfs / MOVE_MOUNT_BENEATH series (lands in 7.2);
// without it pivot_root cannot operate on the running rootfs.
//
// Refuses to run unless / is overlayfs and /lowers exists, i.e. unless we
// look like a booted pancake-os. This is also the second line of defense
// against accidentally running it on the host.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/runner"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/sandbox"
)

func cmdSwap(k *kit.Kit, args []string) int {
	fs := flag.NewFlagSet("swap", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !sandbox.RunningInPancakeOS() {
		fmt.Fprintln(os.Stderr,
			"pancake swap: must be run from inside a booted pancake-os "+
				"(no overlay rootfs detected)")
		return 1
	}

	// Target id: explicit arg, otherwise latest.
	var targetID int
	if fs.NArg() == 1 {
		n, err := strconv.Atoi(fs.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "pancake swap: bad id: %v\n", err)
			return 2
		}
		targetID = n
	} else {
		latest, err := k.LatestGenerationID()
		if err != nil {
			return die(err)
		}
		targetID = latest
	}

	targetGen := filepath.Join(k.Generations(), strconv.Itoa(targetID))
	if _, err := os.Stat(targetGen); err != nil {
		fmt.Fprintf(os.Stderr, "pancake swap: no such generation: %d\n", targetID)
		return 1
	}
	lowersFile := filepath.Join(targetGen, "lowers")
	if _, err := os.Stat(lowersFile); err != nil {
		fmt.Fprintf(os.Stderr, "pancake swap: %s missing\n", lowersFile)
		return 1
	}
	curID, err := k.CurrentID()
	if err != nil {
		return die(err)
	}

	targetLowers, err := kit.ReadLowers(lowersFile)
	if err != nil {
		return die(err)
	}
	curLowers, err := kit.ReadLowers(filepath.Join(
		k.Generations(), strconv.Itoa(curID), "lowers"))
	if err != nil {
		return die(err)
	}
	// "current" tracks what's set for next boot, NOT what's running. The
	// truth about what's running comes from /proc/mounts on the active
	// overlay. If the running set already matches the target, we're done.
	runningSlugs, err := runningOverlaySlugs()
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"[swap] warning: could not detect running overlay (%v); proceeding\n", err)
		runningSlugs = nil
	}
	targetSlugs := map[string]bool{}
	for _, L := range targetLowers {
		targetSlugs[L.Slug] = true
	}
	if runningSlugs != nil && slugSetsEqual(runningSlugs, targetSlugs) {
		fmt.Fprintf(os.Stderr,
			"[swap] running overlay already matches generation %d\n", targetID)
		// still flip the symlink in case offline activate didn't
		_ = k.SetCurrent(targetID)
		return 0
	}
	curSlugs := map[string]bool{}
	if runningSlugs != nil {
		// Use the actual running set (more accurate than current/lowers,
		// which may differ if pancake activate was used offline).
		curSlugs = runningSlugs
	} else {
		for _, L := range curLowers {
			curSlugs[L.Slug] = true
		}
	}

	newLayers := 0
	for s := range targetSlugs {
		if !curSlugs[s] {
			newLayers++
		}
	}
	retiredLayers := 0
	for s := range curSlugs {
		if !targetSlugs[s] {
			retiredLayers++
		}
	}
	fmt.Fprintf(os.Stderr,
		"[swap] preparing %d layers (%d new, %d to retire)\n",
		len(targetLowers), newLayers, retiredLayers)

	// 1. Open + RO-mount layers we don't already have under /lowers.
	for _, L := range targetLowers {
		if curSlugs[L.Slug] {
			continue
		}
		img := filepath.Join(k.Dir, L.ImageRel)
		hashf := filepath.Join(k.Dir, L.HashRel)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"veritysetup", "open", img, "v_" + L.Slug,
				hashf, L.Roothash},
			Sudo: true,
		}); err != nil {
			return die(err)
		}
		mp := filepath.Join("/lowers", L.Slug)
		if err := os.MkdirAll(mp, 0o755); err != nil {
			return die(err)
		}
		if err := runner.Run(runner.Cmd{
			Argv: []string{"mount", "-o", "ro",
				"/dev/mapper/v_" + L.Slug, mp},
			Sudo: true,
		}); err != nil {
			return die(err)
		}
	}

	// 2. Build new overlay at /pancake-newroot, with its own tmpfs upper.
	newroot := "/pancake-newroot"
	if err := os.MkdirAll(newroot, 0o755); err != nil {
		return die(err)
	}
	newRW := "/run/pancake-newrw"
	if err := os.MkdirAll(newRW, 0o755); err != nil {
		return die(err)
	}
	if !isMounted(newRW) {
		if err := runner.Run(runner.Cmd{
			Argv: []string{"mount", "-t", "tmpfs", "-o", "mode=755",
				"tmpfs", newRW},
			Sudo: true,
		}); err != nil {
			return die(err)
		}
	}
	upper := filepath.Join(newRW, "upper")
	work := filepath.Join(newRW, "work")
	for _, d := range []string{upper, work} {
		_ = os.MkdirAll(d, 0o755)
	}

	mountOverlay, err := sandbox.FindHelper("mount-overlay",
		repoRoot(), "initramfs")
	if err != nil {
		return die(err)
	}
	args2 := []string{"--upper", upper, "--work", work, "--target", newroot}
	for _, L := range targetLowers {
		args2 = append(args2, "--lower", "/lowers/"+L.Slug)
	}
	if err := runner.Run(runner.Cmd{
		Argv: append([]string{mountOverlay}, args2...), Sudo: true,
	}); err != nil {
		return die(err)
	}

	// 3. Bring kernel/runtime mounts into the new root. rbind for trees with
	// submounts; bind for single-mount paths.
	for _, sub := range []string{"proc", "sys", "dev", "run"} {
		_ = os.MkdirAll(filepath.Join(newroot, sub), 0o755)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"mount", "--rbind", "/" + sub,
				filepath.Join(newroot, sub)},
			Sudo: true,
		}); err != nil {
			return die(err)
		}
	}
	_ = os.MkdirAll(filepath.Join(newroot, "var/lib/pancake"), 0o755)
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mount", "--bind", "/var/lib/pancake",
			filepath.Join(newroot, "var/lib/pancake")},
		Sudo: true,
	}); err != nil {
		return die(err)
	}
	_ = os.MkdirAll(filepath.Join(newroot, "lowers"), 0o755)
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mount", "--rbind", "/lowers",
			filepath.Join(newroot, "lowers")},
		Sudo: true,
	}); err != nil {
		return die(err)
	}

	// 4. Atomically flip current → target (rename of a sibling symlink, so
	// if pivot fails the symlink is consistent for next boot).
	if err := k.SetCurrent(targetID); err != nil {
		return die(err)
	}
	fmt.Fprintf(os.Stderr,
		"[swap] current → generations/%d (committed)\n", targetID)

	// 5. pivot_root prerequisites: neither old nor new root may be MS_SHARED.
	// systemd marks / as shared at boot; clear that recursively.
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mount", "--make-rprivate", "/"}, Sudo: true,
	}); err != nil {
		return die(err)
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mount", "--make-rprivate", newroot}, Sudo: true,
	}); err != nil {
		return die(err)
	}

	// 6. The pivot itself. chdir(/) so cwd doesn't anchor old-root mounts.
	_ = os.Chdir("/")
	pivotRoot, err := sandbox.FindHelper("pivot-root", repoRoot(), ".")
	if err != nil {
		return die(err)
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{pivotRoot, newroot}, Sudo: true,
	}); err != nil {
		return die(err)
	}

	// 7. Restore / as shared so systemd's mount-propagation expectations hold.
	_ = runner.RunOK(runner.Cmd{
		Argv: []string{"mount", "--make-rshared", "/"}, Sudo: true,
	})

	// 8. Close layers no longer referenced (best-effort; udev triggers can
	// delay device close).
	for _, L := range curLowers {
		if targetSlugs[L.Slug] {
			continue
		}
		_ = runner.RunOK(runner.Cmd{
			Argv: []string{"umount", "-l", "/lowers/" + L.Slug}, Sudo: true,
		})
		_ = runner.RunOK(runner.Cmd{
			Argv: []string{"veritysetup", "close", "v_" + L.Slug}, Sudo: true,
		})
	}

	fmt.Fprintf(os.Stderr,
		"[swap] live swap complete — running generation %d\n", targetID)
	return 0
}

func isMounted(p string) bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == p {
			return true
		}
	}
	return false
}

// runningOverlaySlugs returns the set of layer slugs the currently-mounted
// rootfs overlay is composed of, by parsing /proc/mounts. The overlay's
// mount-options string contains "lowerdir+=/lowers/<slug>" entries (one per
// layer, in fsconfig insertion order). Used by cmd_swap to know whether
// "current" symlink and the live system actually agree.
func runningOverlaySlugs() (map[string]bool, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, err
	}
	var optsLine string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[1] == "/" && f[2] == "overlay" {
			optsLine = f[3]
			break
		}
	}
	if optsLine == "" {
		return nil, fmt.Errorf("no overlay mount at /")
	}
	out := map[string]bool{}
	const prefix = "lowerdir+=/lowers/"
	for _, opt := range strings.Split(optsLine, ",") {
		if strings.HasPrefix(opt, prefix) {
			out[strings.TrimPrefix(opt, prefix)] = true
		}
	}
	return out, nil
}

func slugSetsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
