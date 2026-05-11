// Package initramfs builds the manifest-driven initramfs used to boot
// pancake-os: an mmdebstrap'd minimal userland (busybox-equivalent + bash +
// cryptsetup-bin + kmod + ext4 tools) plus the host's /lib/modules/<KVER>
// plus the initramfs/init script and the mount-overlay helper.
//
// Port of build-pancake-initramfs.sh.
//
// Output is a gzipped newc cpio that QEMU consumes via -initrd.
package initramfs

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/runner"
)

// Defaults match the shell version. Pulling util-linux + mount + cryptsetup-bin
// + e2fsprogs gives us blkid, mount, veritysetup; udev/kmod give modprobe.
var DefaultPackages = []string{
	"bash", "coreutils", "util-linux", "mount",
	"cryptsetup-bin",
	"kmod", "libzstd1",
	"udev",
	"e2fsprogs",
}

// Opts configures Build. SrcRoot must point at the fs-pancake source tree
// (where initramfs/init and initramfs/mount-overlay.c live). Caller must
// have mmdebstrap, cc, cpio, gzip, depmod available on the host.
type Opts struct {
	OutPath  string   // <foo>.cpio.gz
	KVer     string   // kernel version under /lib/modules/<KVer>
	SrcRoot  string   // path to fs-pancake checkout
	Suite    string   // mmdebstrap suite, default "noble"
	Mirror   string   // default Ubuntu archive
	Packages []string // override DefaultPackages if non-nil
	Stage    string   // override staging dir, default /tmp/pancake-initramfs-stage
	Force    bool     // rebuild stage even if dir exists (mmdebstrap is slow)
}

// Build assembles the initramfs into o.OutPath. Steps mirror the shell
// version one-to-one so the output is byte-equivalent for the same inputs.
func Build(o Opts) error {
	if o.OutPath == "" {
		return fmt.Errorf("initramfs: OutPath required")
	}
	if o.KVer == "" {
		return fmt.Errorf("initramfs: KVer required")
	}
	if o.SrcRoot == "" {
		return fmt.Errorf("initramfs: SrcRoot required (location of " +
			"initramfs/init and initramfs/mount-overlay.c)")
	}
	if o.Suite == "" {
		o.Suite = "noble"
	}
	if o.Mirror == "" {
		o.Mirror = "http://archive.ubuntu.com/ubuntu/"
	}
	if len(o.Packages) == 0 {
		o.Packages = DefaultPackages
	}
	if o.Stage == "" {
		o.Stage = "/tmp/pancake-initramfs-stage"
	}

	modSrc := filepath.Join("/lib/modules", o.KVer)
	if _, err := os.Stat(modSrc); err != nil {
		return fmt.Errorf("initramfs: kernel modules dir not found: %s "+
			"(install matching headers/modules first)", modSrc)
	}
	initSrc := filepath.Join(o.SrcRoot, "initramfs", "init")
	if _, err := os.Stat(initSrc); err != nil {
		return fmt.Errorf("initramfs: %s missing — wrong --src-root?", initSrc)
	}
	moSrc := filepath.Join(o.SrcRoot, "initramfs", "mount-overlay.c")
	if _, err := os.Stat(moSrc); err != nil {
		return fmt.Errorf("initramfs: %s missing — wrong --src-root?", moSrc)
	}

	// 1. mmdebstrap into staging (skip if already present and not forced).
	if o.Force {
		_ = runner.Run(runner.Cmd{
			Argv: []string{"rm", "-rf", o.Stage}, Sudo: true,
		})
	}
	if _, err := os.Stat(o.Stage); err != nil {
		fmt.Fprintf(os.Stderr, "[initramfs] mmdebstrap → %s\n", o.Stage)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"mmdebstrap", "--variant=essential",
				"--components=main,universe",
				"--include=" + strings.Join(o.Packages, ","),
				o.Suite, o.Stage, o.Mirror},
			Sudo: true,
		}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(os.Stderr,
			"[initramfs] reusing existing stage %s (set Force=true to rebuild)\n",
			o.Stage)
	}

	// 2. /init.
	fmt.Fprintln(os.Stderr, "[initramfs] installing /init")
	if err := runner.Run(runner.Cmd{
		Argv: []string{"install", "-m", "0755", initSrc,
			filepath.Join(o.Stage, "init")},
		Sudo: true,
	}); err != nil {
		return err
	}

	// 3. /sbin/mount-overlay (compile from C).
	fmt.Fprintln(os.Stderr, "[initramfs] compiling + installing /sbin/mount-overlay")
	tmpBin := "/tmp/_pancake-initramfs-mount-overlay"
	if err := runner.Run(runner.Cmd{
		Argv: []string{"cc", "-O2", "-Wall", "-Wextra", "-static",
			"-o", tmpBin, moSrc},
	}); err != nil {
		return err
	}
	defer os.Remove(tmpBin)
	if err := runner.Run(runner.Cmd{
		Argv: []string{"install", "-m", "0755", tmpBin,
			filepath.Join(o.Stage, "sbin", "mount-overlay")},
		Sudo: true,
	}); err != nil {
		return err
	}

	// 4. /lib/modules/<KVer> (clean copy from host).
	fmt.Fprintf(os.Stderr,
		"[initramfs] copying %s → initramfs\n", modSrc)
	dstMod := filepath.Join(o.Stage, "lib/modules", o.KVer)
	_ = runner.Run(runner.Cmd{
		Argv: []string{"rm", "-rf", dstMod}, Sudo: true,
	})
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mkdir", "-p", dstMod}, Sudo: true,
	}); err != nil {
		return err
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"cp", "-a", filepath.Join(modSrc, "kernel"), dstMod + "/"},
		Sudo: true,
	}); err != nil {
		return err
	}
	for _, f := range []string{"modules.builtin", "modules.builtin.modinfo",
		"modules.order"} {
		src := filepath.Join(modSrc, f)
		if _, err := os.Stat(src); err == nil {
			_ = runner.Run(runner.Cmd{
				Argv: []string{"cp", src, dstMod + "/"}, Sudo: true,
			})
		}
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"depmod", "-b", o.Stage, o.KVer}, Sudo: true,
	}); err != nil {
		return err
	}

	// 5. cpio.gz the staging dir.
	fmt.Fprintf(os.Stderr, "[initramfs] cpio.gz → %s\n", o.OutPath)
	if err := os.MkdirAll(filepath.Dir(o.OutPath), 0o755); err != nil {
		return err
	}
	if err := writeCpioGz(o.Stage, o.OutPath); err != nil {
		return err
	}
	st, _ := os.Stat(o.OutPath)
	fmt.Fprintf(os.Stderr, "[initramfs] wrote %s (%s)\n",
		o.OutPath, humanSize(st.Size()))
	return nil
}

// writeCpioGz pipes `find <stage> | cpio -o newc | gzip -1` to outPath.
// `find` and `cpio` need sudo because the staging tree is root-owned (it
// contains setuid binaries, /dev nodes, etc).
func writeCpioGz(stage, out string) error {
	outF, err := os.Create(out)
	if err != nil {
		return err
	}
	defer outF.Close()
	gz, _ := gzip.NewWriterLevel(outF, gzip.BestSpeed)
	defer gz.Close()

	sudoPfx := []string{}
	if syscall.Getuid() != 0 {
		sudoPfx = []string{"sudo"}
	}

	// find . -print0 | cpio --null --create --format=newc --quiet
	findArgv := append(sudoPfx, "find", ".", "-print0")
	cpioArgv := append(sudoPfx, "cpio", "--null", "--create",
		"--format=newc", "--quiet")
	fmt.Fprintf(os.Stderr,
		"  ▸ %s | %s | gzip -1 > %s\n",
		strings.Join(findArgv, " "), strings.Join(cpioArgv, " "), out)

	findCmd := exec.Command(findArgv[0], findArgv[1:]...)
	findCmd.Dir = stage
	findCmd.Stderr = os.Stderr
	findOut, err := findCmd.StdoutPipe()
	if err != nil {
		return err
	}

	cpioCmd := exec.Command(cpioArgv[0], cpioArgv[1:]...)
	cpioCmd.Dir = stage
	cpioCmd.Stdin = findOut
	cpioCmd.Stderr = os.Stderr
	cpioOut, err := cpioCmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := findCmd.Start(); err != nil {
		return err
	}
	if err := cpioCmd.Start(); err != nil {
		_ = findCmd.Wait()
		return err
	}
	if _, err := io.Copy(gz, cpioOut); err != nil {
		return err
	}
	if err := findCmd.Wait(); err != nil {
		return fmt.Errorf("find: %w", err)
	}
	if err := cpioCmd.Wait(); err != nil {
		return fmt.Errorf("cpio: %w", err)
	}
	return nil
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%dM", n/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%dK", n/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}
