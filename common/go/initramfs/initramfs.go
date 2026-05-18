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

	"github.com/sinkap/pancake/common/go/runner"
)

// Defaults match the shell version. Pulling util-linux + mount + cryptsetup-bin
// + e2fsprogs gives us blkid, mount, veritysetup; udev/kmod give modprobe.
// openssl is for `openssl dgst -verify` against the manifest signature
// when a baked-in pubkey is present. tpm2-tools is for the rollback
// counter check (tpm2_nvdefine, tpm2_nvread, tpm2_nvwrite); soft-fails
// gracefully if no TPM is present.
var DefaultPackages = []string{
	"bash", "coreutils", "util-linux", "mount",
	"cryptsetup-bin",
	"kmod", "libzstd1",
	"udev",
	"e2fsprogs",
	"openssl",
	"tpm2-tools",
	"xxd", // for hex<->binary conversion in the TPM-counter check
}

// Opts configures Build. Most fields fall back to legacy
// host-relative defaults when empty, which keeps the deprecated
// client-side bootstrap path working until Phase 6 deletes it. A
// server-side caller supplies all the new explicit-source fields.
//
// Caller must have mmdebstrap, cpio, gzip, depmod available; cc is
// only needed when MountOverlayBin is empty (legacy compile path).
type Opts struct {
	OutPath  string   // <foo>.cpio.gz (required)
	KVer     string   // kernel version (used as the /lib/modules/<KVer> dir name)
	Suite    string   // mmdebstrap suite, default "noble"
	Mirror   string   // default Ubuntu archive
	Packages []string // override DefaultPackages if non-nil
	Stage    string   // override staging dir, default /tmp/pancake-initramfs-stage
	Force    bool     // rebuild stage even if dir exists (mmdebstrap is slow)

	// SrcRoot (legacy / client path): when non-empty, the builder
	// reads init from <SrcRoot>/tools/initramfs/init and compiles
	// mount-overlay.c from <SrcRoot>/tools/initramfs/mount-overlay.c, and
	// reads modules from /lib/modules/<KVer>. Phase 6 deletes this
	// path; new callers should set the explicit fields below.
	SrcRoot string

	// ModulesDir (preferred): directory containing the kernel
	// modules tree to bake in. Should already have the
	// `lib/modules/<KVer>` layout — Build copies the entire
	// `<ModulesDir>/lib/modules/<KVer>` subtree into the staging
	// area. When empty, Build falls back to /lib/modules/<KVer> on
	// the host.
	ModulesDir string

	// InitSrcPath (preferred): path to the `/init` shell script
	// that becomes the initramfs entrypoint. Empty falls back to
	// SrcRoot/tools/initramfs/init.
	InitSrcPath string

	// MountOverlayBin (preferred): path to a pre-compiled
	// mount-overlay binary. Empty falls back to compiling
	// SrcRoot/tools/initramfs/mount-overlay.c. Saves having to ship
	// gcc + libc-dev to the build server.
	MountOverlayBin string

	// PubKeyPath: when set, copy this PEM-encoded public key into
	// the initramfs at /etc/pancake/manifest.pubkey. /init uses it
	// to verify the manifest signature before mounting the overlay.
	// Mutually exclusive with PubKeyBytes.
	PubKeyPath string

	// PubKeyBytes (preferred): same effect as PubKeyPath but the
	// caller supplies the bytes directly. Server-side callers use
	// this to avoid spilling the pubkey to disk before staging.
	PubKeyBytes []byte
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

	// Modules: explicit ModulesDir wins; otherwise the host's
	// /lib/modules (legacy client path).
	modSrc := filepath.Join("/lib/modules", o.KVer)
	if o.ModulesDir != "" {
		modSrc = filepath.Join(o.ModulesDir, "lib/modules", o.KVer)
	}
	if _, err := os.Stat(modSrc); err != nil {
		return fmt.Errorf("initramfs: kernel modules dir not found: %s "+
			"(set Opts.ModulesDir to a kit-style tree, or install "+
			"matching modules under /lib/modules on the host)", modSrc)
	}

	// Init script source: explicit InitSrcPath wins; otherwise
	// SrcRoot/tools/initramfs/init.
	initSrc := o.InitSrcPath
	if initSrc == "" {
		if o.SrcRoot == "" {
			return fmt.Errorf("initramfs: InitSrcPath or SrcRoot required " +
				"(need a path to the /init shell script)")
		}
		initSrc = filepath.Join(o.SrcRoot, "tools", "initramfs", "init")
	}
	if _, err := os.Stat(initSrc); err != nil {
		return fmt.Errorf("initramfs: %s missing", initSrc)
	}

	// mount-overlay binary: prefer pre-compiled MountOverlayBin
	// over compiling from C source.
	moSrc := ""
	if o.MountOverlayBin == "" {
		if o.SrcRoot == "" {
			return fmt.Errorf("initramfs: MountOverlayBin or SrcRoot " +
				"required (need either a pre-compiled mount-overlay " +
				"or its C source)")
		}
		moSrc = filepath.Join(o.SrcRoot, "tools", "initramfs", "mount-overlay.c")
		if _, err := os.Stat(moSrc); err != nil {
			return fmt.Errorf("initramfs: %s missing", moSrc)
		}
	} else {
		if _, err := os.Stat(o.MountOverlayBin); err != nil {
			return fmt.Errorf("initramfs: MountOverlayBin %s: %w",
				o.MountOverlayBin, err)
		}
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

	// 3. /sbin/mount-overlay: prefer the pre-compiled binary path.
	binPath := o.MountOverlayBin
	if binPath == "" {
		fmt.Fprintln(os.Stderr,
			"[initramfs] compiling + installing /sbin/mount-overlay")
		binPath = "/tmp/_pancake-initramfs-mount-overlay"
		if err := runner.Run(runner.Cmd{
			Argv: []string{"cc", "-O2", "-Wall", "-Wextra", "-static",
				"-o", binPath, moSrc},
		}); err != nil {
			return err
		}
		defer os.Remove(binPath)
	} else {
		fmt.Fprintf(os.Stderr,
			"[initramfs] installing pre-compiled /sbin/mount-overlay (%s)\n",
			binPath)
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"install", "-m", "0755", binPath,
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

	// 4b. Manifest pubkey for /init to verify the kit's manifest signature
	// before the overlay is mounted. If absent, /init will skip verification
	// (and warn) — explicit policy lives in initramfs/init.
	pubkeySrc := o.PubKeyPath
	if pubkeySrc == "" && len(o.PubKeyBytes) > 0 {
		// Spill bytes to a tmp so the existing install(1) shell-out
		// path works without special-casing.
		f, err := os.CreateTemp("", "pancake-initramfs-pubkey-*.pem")
		if err != nil {
			return err
		}
		if _, err := f.Write(o.PubKeyBytes); err != nil {
			f.Close()
			os.Remove(f.Name())
			return err
		}
		f.Close()
		pubkeySrc = f.Name()
		defer os.Remove(pubkeySrc)
	}
	if pubkeySrc != "" {
		fmt.Fprintf(os.Stderr,
			"[initramfs] installing /etc/pancake/manifest.pubkey from %s\n",
			pubkeySrc)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"install", "-d", "-m", "0755",
				filepath.Join(o.Stage, "etc/pancake")},
			Sudo: true,
		}); err != nil {
			return err
		}
		if err := runner.Run(runner.Cmd{
			Argv: []string{"install", "-m", "0644", pubkeySrc,
				filepath.Join(o.Stage, "etc/pancake/manifest.pubkey")},
			Sudo: true,
		}); err != nil {
			return err
		}
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
