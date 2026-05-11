// `pancake bootstrap`: build a complete pancake-os kit from a Debian
// package list, optionally also packing the disk image and building the
// initramfs in one go.
//
// Process:
//
//  1. mmdebstrap → _sandbox/ with all packages installed.
//  2. Customize sandbox: hostname, ssh host keys, authorized_keys, debug +
//     networkd units, sshd_config; bake the pancake binary (this same
//     executable) + the C helpers (mount-overlay, pivot-root) + the
//     systemd remount unit.
//  3. For each installed package: stage files → mkfs.ext4 + verity format
//     → manifest.
//  4. Orphans (postinst side effects not owned by any package) →
//     pancake-state layer.
//  5. Topo-sort by Depends, write generations/1/{manifest.toml,lowers},
//     point current → generations/1.
//  6. With --image PATH: pack the kit into one ext4 disk image at PATH.
//  7. With --initramfs PATH: build the manifest-driven initramfs against
//     /lib/modules/<--kver> and write to PATH.
//
// Pure file ops + mmdebstrap + mkfs/cpio. No live overlay-of-N-layers
// stress on the host kernel. Safe to run on the build machine.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/deb"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/initramfs"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/layer"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/pack"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/runner"
)

// SystemBaseline is what mmdebstrap minbase doesn't pull but pancake-os
// needs. Adjust here, not at the call site.
//
// Notably absent vs the Python tooling: python3 (we ship one Go static
// binary instead of python + libpython + sqlite + readline + ffi + ...).
var SystemBaseline = []string{
	"init", "systemd", "systemd-sysv", "libpam-systemd",
	"udev",
	"dbus",
	"iproute2", "iputils-ping",
	"ca-certificates", "netbase",
	"kmod",
	"cryptsetup-bin", "dmsetup",
	"openssh-client",
	"less", "procps",
	"apt", // pancake install needs apt inside the materialized chroot
}

// cmdBootstrap is the `pancake bootstrap` subcommand.
func cmdBootstrap(_ *kit.Kit, args []string) int {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	suite := fs.String("suite", "noble", "Debian/Ubuntu suite")
	mirror := fs.String("mirror",
		"http://archive.ubuntu.com/ubuntu/", "apt mirror URL")
	pkgs := fs.String("packages", "",
		"comma-separated extra packages on top of the system baseline")
	out := fs.String("output", "", "kit output directory (required)")
	hostname := fs.String("hostname", "pancake", "/etc/hostname")
	keepSandbox := fs.Bool("keep-sandbox", false,
		"don't delete _sandbox after building")
	sshHostKeys := fs.String("ssh-host-keys", "",
		"dir with ssh_host_*_key files (else generate fresh)")
	sshAuthKeys := fs.String("ssh-authorized-keys", "",
		"file installed at /root/.ssh/authorized_keys")
	pancakeBin := fs.String("pancake-bin", "",
		"path to the pancake binary to bake (default: this executable)")
	srcRoot := fs.String("src-root", "",
		"path to fs-pancake source tree (for mount-overlay.c, pivot-root.c)")
	image := fs.String("image", "./pancake-state.img",
		"pack the kit into an ext4 disk image at this path; empty to skip")
	initramfsPath := fs.String("initramfs", "./pancake-initramfs.cpio.gz",
		"build the manifest-driven initramfs at this path; empty to skip")
	kernel := fs.String("kernel", currentKVer(),
		"kernel VERSION under /lib/modules/<VERSION> whose modules get baked "+
			"into --initramfs (default: uname -r). The kernel BINARY "+
			"(bzImage) is QEMU's -kernel arg at boot, not handled here.")

	// bootstrap has no positional args; every flag carries a value, so the
	// splitFlagsAndPositionals helper would incorrectly demote those values
	// to "positionals". Direct Parse handles "--foo VAL" cleanly.
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" || *pkgs == "" {
		fmt.Fprintln(os.Stderr,
			"usage: pancake bootstrap --packages a,b,c --output DIR [flags]")
		return 2
	}

	if err := bootstrap(bootstrapArgs{
		Suite:           *suite,
		Mirror:          *mirror,
		Packages:        splitCSV(*pkgs),
		Output:          *out,
		Hostname:        *hostname,
		KeepSandbox:     *keepSandbox,
		SSHHostKeysDir:  *sshHostKeys,
		SSHAuthKeysFile: *sshAuthKeys,
		PancakeBin:      *pancakeBin,
		SrcRoot:         *srcRoot,
		ImagePath:       *image,
		InitramfsPath:   *initramfsPath,
		Kernel:          *kernel,
	}); err != nil {
		return die(err)
	}
	return 0
}

// currentKVer returns uname -r for the running host, used as the default
// for --kver when --initramfs is set. Caller can override.
func currentKVer() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

type bootstrapArgs struct {
	Suite, Mirror, Output, Hostname string
	Packages                        []string
	KeepSandbox                     bool
	SSHHostKeysDir, SSHAuthKeysFile string
	PancakeBin, SrcRoot             string
	ImagePath                       string
	InitramfsPath                   string
	// Kernel is a VERSION string like "7.0.0-g9f5b3ffc3f1d" — the suffix
	// of /lib/modules/<Kernel> on the build host. We bake those modules
	// into the initramfs. The kernel BINARY (bzImage) is QEMU's -kernel
	// arg at boot, not handled by pancake bootstrap.
	Kernel string
}

func bootstrap(a bootstrapArgs) error {
	if err := os.MkdirAll(a.Output, 0o755); err != nil {
		return err
	}
	repo := filepath.Join(a.Output, "repo")
	gen1 := filepath.Join(a.Output, "generations", "1")
	sandboxDir := filepath.Join(a.Output, "_sandbox")
	for _, d := range []string{repo, gen1} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	pkgList := dedup(append(append([]string{}, SystemBaseline...), a.Packages...))

	fmt.Fprintf(os.Stderr, "\n[bootstrap] mmdebstrap → %s\n", sandboxDir)
	if err := mmdebstrap(a.Suite, a.Mirror, pkgList, sandboxDir); err != nil {
		return err
	}

	if err := customizeSandbox(sandboxDir, a); err != nil {
		return err
	}

	pkgs, err := deb.InstalledPackages(sandboxDir)
	if err != nil {
		return err
	}
	pkgs = deb.SortPackages(pkgs)
	fmt.Fprintf(os.Stderr, "\n[bootstrap] %d packages installed in sandbox\n",
		len(pkgs))

	tmp, err := os.MkdirTemp("", "pancake-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	type laidOut struct{ Name, Version, Arch, Dir string }
	var layers []laidOut
	ownedPaths := map[string]bool{}

	for _, p := range pkgs {
		fmt.Fprintf(os.Stderr, "\n[bootstrap] %s %s\n", p.Name, p.Version)
		files, err := deb.PackageFiles(sandboxDir, p.Name)
		if err != nil {
			return err
		}
		for _, f := range files {
			ownedPaths[f] = true
		}
		staging := filepath.Join(tmp, p.Name)
		if err := deb.StageFiles(sandboxDir, files, staging); err != nil {
			return err
		}
		slug := deb.SlugifyVersion(p.Version)
		dirName := fmt.Sprintf("%s-%s", p.Name, slug)
		pkgDir := filepath.Join(repo, dirName)
		if _, err := os.Stat(pkgDir); err == nil {
			_ = runner.Run(runner.Cmd{
				Argv: []string{"rm", "-rf", pkgDir}, Sudo: true,
			})
		}
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			return err
		}
		roothash, dataSize, err := layer.MakeVerity(staging,
			filepath.Join(pkgDir, "image.img"),
			"pk-"+truncateStr(p.Name, 12), 0)
		if err != nil {
			return err
		}
		descRaw, _ := deb.PackageField(sandboxDir, p.Name, "Description")
		depsRaw, _ := deb.PackageField(sandboxDir, p.Name, "Depends")
		if err := kit.WritePackageManifest(pkgDir, kit.PackageManifest{
			Package: kit.PackageBlock{
				Name: p.Name, Version: p.Version, Arch: p.Arch,
				Description: firstLine(descRaw),
			},
			Image:   kit.ImageBlock{DataSize: dataSize, Roothash: roothash},
			Depends: kit.DependsBlock{Runtime: deb.ParseDepends(depsRaw)},
		}); err != nil {
			return err
		}
		layers = append(layers, laidOut{p.Name, p.Version, p.Arch, dirName})
	}

	// Orphans → pancake-state.
	fmt.Fprintln(os.Stderr,
		"\n[bootstrap] computing orphan (postinst-created) files")
	every, err := deb.AllRealFiles(sandboxDir)
	if err != nil {
		return err
	}
	var orphans []string
	for f := range every {
		if ownedPaths[f] {
			continue
		}
		if shouldIgnore(f) {
			continue
		}
		orphans = append(orphans, f)
	}
	sort.Strings(orphans)
	fmt.Fprintf(os.Stderr, "  → %d orphan files (kept)\n", len(orphans))

	if len(orphans) > 0 {
		staging := filepath.Join(tmp, "_pancake-state")
		if err := deb.StageFiles(sandboxDir, orphans, staging); err != nil {
			return err
		}
		pkgDir := filepath.Join(repo, "pancake-state")
		if _, err := os.Stat(pkgDir); err == nil {
			_ = runner.Run(runner.Cmd{
				Argv: []string{"rm", "-rf", pkgDir}, Sudo: true,
			})
		}
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			return err
		}
		roothash, dataSize, err := layer.MakeVerity(staging,
			filepath.Join(pkgDir, "image.img"), "pancake-state", 0)
		if err != nil {
			return err
		}
		if err := kit.WritePackageManifest(pkgDir, kit.PackageManifest{
			Package: kit.PackageBlock{
				Name: "pancake-state", Version: "1.0.0", Arch: "all",
				Description: "post-install state (users, unit symlinks, ...)",
			},
			Image: kit.ImageBlock{DataSize: dataSize, Roothash: roothash},
		}); err != nil {
			return err
		}
		layers = append(layers, laidOut{"pancake-state", "1.0.0", "all", "pancake-state"})
	}

	// Overlay order: leaves (most-specific) first, base last.
	// pancake-state goes at the very top so its post-install bits win over
	// anything a package might re-ship.
	byName := map[string]laidOut{}
	for _, L := range layers {
		byName[L.Name] = L
	}
	depFirst := topologicalOrder(pkgs, sandboxDir)
	var overlay []laidOut
	if L, ok := byName["pancake-state"]; ok {
		overlay = append(overlay, L)
	}
	for i := len(depFirst) - 1; i >= 0; i-- {
		if L, ok := byName[depFirst[i]]; ok {
			overlay = append(overlay, L)
		}
	}

	// Generation 1 manifest.
	k := &kit.Kit{Dir: a.Output}
	gm := kit.GenerationManifest{
		Generation: kit.GenerationBlock{
			ID: 1, Parent: 0,
			Description: fmt.Sprintf("initial generation (%d layers)", len(overlay)),
		},
	}
	for _, L := range overlay {
		gm.Layer = append(gm.Layer, kit.LayerRef{
			Name: L.Name, Version: L.Version,
			Manifest: fmt.Sprintf("repo/%s/manifest.toml", L.Dir),
		})
	}
	if err := kit.WriteGenerationManifest(k, gm); err != nil {
		return err
	}
	if err := k.SetCurrent(1); err != nil {
		return err
	}

	if !a.KeepSandbox {
		_ = runner.Run(runner.Cmd{
			Argv: []string{"rm", "-rf", sandboxDir}, Sudo: true,
		})
	}

	fmt.Fprintf(os.Stderr, "\n[bootstrap] kit ready at %s\n", a.Output)
	fmt.Fprintf(os.Stderr, "  layers: %d\n", len(overlay))
	fmt.Fprintf(os.Stderr, "  generation: %s/manifest.toml\n",
		filepath.Join(a.Output, "generations/1"))
	fmt.Fprintln(os.Stderr, "  current → generations/1")

	// Optional: pack disk image.
	if a.ImagePath != "" {
		fmt.Fprintf(os.Stderr,
			"\n[bootstrap] packing disk image → %s\n", a.ImagePath)
		if err := pack.Disk(a.Output, a.ImagePath); err != nil {
			return fmt.Errorf("pack: %w", err)
		}
	}

	// Optional: build initramfs.
	if a.InitramfsPath != "" {
		fmt.Fprintf(os.Stderr,
			"\n[bootstrap] building initramfs (kernel=%s) → %s\n",
			a.Kernel, a.InitramfsPath)
		srcRoot := a.SrcRoot
		if srcRoot == "" {
			// Same default the bake step uses: derive from os.Executable.
			if exe, err := os.Executable(); err == nil {
				// .../tools/pancake-go/bin/pancake → fs-pancake/
				srcRoot = filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(exe))))
			}
		}
		if err := initramfs.Build(initramfs.Opts{
			OutPath: a.InitramfsPath,
			KVer:    a.Kernel,
			SrcRoot: srcRoot,
			Suite:   a.Suite,
			Mirror:  a.Mirror,
		}); err != nil {
			return fmt.Errorf("initramfs: %w", err)
		}
	}
	return nil
}

func mmdebstrap(suite, mirror string, pkgs []string, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		if err := runner.Run(runner.Cmd{
			Argv: []string{"rm", "-rf", dest}, Sudo: true,
		}); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return runner.Run(runner.Cmd{
		Argv: []string{"mmdebstrap", "--variant=minbase",
			"--components=main,universe",
			"--include=" + strings.Join(pkgs, ","),
			suite, dest, mirror},
		Sudo: true,
	})
}

// ignorePatterns mirrors pancake-bootstrap.py: drop runtime + cache state but
// KEEP /var/lib/dpkg so the booted system can `dpkg-query` what's installed.
var ignorePatterns = []string{
	"/var/cache/", "/var/log/", "/var/lib/apt/",
	"/var/lib/systemd/random-seed",
	"/run/", "/proc/", "/sys/", "/dev/", "/tmp/",
}

func shouldIgnore(p string) bool {
	for _, pat := range ignorePatterns {
		if strings.HasPrefix(p, pat) {
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func dedup(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// truncate, firstLine live in install.go (shared across cmd/pancake files).
