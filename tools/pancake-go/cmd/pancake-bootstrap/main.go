// pancake-bootstrap — build a complete pancake-os kit from a Debian package list.
//
// Process:
//
//  1. Run mmdebstrap to create _sandbox/ with all packages installed
//     (postinsts run, /etc/passwd populated, units enabled, etc).
//  2. Customize: hostname, ssh host keys, authorized_keys, debug+networkd
//     units, sshd_config, then bake the pancake runtime (Go binaries +
//     systemd remount unit).
//  3. For each installed package: stage files → mkfs.ext4 + verity format →
//     manifest.
//  4. Orphans (postinst side effects not owned by any package) → pancake-state
//     layer.
//  5. Topo-sort by Depends, write generations/1/manifest.toml + lowers,
//     point current → generations/1.
//
// Pure file ops + mmdebstrap; no live overlay-of-N-layers stress on the
// host kernel. Safe to run on the build machine.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/deb"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/layer"
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

func main() {
	suite := flag.String("suite", "noble", "Debian/Ubuntu suite")
	mirror := flag.String("mirror", "http://archive.ubuntu.com/ubuntu/", "")
	pkgs := flag.String("packages", "", "comma-separated extra packages")
	out := flag.String("output", "", "kit output directory (required)")
	hostname := flag.String("hostname", "pancake", "/etc/hostname")
	keepSandbox := flag.Bool("keep-sandbox", false,
		"don't delete _sandbox after building")
	sshHostKeys := flag.String("ssh-host-keys", "",
		"dir with ssh_host_*_key files (else generate fresh)")
	sshAuthKeys := flag.String("ssh-authorized-keys", "",
		"file installed at /root/.ssh/authorized_keys")
	pancakeBin := flag.String("pancake-bin", "",
		"path to the pancake binary to bake (default: next to bootstrap or $PATH)")
	pancakeBuildBin := flag.String("pancake-build-bin", "",
		"path to the pancake-build binary to bake")
	srcRoot := flag.String("src-root", "",
		"path to fs-pancake source tree (for mount-overlay.c, pivot-root.c)")
	flag.Parse()

	if *out == "" || *pkgs == "" {
		fmt.Fprintln(os.Stderr,
			"usage: pancake-bootstrap --packages a,b,c --output DIR [flags]")
		os.Exit(2)
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
		PancakeBuildBin: *pancakeBuildBin,
		SrcRoot:         *srcRoot,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type bootstrapArgs struct {
	Suite, Mirror, Output, Hostname                   string
	Packages                                          []string
	KeepSandbox                                       bool
	SSHHostKeysDir, SSHAuthKeysFile                   string
	PancakeBin, PancakeBuildBin, SrcRoot              string
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
			"pk-"+truncate(p.Name, 12), 0)
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
