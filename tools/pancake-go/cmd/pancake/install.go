// `pancake install <pkg>...`: materialize current generation as an overlay
// chroot, run apt-get install inside it, snapshot each newly-installed
// package as its own verity layer, write generation N+1.
//
// MUST run inside the booted pancake-os VM (or another disposable host) —
// stacking 100+ verity lowers + bind-mounting /proc/sys/dev is too kernel-
// stressy for the user's primary box. cmd_install doesn't enforce this
// (some test setups use a stock-kernel VM), but the project rule is firm.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/deb"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/layer"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/runner"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/sandbox"
)

func cmdInstall(k *kit.Kit, args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	activate := fs.Bool("activate", false,
		"set current → the new generation immediately")
	// Go's flag.Parse stops at the first non-flag arg, which means
	// `pancake install htop --activate` would silently ignore --activate
	// and treat it as a no-op. Pre-split so flags can appear anywhere.
	flagArgs, positional := splitFlagsAndPositionals(args)
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	if len(positional) == 0 {
		fmt.Fprintln(os.Stderr,
			"usage: pancake install <pkg>... [--activate]")
		return 2
	}
	packages := positional

	// Read current generation so we can compute "what's new" later.
	curGenPath, err := k.CurrentGeneration()
	if err != nil {
		return die(err)
	}
	curMan, err := kit.ReadGenerationManifest(
		filepath.Join(curGenPath, "manifest.toml"))
	if err != nil {
		return die(err)
	}
	curPkgs := map[string]bool{}
	for _, L := range curMan.Layer {
		curPkgs[L.Name] = true
	}

	mountOverlay, err := sandbox.FindHelper("mount-overlay",
		repoRoot(), "initramfs")
	if err != nil {
		return die(err)
	}

	scratch, err := os.MkdirTemp("", "pancake-install-")
	if err != nil {
		return die(err)
	}
	defer os.RemoveAll(scratch)

	tag := fmt.Sprintf("pkadd%d", os.Getpid())
	sb, err := sandbox.MaterializeCurrent(k, scratch, tag, mountOverlay)
	if err != nil {
		return die(err)
	}
	defer sb.Teardown()

	if err := sb.BindChrootRuntime(); err != nil {
		return die(err)
	}

	env := []string{
		"DEBIAN_FRONTEND=noninteractive",
		"DPKG_FORCE=confnew",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
	}
	fmt.Fprintf(os.Stderr, "[pancake] apt update + install %v\n", packages)
	if err := runner.Run(runner.Cmd{
		Argv: []string{"chroot", sb.Path, "apt-get", "update", "-q", "-y"},
		Env:  env,
	}); err != nil {
		return die(err)
	}
	if err := runner.Run(runner.Cmd{
		Argv: append([]string{"chroot", sb.Path, "apt-get", "install", "-y",
			"--no-install-recommends",
			"-o", "Dpkg::Options::=--force-confnew"}, packages...),
		Env: env,
	}); err != nil {
		return die(err)
	}

	// Diff installed packages to find newly-added ones (apt resolved deps).
	allNow, err := deb.InstalledPackages(sb.Path)
	if err != nil {
		return die(err)
	}
	type newPkg struct{ Name, Version, Arch string }
	var newPkgs []newPkg
	for _, p := range allNow {
		if curPkgs[p.Name] || p.Name == "pancake-state" {
			continue
		}
		newPkgs = append(newPkgs, newPkg{p.Name, p.Version, p.Arch})
	}
	fmt.Fprintf(os.Stderr,
		"[pancake] %d new packages (after dep resolution)\n", len(newPkgs))
	if len(newPkgs) == 0 {
		fmt.Fprintln(os.Stderr,
			"[pancake] nothing to do — already installed in current generation")
		return 0
	}

	// Stage each new pkg into its own staging dir → verity layer → manifest.
	stageRoot, err := os.MkdirTemp("", "pancake-install-stage-")
	if err != nil {
		return die(err)
	}
	defer os.RemoveAll(stageRoot)

	type laidOut struct {
		Name, Version, Slug string
	}
	var newLayers []laidOut
	for _, p := range newPkgs {
		fmt.Fprintf(os.Stderr, "  → %s %s\n", p.Name, p.Version)
		files, err := deb.PackageFiles(sb.Path, p.Name)
		if err != nil {
			return die(err)
		}
		staging := filepath.Join(stageRoot, p.Name)
		if err := deb.StageFiles(sb.Path, files, staging); err != nil {
			return die(err)
		}

		slug := fmt.Sprintf("%s-%s", p.Name, deb.SlugifyVersion(p.Version))
		pkgDir := filepath.Join(k.Repo(), slug)
		if _, err := os.Stat(pkgDir); err == nil {
			_ = runner.Run(runner.Cmd{
				Argv: []string{"rm", "-rf", pkgDir}, Sudo: true,
			})
		}
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			return die(err)
		}
		roothash, dataSize, err := layer.MakeVerity(staging,
			filepath.Join(pkgDir, "image.img"),
			"pk-"+truncateStr(p.Name, 12), 0, slug)
		if err != nil {
			return die(err)
		}

		descRaw, _ := deb.PackageField(sb.Path, p.Name, "Description")
		depsRaw, _ := deb.PackageField(sb.Path, p.Name, "Depends")
		if err := kit.WritePackageManifest(pkgDir, kit.PackageManifest{
			Package: kit.PackageBlock{
				Name: p.Name, Version: p.Version, Arch: p.Arch,
				Description: firstLine(descRaw),
			},
			Image:   kit.ImageBlock{DataSize: dataSize, Roothash: roothash},
			Depends: kit.DependsBlock{Runtime: deb.ParseDepends(depsRaw)},
		}); err != nil {
			return die(err)
		}
		newLayers = append(newLayers, laidOut{p.Name, p.Version, slug})
	}

	// New generation = new layers (top) + everything currently active.
	curID, err := k.CurrentID()
	if err != nil {
		return die(err)
	}
	latest, err := k.LatestGenerationID()
	if err != nil {
		return die(err)
	}
	newID := latest + 1
	// Counter must monotonically increase across kit history so the
	// initramfs's TPM-NV-counter check rejects rollback attempts.
	maxCtr, err := k.MaxCounter()
	if err != nil {
		return die(err)
	}
	allLayers := make([]kit.LayerRef, 0, len(newLayers)+len(curMan.Layer))
	for _, L := range newLayers {
		allLayers = append(allLayers, kit.LayerRef{
			Name: L.Name, Version: L.Version,
			Manifest: fmt.Sprintf("repo/%s/manifest.toml", L.Slug),
		})
	}
	allLayers = append(allLayers, curMan.Layer...)
	if err := kit.WriteGenerationManifest(k, kit.GenerationManifest{
		Generation: kit.GenerationBlock{
			ID: newID, Parent: curID, Counter: maxCtr + 1,
			Description: fmt.Sprintf("install %s (%d new layers)",
				csv(packages), len(newLayers)),
		},
		Layer: allLayers,
	}); err != nil {
		return die(err)
	}

	if *activate {
		if err := k.SetCurrent(newID); err != nil {
			return die(err)
		}
		fmt.Fprintf(os.Stderr, "[pancake] activated generation %d\n", newID)
	} else {
		fmt.Fprintf(os.Stderr,
			"[pancake] generation %d staged. `pancake activate %d` to switch.\n",
			newID, newID)
	}
	return 0
}

// helpers shared with cmd_swap, kept package-local
func die(err error) int {
	fmt.Fprintln(os.Stderr, err)
	return 1
}

// splitFlagsAndPositionals partitions argv into (flag-tokens, positionals)
// so the stdlib flag package's "stop at first non-flag" rule doesn't cause
// `pancake install htop --activate` to silently drop --activate.
//
// Handles --foo, --foo=val, -f, -f=val. Does NOT handle the "--foo val"
// (separate-token value) form because none of pancake's flags use it; if
// any do later, this needs to grow a little.
func splitFlagsAndPositionals(args []string) (flags, positional []string) {
	for _, a := range args {
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
		} else {
			positional = append(positional, a)
		}
	}
	return
}
func truncateStr(s string, n int) string {
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
func csv(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}

// repoRoot tries to locate the fs-pancake source tree, used by FindHelper
// as a last-resort fallback if /sbin/mount-overlay isn't present (i.e.,
// when the binary is being run from a dev checkout, not from the kit).
// Returns "" if it can't figure it out, which makes FindHelper rely on
// the /sbin search only.
func repoRoot() string {
	// argv[0] of `pancake` is typically /usr/local/bin/pancake (in the kit)
	// or .../pancake-go/bin/pancake (in dev). For the latter, the helper
	// .c sources live two dirs up.
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	// .../tools/pancake-go/bin/pancake → .../
	dir := filepath.Dir(exe)
	if filepath.Base(dir) == "bin" {
		// .../tools/pancake-go/bin
		return filepath.Dir(filepath.Dir(filepath.Dir(dir)))
	}
	return ""
}

// silence "unused" warning until the swap subcommand lands
var _ = strconv.Atoi
