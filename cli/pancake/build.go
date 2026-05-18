// `pancake build`: turn one .deb into one verity layer + manifest.
//
// Process (matches the historical pancake-build):
//
//  1. Mount overlay sandbox: lower = the cumulative chroot of already-built
//     packages, upper = scratch tmpfs.
//  2. Bind /proc /sys /dev inside the sandbox (postinst usually wants them).
//  3. Run `dpkg --install <pkg>.deb` inside the sandbox. dpkg unpacks AND
//     configures, which fires preinst/postinst/triggers.
//  4. The overlay's upper layer is exactly this package's contribution:
//     files it shipped, plus anything postinst added.
//  5. mkfs.ext4 + veritysetup format on the upper layer → image.img + image.hash
//  6. Write manifest.toml with package metadata + roothash + Depends:.
//
// `pancake install` is the higher-level workflow — it materializes the
// kit, runs apt to resolve deps, then snapshots each new package directly.
// `pancake build` is the manual override for when you have a single .deb
// already + a chroot to install it against.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sinkap/pancake/common/go/deb"
	"github.com/sinkap/pancake/common/go/kit"
	"github.com/sinkap/pancake/common/go/layer"
	"github.com/sinkap/pancake/common/go/runner"
)

// overlayInstall mounts overlay(lower, upper, work) at merged, bind-mounts
// /proc /sys /dev under it, copies the .deb in, and runs dpkg --install
// followed by a deferred --triggers-only pass. All mounts are torn down in
// the deferred cleanup whether the install succeeded or not.
func overlayInstall(debPath, lower, upper, work, merged string) error {
	for _, d := range []string{merged, upper, work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mount", "-t", "overlay", "overlay",
			"-o", fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work),
			merged},
		Sudo: true,
	}); err != nil {
		return err
	}
	defer runner.RunOK(runner.Cmd{Argv: []string{"umount", merged}, Sudo: true})

	for _, sub := range []string{"proc", "sys", "dev"} {
		tgt := filepath.Join(merged, sub)
		_ = os.MkdirAll(tgt, 0o755)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"mount", "--rbind", "/" + sub, tgt}, Sudo: true,
		}); err != nil {
			return err
		}
	}
	defer func() {
		// reverse order, lazy detach so partial cleanup doesn't wedge
		for _, sub := range []string{"dev", "sys", "proc"} {
			runner.RunOK(runner.Cmd{
				Argv: []string{"umount", "-l", filepath.Join(merged, sub)},
				Sudo: true,
			})
		}
	}()

	debName := filepath.Base(debPath)
	inChroot := filepath.Join(merged, "tmp", debName)
	if err := os.MkdirAll(filepath.Dir(inChroot), 0o755); err != nil {
		return err
	}
	if err := copyFile(debPath, inChroot); err != nil {
		return err
	}
	defer runner.RunOK(runner.Cmd{
		Argv: []string{"rm", "-f", inChroot}, Sudo: true,
	})

	env := []string{
		"DEBIAN_FRONTEND=noninteractive",
		"DPKG_FORCE=confnew",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
	}
	// --force-depends: pancake-os manages deps via the generation manifest,
	// not via dpkg's status DB. We trust the caller to have ensured all
	// needed dep layers are stacked already.
	if err := runner.Run(runner.Cmd{
		Argv: []string{"chroot", merged, "dpkg", "--install",
			"--force-confnew", "--force-depends", "--no-triggers",
			"/tmp/" + debName},
		Sudo: true,
		Env:  env,
	}); err != nil {
		return err
	}
	// triggers fire after the install — non-fatal if any single trigger
	// fails (some need network, etc).
	_ = runner.RunOK(runner.Cmd{
		Argv: []string{"chroot", merged, "dpkg", "--triggers-only", "--pending"},
		Sudo: true,
		Env:  env,
	})
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func buildOne(debPath, lower, repo string) (string, error) {
	md, err := deb.ReadDebMetadata(debPath)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "[pancake-build] %s %s\n", md.Package, md.Version)

	outDir := filepath.Join(repo, fmt.Sprintf("%s-%s",
		md.Package, deb.SlugifyVersion(md.Version)))
	if _, err := os.Stat(outDir); err == nil {
		_ = runner.Run(runner.Cmd{
			Argv: []string{"rm", "-rf", outDir}, Sudo: true,
		})
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}

	tmp, err := os.MkdirTemp("", "pancake-build-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	upper := filepath.Join(tmp, "upper")
	work := filepath.Join(tmp, "work")
	merged := filepath.Join(tmp, "merged")
	if err := overlayInstall(debPath, lower, upper, work, merged); err != nil {
		return "", err
	}

	imgPath := filepath.Join(outDir, "image.img")
	slug := fmt.Sprintf("%s-%s", md.Package, deb.SlugifyVersion(md.Version))
	roothash, dataSize, err := layer.MakeVerity(upper, imgPath,
		"pk-"+truncateStr(md.Package, 12), 8, slug)
	if err != nil {
		return "", err
	}

	debSHA, err := deb.FileSHA256(debPath)
	if err != nil {
		return "", err
	}
	arch := md.Arch
	if arch == "" {
		arch = "amd64"
	}
	descr := firstLine(md.Description)
	if err := kit.WritePackageManifest(outDir, kit.PackageManifest{
		Package: kit.PackageBlock{
			Name:        md.Package,
			Version:     md.Version,
			Arch:        arch,
			Description: descr,
		},
		Image: kit.ImageBlock{
			DataSize: dataSize,
			Roothash: roothash,
		},
		Depends: kit.DependsBlock{Runtime: deb.ParseDepends(md.Depends)},
		Prov: kit.Provenance{
			DebName:   filepath.Base(debPath),
			DebSHA256: debSHA,
		},
	}); err != nil {
		return "", err
	}
	short := roothash
	if len(short) > 16 {
		short = short[:16]
	}
	fmt.Fprintf(os.Stderr, "  → %s/image.img  roothash=%s…\n", outDir, short)
	return outDir, nil
}

// cmdBuild is the `pancake build` subcommand. It ignores the global --kit
// (build operates on a free-standing --repo dir) but accepts the
// (k *kit.Kit, args) signature for dispatch uniformity.
func cmdBuild(_ *kit.Kit, args []string) int {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	debPath := fs.String("deb", "", "path to .deb to build")
	lower := fs.String("lower", "",
		"dependency chroot to use as overlay lowerdir")
	repo := fs.String("repo", "",
		"output dir; package goes to <repo>/<name>-<ver>/")
	// build takes no positional args (--deb, --lower, --repo all carry values),
	// so direct Parse is safe and correct for "--foo VAL" separate-token form.
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *debPath == "" || *lower == "" || *repo == "" {
		fmt.Fprintln(os.Stderr,
			"usage: pancake build --deb foo.deb --lower CHROOT --repo OUTDIR")
		return 2
	}
	if fi, err := os.Stat(*debPath); err != nil || fi.IsDir() {
		fmt.Fprintf(os.Stderr, "no such .deb: %s\n", *debPath)
		return 2
	}
	if fi, err := os.Stat(*lower); err != nil || !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "lower not a directory: %s\n", *lower)
		return 2
	}
	if _, err := buildOne(*debPath, *lower, *repo); err != nil {
		return die(err)
	}
	return 0
}
