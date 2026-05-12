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
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/efi"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/initramfs"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/layer"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/pack"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/runner"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/sign"
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
	// libtss2-* are dlopen'd by systemd-creds for TPM2 sealing. Without
	// them `pancake enroll` (and any systemd-creds --tpm2-* op) reports
	// `-libraries` and refuses. tpm2-tools also gives `tpm2_*` CLIs in
	// the booted system for debugging.
	"tpm2-tools",
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
			"into --initramfs (default: uname -r).")
	bzimage := fs.String("bzimage", "",
		"path to a custom-built bzImage; if set, pack it as a "+
			"'pancake-kernel' verity layer (and modules from "+
			"/lib/modules/<--kernel> as 'pancake-modules') instead of "+
			"installing the suite's linux-image-generic. Use this when your "+
			"kernel isn't in any apt repo (e.g. bpf-next/for-next).")
	bzimageOut := fs.String("bzimage-out", "./pancake-bzImage",
		"after building, drop the kernel bzImage at this path so the QEMU "+
			"-kernel arg can point at it without extracting from the kit; "+
			"empty to skip")
	efiOut := fs.String("efi", "",
		"build a UEFI-bootable disk image at this path (GPT + ESP + rootfs, "+
			"systemd-boot + a UKI bundling kernel/initrd/cmdline). When set, "+
			"the QEMU command needs no -kernel/-initrd args, just OVMF + the "+
			"image. Independent of --image (which produces a kit-only ext4); "+
			"empty (default) to skip.")
	cmdline := fs.String("cmdline",
		"console=ttyS0 rdinit=/init pancake.state=LABEL=PANCAKE_STATE",
		"kernel cmdline baked into the UKI when --efi is set")
	signKey := fs.String("sign-key", "",
		"PEM private key (RSA-2048) used to sign the UKI (UEFI Secure Boot) "+
			"AND the generation manifest. Generated alongside --sign-cert "+
			"if neither file exists. Empty disables signing.")
	signCert := fs.String("sign-cert", "",
		"PEM X.509 cert matching --sign-key. UEFI verifies the UKI "+
			"signature against this cert (must be enrolled in db). The "+
			"public key is also extracted and baked into the initramfs at "+
			"/etc/pancake/manifest.pubkey for manifest verification at boot.")

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
		BzImagePath:     *bzimage,
		BzImageOutPath:  *bzimageOut,
		EFIPath:         *efiOut,
		Cmdline:         *cmdline,
		SignKey:         *signKey,
		SignCert:        *signCert,
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
	// of /lib/modules/<Kernel> on the build host. Used both for the
	// initramfs modules AND (when BzImagePath is set) for the
	// pancake-modules layer's source.
	Kernel string
	// BzImagePath: path to a custom-built bzImage. If set, we pack it as
	// a pancake-kernel verity layer + pancake-modules from /lib/modules/<Kernel>,
	// and skip pulling linux-image-generic from the suite.
	BzImagePath string
	// BzImageOutPath: where to drop a copy of the bzImage for QEMU. The
	// kit owns the canonical (verity-protected) copy; this is just a
	// convenience handoff.
	BzImageOutPath string
	// EFIPath: when set, build a UEFI-bootable disk image (GPT + ESP +
	// rootfs, systemd-boot + UKI). Independent of ImagePath.
	EFIPath string
	// Cmdline: kernel cmdline baked into the UKI when EFIPath is set.
	Cmdline string
	// SignKey + SignCert: when both set, sign the UKI (UEFI Secure Boot)
	// and the generation manifest, and bake the cert's public key into
	// the initramfs so /init can verify the manifest before mounting.
	SignKey, SignCert string
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
	if a.BzImagePath == "" {
		// No custom bzImage → pull the suite's default kernel meta-package.
		// On Debian/Ubuntu this in turn pulls linux-image-X.Y.Z and
		// linux-modules-X.Y.Z as separate .debs, so they end up as two
		// natural pancake layers via the per-package staging below.
		pkgList = append(pkgList, "linux-image-generic")
	}

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
			"pk-"+truncateStr(p.Name, 12), 0, dirName)
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
			filepath.Join(pkgDir, "image.img"), "pancake-state", 0,
			"pancake-state")
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

	// Synthetic kernel layers (only when --bzimage was given; the suite
	// kernel route already produces linux-image-* + linux-modules-* layers
	// naturally via the per-package staging loop above).
	if a.BzImagePath != "" {
		var err error
		layers, err = packCustomKernel(tmp, repo, layers, a)
		if err != nil {
			return err
		}
	}

	// Overlay order: leaves (most-specific) first, base last.
	// pancake-state at the very top so its post-install bits win over
	// anything a package might re-ship. The synthetic kernel + modules
	// layers go just below — they own /boot/vmlinuz and
	// /lib/modules/<ver> exclusively, so order is mostly cosmetic, but
	// putting them near the top keeps related layers visually adjacent
	// in `pancake list` output.
	byName := map[string]laidOut{}
	for _, L := range layers {
		byName[L.Name] = L
	}
	depFirst := topologicalOrder(pkgs, sandboxDir)
	var overlay []laidOut
	for _, name := range []string{"pancake-state", "pancake-kernel", "pancake-modules"} {
		if L, ok := byName[name]; ok {
			overlay = append(overlay, L)
		}
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
			ID: 1, Parent: 0, Counter: 1,
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

	// Sign the generation manifest if signing material was provided.
	// Bootstrap auto-generates a self-signed dev pair if neither file
	// exists yet, so the user gets a working signed kit on first run.
	if a.SignKey != "" && a.SignCert != "" {
		hostname := a.Hostname
		if hostname == "" {
			hostname = "pancake"
		}
		if generated, err := sign.EnsureKeyAndCert(
			a.SignKey, a.SignCert, hostname); err != nil {
			return fmt.Errorf("sign-key/sign-cert: %w", err)
		} else if generated {
			fmt.Fprintf(os.Stderr,
				"\n[bootstrap] generated dev signing pair:\n"+
					"  key:  %s\n  cert: %s\n"+
					"  (use real keys for production; UEFI db enrollment "+
					"required for Secure Boot to verify)\n",
				a.SignKey, a.SignCert)
		}
		manifestPath := filepath.Join(k.Generations(), "1", "manifest.toml")
		if _, err := sign.SignManifest(manifestPath, a.SignKey); err != nil {
			return fmt.Errorf("sign manifest: %w", err)
		}
		fmt.Fprintf(os.Stderr,
			"  → signed %s.sig (verifiable with `openssl dgst -sha256 "+
				"-verify pubkey.pem -signature %s.sig %s`)\n",
			manifestPath, manifestPath, manifestPath)
	} else if a.SignKey != "" || a.SignCert != "" {
		return fmt.Errorf("--sign-key and --sign-cert must both be set")
	}

	// bzImage hand-off for QEMU: do this BEFORE sandbox cleanup since the
	// suite-kernel path reads /boot/vmlinuz-* out of the sandbox.
	if a.BzImageOutPath != "" {
		if err := exportBzImage(sandboxDir, a); err != nil {
			return fmt.Errorf("bzimage-out: %w", err)
		}
		fmt.Fprintf(os.Stderr, "  → bzImage at %s\n", a.BzImageOutPath)
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
		// If signing is on, extract pubkey from cert into a temp file so
		// the initramfs builder can bake it at /etc/pancake/manifest.pubkey.
		var pubkeyPath string
		if a.SignCert != "" {
			pubkeyPath = filepath.Join(a.Output, ".pancake-manifest.pubkey")
			if err := sign.PubkeyFromCert(a.SignCert, pubkeyPath); err != nil {
				return fmt.Errorf("extract pubkey: %w", err)
			}
			defer os.Remove(pubkeyPath)
		}
		if err := initramfs.Build(initramfs.Opts{
			OutPath:    a.InitramfsPath,
			KVer:       a.Kernel,
			SrcRoot:    srcRoot,
			Suite:      a.Suite,
			Mirror:     a.Mirror,
			PubKeyPath: pubkeyPath,
		}); err != nil {
			return fmt.Errorf("initramfs: %w", err)
		}
	}

	// Optional: build a UEFI-bootable disk image. Needs the bzImage and
	// initramfs to exist; if either was suppressed via empty flags, error
	// clearly rather than silently producing nothing.
	if a.EFIPath != "" {
		if a.BzImageOutPath == "" {
			return fmt.Errorf("--efi requires --bzimage-out (the kernel " +
				"to bundle into the UKI). Set both, or skip --efi.")
		}
		if a.InitramfsPath == "" {
			return fmt.Errorf("--efi requires --initramfs (the initramfs " +
				"to bundle into the UKI). Set both, or skip --efi.")
		}
		fmt.Fprintf(os.Stderr,
			"\n[bootstrap] building UKI + EFI disk → %s\n", a.EFIPath)
		uki := strings.TrimSuffix(a.EFIPath, filepath.Ext(a.EFIPath)) + ".uki.efi"
		if err := efi.BuildUKI(efi.UKIOpts{
			Linux:    a.BzImageOutPath,
			Initrd:   a.InitramfsPath,
			Cmdline:  a.Cmdline,
			Out:      uki,
			UName:    a.Kernel,
			SignKey:  a.SignKey,
			SignCert: a.SignCert,
		}); err != nil {
			return fmt.Errorf("uki: %w", err)
		}
		if err := efi.PackEFIDisk(efi.EFIDiskOpts{
			Out:    a.EFIPath,
			KitDir: a.Output,
			UKI:    uki,
			GenID:  1,
		}); err != nil {
			return fmt.Errorf("efi disk: %w", err)
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

// laidOut is one row of the bootstrap layer ledger: a package (or
// synthetic layer like pancake-state / pancake-kernel) with the slug
// directory under repo/. Package-level so the synthetic-layer helpers
// can return + extend it.
type laidOut struct{ Name, Version, Arch, Dir string }

// packCustomKernel synthesizes two pancake layers from a user-supplied
// bzImage + the host's /lib/modules/<--kernel>/ tree. Used only when
// --bzimage was given; the suite-kernel path makes both layers naturally
// from linux-image-* and linux-modules-* .debs.
//
// pancake-kernel layer: just /boot/vmlinuz containing the bzImage.
// pancake-modules layer: /lib/modules/<Kernel>/ from the host (recursive).
func packCustomKernel(tmp, repo string, layers []laidOut, a bootstrapArgs) ([]laidOut, error) {
	fmt.Fprintf(os.Stderr,
		"\n[bootstrap] custom kernel: packing pancake-kernel + pancake-modules layers\n")

	// pancake-kernel (the bzImage as /boot/vmlinuz)
	{
		staging := filepath.Join(tmp, "_pancake-kernel")
		bootDir := filepath.Join(staging, "boot")
		if err := os.MkdirAll(bootDir, 0o755); err != nil {
			return layers, err
		}
		if err := copyFileLocal(a.BzImagePath,
			filepath.Join(bootDir, "vmlinuz")); err != nil {
			return layers, fmt.Errorf("copy bzImage: %w", err)
		}
		pkgDir := filepath.Join(repo, "pancake-kernel")
		if _, err := os.Stat(pkgDir); err == nil {
			_ = runner.Run(runner.Cmd{
				Argv: []string{"rm", "-rf", pkgDir}, Sudo: true,
			})
		}
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			return layers, err
		}
		roothash, dataSize, err := layer.MakeVerity(staging,
			filepath.Join(pkgDir, "image.img"), "pancake-kernel", 0,
			"pancake-kernel-"+a.Kernel)
		if err != nil {
			return layers, err
		}
		if err := kit.WritePackageManifest(pkgDir, kit.PackageManifest{
			Package: kit.PackageBlock{
				Name:    "pancake-kernel",
				Version: a.Kernel,
				Arch:    "all",
				Description: fmt.Sprintf("custom kernel from %s",
					filepath.Base(a.BzImagePath)),
			},
			Image: kit.ImageBlock{DataSize: dataSize, Roothash: roothash},
		}); err != nil {
			return layers, err
		}
		layers = append(layers, laidOut{"pancake-kernel", a.Kernel, "all", "pancake-kernel"})
	}

	// pancake-modules (/lib/modules/<Kernel>)
	{
		modSrc := filepath.Join("/lib/modules", a.Kernel)
		if _, err := os.Stat(modSrc); err != nil {
			return layers, fmt.Errorf("--bzimage given but %s missing — "+
				"pass --kernel <ver> matching the bzImage and ensure "+
				"`make modules_install` has been run", modSrc)
		}
		staging := filepath.Join(tmp, "_pancake-modules")
		modDst := filepath.Join(staging, "lib/modules", a.Kernel)
		if err := os.MkdirAll(modDst, 0o755); err != nil {
			return layers, err
		}
		// cp -a preserves perms, symlinks, hard links — important for
		// the kernel/<arch>/<subsys>/foo.ko tree which has thousands.
		if err := runner.Run(runner.Cmd{
			Argv: []string{"cp", "-a", modSrc + "/.", modDst + "/"},
			Sudo: true,
		}); err != nil {
			return layers, err
		}
		pkgDir := filepath.Join(repo, "pancake-modules")
		if _, err := os.Stat(pkgDir); err == nil {
			_ = runner.Run(runner.Cmd{
				Argv: []string{"rm", "-rf", pkgDir}, Sudo: true,
			})
		}
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			return layers, err
		}
		roothash, dataSize, err := layer.MakeVerity(staging,
			filepath.Join(pkgDir, "image.img"), "pancake-modules", 0,
			"pancake-modules-"+a.Kernel)
		if err != nil {
			return layers, err
		}
		if err := kit.WritePackageManifest(pkgDir, kit.PackageManifest{
			Package: kit.PackageBlock{
				Name:    "pancake-modules",
				Version: a.Kernel,
				Arch:    "all",
				Description: fmt.Sprintf(
					"kernel modules from /lib/modules/%s on build host",
					a.Kernel),
			},
			Image: kit.ImageBlock{DataSize: dataSize, Roothash: roothash},
		}); err != nil {
			return layers, err
		}
		layers = append(layers, laidOut{"pancake-modules", a.Kernel, "all", "pancake-modules"})
	}

	return layers, nil
}

// exportBzImage drops a copy of the kernel binary at a.BzImageOutPath so
// QEMU's `-kernel` arg can point at it without mounting the kit.
//
//   - If --bzimage was given: just copy that path to BzImageOutPath.
//   - Else: find /boot/vmlinuz-* in the sandbox (placed there by
//     linux-image-X.Y.Z's .deb extraction) and copy the newest one.
func exportBzImage(sandbox string, a bootstrapArgs) error {
	if a.BzImagePath != "" {
		return copyFileLocal(a.BzImagePath, a.BzImageOutPath)
	}
	bootDir := filepath.Join(sandbox, "boot")
	ents, err := os.ReadDir(bootDir)
	if err != nil {
		return fmt.Errorf("no /boot in sandbox (linux-image-generic "+
			"didn't install?): %w", err)
	}
	var newest string
	var newestMtime int64
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "vmlinuz-") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.ModTime().Unix() > newestMtime {
			newest = filepath.Join(bootDir, e.Name())
			newestMtime = fi.ModTime().Unix()
		}
	}
	if newest == "" {
		return fmt.Errorf("no vmlinuz-* in %s", bootDir)
	}
	return copyFileLocal(newest, a.BzImageOutPath)
}

// copyFileLocal copies src→dst using `install` so we can stamp ownership
// to the invoking user (unprivileged read access for QEMU).
func copyFileLocal(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return runner.Run(runner.Cmd{
		Argv: []string{"install", "-m", "0644", src, dst}, Sudo: true,
	})
}
