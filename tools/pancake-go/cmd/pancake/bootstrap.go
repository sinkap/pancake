// `pancake bootstrap`: dial a pancake-build-server, hand it the
// recipe + uploaded blobs, receive the assembled artifacts.
//
// All build steps (mmdebstrap, per-package layer extraction,
// pancake-host / pancake-runtime / pancaked / kernel / modules /
// orch-config layer assembly, disk pack, initramfs build, UKI
// signing, EFI disk pack) live server-side now. The CLI is a thin
// orchestrator: parse recipe → upload blobs → call the server →
// stream artifacts back.
//
// "I want to build offline" → run the server locally via the
// compose stack (tools/pancake-go/compose.yaml).
//
// Today the server-side endpoint that does the full assembly is
// reachable as Server.AssembleImage; the BuildImage gRPC RPC that
// wraps it lands once `protoc` regenerates internal/buildpb (see
// tools/pancake-go/HACKING.md). Until that regen, the client still
// post-processes layers locally — the pack* helpers in this file
// stay around to support that interim.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/layer"
	"github.com/sinkap/pancake/tools/pancake-go/internal/recipe"
	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"
	"github.com/sinkap/pancake/tools/pancake-go/internal/sign"
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
	"netbase",
	// ca-certificates intentionally NOT in baseline: nothing in
	// pancake-os validates TLS against the public CA store. Trust
	// model is the kit's own signing key (baked at
	// /etc/pancake/manifest.pubkey), TPM-sealed bearer tokens for
	// orchestrator auth, and authorized_keys for SSH. Re-add only
	// when a future feature needs to verify a public TLS endpoint.
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
	out := fs.String("output", ".", "kit output directory")
	fs.StringVar(out, "o", ".", "shorthand for --output")
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
	pancakedBin := fs.String("pancaked-bin", "",
		"path to the pancaked binary to bake as a separate verity layer. "+
			"Default: sibling of --pancake-bin / this executable. The layer "+
			"includes /usr/sbin/pancaked + the systemd unit so the daemon "+
			"auto-starts at boot.")
	builder := fs.String("builder", "",
		"address of a pancake-build-server (e.g. localhost:7879). "+
			"Required — overrides `builder:` in the recipe. The local "+
			"build path is gone; \"build offline\" means run the build "+
			"server locally via the compose stack.")

	// One optional positional: a recipe YAML path. If absent, look for
	// ./pancake-recipe.yaml; if THAT's absent, fall back to flag-only.
	if err := fs.Parse(args); err != nil {
		return 2
	}
	recipePath := fs.Arg(0)
	if recipePath == "" {
		if _, err := os.Stat(recipe.DefaultRecipePath); err == nil {
			recipePath = recipe.DefaultRecipePath
			fmt.Fprintf(os.Stderr,
				"[bootstrap] using default recipe %s (override with positional arg)\n",
				recipePath)
		}
	}

	// CLI flags override recipe values. fs.Visit reports flags actually
	// set by the user (NOT defaulted), so we know whose values to keep.
	flagSet := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { flagSet[f.Name] = true })
	// `-o` is a shorthand for `--output`; collapse so the recipe-
	// precedence check doesn't think the user "didn't set" output
	// when they actually passed `-o`.
	if flagSet["o"] {
		flagSet["output"] = true
	}

	var orch OrchArgs
	if recipePath != "" {
		r, err := recipe.Load(recipePath)
		if err != nil {
			return die(fmt.Errorf("recipe %s: %w", recipePath, err))
		}
		applyRecipeDefaults(r, flagSet,
			suite, mirror, pkgs, out, hostname, keepSandbox,
			sshHostKeys, sshAuthKeys, pancakeBin, pancakedBin, srcRoot,
			image, initramfsPath, kernel, bzimage, bzimageOut,
			efiOut, cmdline, signKey, signCert, builder)
		orch = OrchArgs{
			StepCARoot:   r.Orchestrator.StepCARoot,
			AhkcidRoot:   r.Orchestrator.AhkcidRoot,
			ClientCARoot: r.Orchestrator.ClientCARoot,
			CAURL:        r.Orchestrator.CAURL,
			AttestCAURL:  r.Orchestrator.AttestCAURL,
		}
	}

	// Sentinel kernel versions: "tree" / "local" mean "read it out of
	// --bzimage" — handy in recipes that pin a kernel tree but don't
	// want to repeat the version string.
	if *kernel == "tree" || *kernel == "local" {
		if *bzimage == "" {
			return die(fmt.Errorf(
				"--kernel=%s requires --bzimage to be set", *kernel))
		}
		v, err := extractBzImageVersion(*bzimage)
		if err != nil {
			return die(fmt.Errorf("extract version from %s: %w", *bzimage, err))
		}
		fmt.Fprintf(os.Stderr,
			"[bootstrap] --kernel=%s → %s (from %s)\n", *kernel, v, *bzimage)
		*kernel = v
	}

	if *pkgs == "" {
		fmt.Fprintln(os.Stderr,
			"usage:\n"+
				"  pancake bootstrap [recipe.yaml] [--flag=value ...]\n"+
				"  pancake bootstrap --packages a,b,c [-o DIR] [other flags]\n"+
				"\n"+
				"recipe is auto-loaded from ./pancake-recipe.yaml if present.\n"+
				"output defaults to the current directory; override with -o / --output.")
		return 2
	}
	if *builder == "" {
		return die(fmt.Errorf(
			"--builder is required (or set `builder:` in the recipe). " +
				"To build offline, run the build server locally — see " +
				"tools/pancake-go/compose.yaml."))
	}

	fmt.Fprintf(os.Stderr,
		"[bootstrap] resolved: output=%s hostname=%s suite=%s kernel=%s\n",
		*out, *hostname, *suite, *kernel)

	if err := bootstrapViaBuilder(bootstrapArgs{
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
		PancakedBin:     *pancakedBin,
		BuilderAddr:     *builder,
		Orch:            orch,
	}); err != nil {
		return die(err)
	}
	return 0
}

// applyRecipeDefaults overrides any string/bool flag value that the user
// did NOT explicitly set on the command line with the corresponding value
// from the recipe (if non-empty). Precedence: CLI flag > recipe > flag's
// own default.
//
// 21 flags = 21 lines of explicit if-then. Verbose but unambiguous; a
// reflection-based version would obscure the precedence rule.
func applyRecipeDefaults(r *recipe.Recipe, flagSet map[string]bool,
	suite, mirror, pkgs, out, hostname *string, keepSandbox *bool,
	sshHostKeys, sshAuthKeys, pancakeBin, pancakedBin, srcRoot *string,
	image, initramfsPath, kernel, bzimage, bzimageOut, efiOut,
	cmdline, signKey, signCert, builder *string) {
	set := func(name, recipeVal string, dst *string) {
		if !flagSet[name] && recipeVal != "" {
			*dst = recipeVal
		}
	}
	setBool := func(name string, recipeVal bool, dst *bool) {
		if !flagSet[name] && recipeVal {
			*dst = recipeVal
		}
	}

	// Top-level
	set("output", r.Output, out)
	set("hostname", r.Hostname, hostname)
	set("builder", r.Builder, builder)
	if !flagSet["packages"] && len(r.Packages) > 0 {
		*pkgs = strings.Join(r.Packages, ",")
	}

	// [distro]
	set("suite", r.Distro.Suite, suite)
	set("mirror", r.Distro.Mirror, mirror)

	// [ssh]
	set("ssh-authorized-keys", r.SSH.AuthorizedKeys, sshAuthKeys)
	set("ssh-host-keys", r.SSH.HostKeysDir, sshHostKeys)

	// [kernel]
	set("kernel", r.Kernel.Version, kernel)
	set("bzimage", r.Kernel.BzImage, bzimage)
	set("cmdline", r.Kernel.Cmdline, cmdline)

	// [outputs]
	set("image", r.Outputs.Image, image)
	set("initramfs", r.Outputs.Initramfs, initramfsPath)
	set("bzimage-out", r.Outputs.BzImage, bzimageOut)
	set("efi", r.Outputs.EFI, efiOut)

	// [signing]
	set("sign-key", r.Signing.Key, signKey)
	set("sign-cert", r.Signing.Cert, signCert)

	// [advanced]
	setBool("keep-sandbox", r.Advanced.KeepSandbox, keepSandbox)
	set("src-root", r.Advanced.SrcRoot, srcRoot)
	set("pancake-bin", r.Advanced.PancakeBin, pancakeBin)
	set("pancaked-bin", r.Advanced.PancakedBin, pancakedBin)
}

// extractBzImageVersion reads the version string embedded in an x86
// bzImage. The setup header at byte 0x20E holds a u16 whose value plus
// 0x200 is the file offset of a NUL-terminated version string of the
// form "<release> (<builder>@<host>) #N SMP ..." — we keep the first
// whitespace-delimited token. See Documentation/x86/boot.rst,
// kernel_version field.
func extractBzImageVersion(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var hdr [0x210]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return "", fmt.Errorf("read setup header: %w", err)
	}
	if string(hdr[0x202:0x206]) != "HdrS" {
		return "", fmt.Errorf("not a bzImage (no HdrS magic at 0x202)")
	}
	off := int64(binary.LittleEndian.Uint16(hdr[0x20E:0x210])) + 0x200
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return "", err
	}
	buf := make([]byte, 256)
	n, _ := f.Read(buf)
	end := n
	for i, c := range buf[:n] {
		if c == 0 || c == ' ' || c == '\t' || c == '\n' {
			end = i
			break
		}
	}
	if end == 0 {
		return "", fmt.Errorf("empty version string at offset 0x%x", off)
	}
	return string(buf[:end]), nil
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
	// PancakedBin: path to the pancaked daemon binary. If empty, defaults
	// to a sibling of PancakeBin (or this executable). Goes into its own
	// "pancaked" verity layer alongside the systemd unit.
	PancakedBin string
	// BuilderAddr: when non-empty, delegate per-package + base layer
	// building to this pancake-build-server over gRPC. See
	// bootstrap_builder.go for the alternate code path.
	BuilderAddr string

	// Orch: orchestrator-side trust anchors + URLs. When all required
	// fields are set, bootstrap builds a `pancake-orch-config` verity
	// layer carrying the CA roots + a JSON config readable by `pancake
	// enroll` and `pancaked` at /etc/pancake/orch/. Empty struct skips
	// the layer (Slice 1 fallback path).
	Orch OrchArgs
}

// OrchArgs mirrors recipe.Orchestrator. Pulled out into its own
// struct so the bootstrap helpers can pass it around without
// dragging the recipe package through every signature. Server-side
// the orch-config layer is built by bakeOrchConfig in the build
// server's recipes.go; the client uploads these as blobs.
type OrchArgs struct {
	StepCARoot   string
	AhkcidRoot   string
	ClientCARoot string
	CAURL        string
	AttestCAURL  string
}

// hasAll returns true when every required field is populated. The
// orch-config layer is only built when this is true; otherwise the
// VM falls back to the Slice 1 path (manually-delivered certs).
func (o OrchArgs) hasAll() bool {
	return o.StepCARoot != "" && o.AhkcidRoot != "" &&
		o.ClientCARoot != "" && o.CAURL != "" && o.AttestCAURL != ""
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

// signPubkeyFromCert is a tiny indirection so the bake step can call into
// internal/sign without growing the existing imports list ergonomics.
func signPubkeyFromCert(certPath, outPath string) error {
	return sign.PubkeyFromCert(certPath, outPath)
}

// packPancakedLayer synthesizes the "pancaked" verity layer: contains
// the daemon binary at /usr/sbin/pancaked plus a systemd unit that auto-
// starts it at boot. Lives in its own layer so the daemon is updatable
// independently of pancake-state and the rest of the kit.
//
// Where the binary comes from:
//   - --pancaked-bin if explicitly set
//   - else: sibling of --pancake-bin (or os.Executable() if the bootstrap
//     binary is `pancake` and pancaked is in the same dir, the typical
//     `go build -o ./bin/ ./cmd/...` layout)
//   - else: error with a clear message
//
// The systemd unit:
//   - Description, Documentation
//   - After=network-online.target, pancake-state-rw.service
//   - ExecStart=/usr/sbin/pancaked --tpm-token=auto (uses the sealed
//     token at /etc/pancake/orch-token.creds if `pancake enroll` has
//     been run; fails clearly otherwise)
//   - Restart=on-failure RestartSec=5
//   - WantedBy=multi-user.target (with the symlink already created in
//     the layer for first-boot enable)
func packPancakedLayer(tmp, repo string, layers []laidOut, a bootstrapArgs) ([]laidOut, error) {
	bin := a.PancakedBin
	if bin == "" {
		// Try sibling of --pancake-bin or the running executable.
		base := a.PancakeBin
		if base == "" {
			exe, err := os.Executable()
			if err != nil {
				return layers, fmt.Errorf("locate self for --pancaked-bin: %w", err)
			}
			base = exe
		}
		candidate := filepath.Join(filepath.Dir(base), "pancaked")
		if _, err := os.Stat(candidate); err != nil {
			return layers, fmt.Errorf(
				"--pancaked-bin not given and no sibling 'pancaked' next to %s "+
					"(build with: go build -o ./bin/ ./cmd/...)", base)
		}
		bin = candidate
	}
	if _, err := os.Stat(bin); err != nil {
		return layers, fmt.Errorf("--pancaked-bin: %w", err)
	}

	fmt.Fprintf(os.Stderr,
		"\n[bootstrap] packing pancaked layer (binary: %s)\n", bin)

	staging := filepath.Join(tmp, "_pancaked")
	sbinDir := filepath.Join(staging, "usr/sbin")
	unitDir := filepath.Join(staging, "etc/systemd/system")
	wantsDir := filepath.Join(unitDir, "multi-user.target.wants")
	for _, d := range []string{sbinDir, unitDir, wantsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return layers, err
		}
	}
	if err := copyFileLocal(bin, filepath.Join(sbinDir, "pancaked")); err != nil {
		return layers, err
	}
	if err := os.Chmod(filepath.Join(sbinDir, "pancaked"), 0o755); err != nil {
		return layers, err
	}

	const unit = `[Unit]
Description=pancake update daemon (orchestrator gRPC receiver)
Documentation=https://github.com/sinkap/pancake
After=pancake-state-rw.service
Requires=pancake-state-rw.service

[Service]
ExecStart=/usr/sbin/pancaked --tpm-token=auto
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(
		filepath.Join(unitDir, "pancaked.service"),
		[]byte(unit), 0o644); err != nil {
		return layers, err
	}
	// Pre-enable: the multi-user.target.wants symlink, so first boot
	// after install brings the unit up without `systemctl enable`.
	if err := os.Symlink(
		"/etc/systemd/system/pancaked.service",
		filepath.Join(wantsDir, "pancaked.service")); err != nil {
		return layers, err
	}

	pkgDir := filepath.Join(repo, "pancaked")
	if _, err := os.Stat(pkgDir); err == nil {
		_ = runner.Run(runner.Cmd{
			Argv: []string{"rm", "-rf", pkgDir}, Sudo: true,
		})
	}
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		return layers, err
	}
	roothash, dataSize, err := layer.MakeVerity(staging,
		filepath.Join(pkgDir, "image.img"), "pancaked", 0, "pancaked")
	if err != nil {
		return layers, err
	}
	if err := kit.WritePackageManifest(pkgDir, kit.PackageManifest{
		Package: kit.PackageBlock{
			Name: "pancaked", Version: "1.0.0", Arch: "all",
			Description: "pancake update daemon — gRPC receiver for orchestrator pushes",
		},
		Image: kit.ImageBlock{DataSize: dataSize, Roothash: roothash},
	}); err != nil {
		return layers, err
	}
	layers = append(layers, laidOut{"pancaked", "1.0.0", "all", "pancaked"})
	return layers, nil
}

// packPancakeRuntimeLayer ships pancake-os defaults that need to take
// effect on every boot but shouldn't pollute per-host or per-package
// layers. Contents:
//
//   /usr/local/bin/pancake                          ← --pancake-bin
//   /usr/sbin/mount-overlay                         ← compiled C
//   /usr/sbin/pivot-root                            ← compiled C
//   /usr/lib/systemd/system-generators/pancake-defaults
//   /etc/systemd/system/pancake-state-rw.service    + MUTW symlink
//   /etc/systemd/system/pancake-debug.service       + MUTW symlink
//   /etc/pancake/manifest.pubkey                    (when --sign-cert)
//
// Why a generator (not a static *.wants symlink in this layer):
// generators are systemd's native way to express "compute enables
// at boot time." They run before the unit tree is read, so their
// symlinks are honored on the first activation of multi-user.target
// — unlike a unit that calls `systemctl enable`, which only takes
// effect on the NEXT boot.
func packPancakeRuntimeLayer(tmp, repo string, layers []laidOut, a bootstrapArgs) ([]laidOut, error) {
	fmt.Fprintln(os.Stderr,
		"\n[bootstrap] packing pancake-runtime layer")

	staging := filepath.Join(tmp, "_pancake-runtime")
	sbinDir := filepath.Join(staging, "usr/sbin")
	binDir := filepath.Join(staging, "usr/local/bin")
	genDir := filepath.Join(staging, "usr/lib/systemd/system-generators")
	unitDir := filepath.Join(staging, "etc/systemd/system")
	wantsDir := filepath.Join(unitDir, "multi-user.target.wants")
	for _, d := range []string{sbinDir, binDir, genDir, unitDir, wantsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return layers, err
		}
	}

	// 1. systemd generator: enables systemd-networkd at boot.
	const generator = `#!/bin/sh
# pancake-defaults: systemd generator. Materializes default unit
# enables under /run/systemd/generator/ on every boot. Runs before
# systemd reads the unit tree, so its symlinks are honored on the
# first activation of multi-user.target.
#
# args: $1 normal-dir, $2 early-dir, $3 late-dir
set -e
ND="$1"
mkdir -p "$ND/multi-user.target.wants" "$ND/sockets.target.wants"
ln -sf /lib/systemd/system/systemd-networkd.service \
    "$ND/multi-user.target.wants/systemd-networkd.service"
ln -sf /lib/systemd/system/systemd-networkd.socket \
    "$ND/sockets.target.wants/systemd-networkd.socket"
exit 0
`
	if err := os.WriteFile(filepath.Join(genDir, "pancake-defaults"),
		[]byte(generator), 0o755); err != nil {
		return layers, err
	}

	// 2. mount-overlay + pivot-root: compile from src, install.
	srcRoot := a.SrcRoot
	if srcRoot == "" {
		if exe, err := os.Executable(); err == nil {
			srcRoot = filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(exe))))
		}
	}
	for _, pair := range []struct{ src, name string }{
		{filepath.Join(srcRoot, "initramfs/mount-overlay.c"), "mount-overlay"},
		{filepath.Join(srcRoot, "pivot-root.c"), "pivot-root"},
	} {
		if _, err := os.Stat(pair.src); err != nil {
			return layers, fmt.Errorf("missing source: %s "+
				"(use --src-root to override)", pair.src)
		}
		tmpBin := filepath.Join("/tmp", "_pancake-runtime-"+pair.name)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"cc", "-O2", "-Wall", "-Wextra", "-static",
				"-o", tmpBin, pair.src},
		}); err != nil {
			return layers, err
		}
		if err := copyFileLocal(tmpBin, filepath.Join(sbinDir, pair.name)); err != nil {
			return layers, err
		}
		if err := os.Chmod(filepath.Join(sbinDir, pair.name), 0o755); err != nil {
			return layers, err
		}
		_ = os.Remove(tmpBin)
	}

	// 3. pancake CLI binary.
	bin := a.PancakeBin
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return layers, fmt.Errorf("locate self: %w", err)
		}
		bin = exe
	}
	if _, err := os.Stat(bin); err != nil {
		return layers, fmt.Errorf("--pancake-bin: %w", err)
	}
	if err := copyFileLocal(bin, filepath.Join(binDir, "pancake")); err != nil {
		return layers, err
	}
	if err := os.Chmod(filepath.Join(binDir, "pancake"), 0o755); err != nil {
		return layers, err
	}

	// 4. systemd units: pancake-state-rw + pancake-debug, both
	// pre-enabled via the multi-user.target.wants symlinks shipped
	// in this layer.
	const stateRwUnit = `[Unit]
Description=Remount /var/lib/pancake read-write for pancake CLI
DefaultDependencies=no
ConditionPathIsMountPoint=/var/lib/pancake
After=local-fs.target
Before=multi-user.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/mount -o remount,rw /var/lib/pancake
[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(filepath.Join(unitDir, "pancake-state-rw.service"),
		[]byte(stateRwUnit), 0o644); err != nil {
		return layers, err
	}
	if err := os.Symlink(
		"/etc/systemd/system/pancake-state-rw.service",
		filepath.Join(wantsDir, "pancake-state-rw.service")); err != nil {
		return layers, err
	}

	const debugUnit = `[Unit]
Description=pancake-os end-of-boot diagnostic dump
DefaultDependencies=no
After=multi-user.target
[Service]
Type=oneshot
StandardOutput=journal+console
ExecStart=/bin/sh -c 'echo === PANCAKE DEBUG ===; echo --- ip ---; ip -4 addr 2>&1 | head -10; echo --- ss listening ---; ss -tlnp 2>&1 | head; echo --- ssh status ---; systemctl status ssh.socket ssh.service --no-pager -l 2>&1 | head -20; echo === END DEBUG ==='
[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(filepath.Join(unitDir, "pancake-debug.service"),
		[]byte(debugUnit), 0o644); err != nil {
		return layers, err
	}
	if err := os.Symlink(
		"/etc/systemd/system/pancake-debug.service",
		filepath.Join(wantsDir, "pancake-debug.service")); err != nil {
		return layers, err
	}

	// 5. Optional manifest pubkey for in-VM verification of pushed
	// generation manifests by `pancake` / pancaked.
	if a.SignCert != "" {
		etcPancake := filepath.Join(staging, "etc/pancake")
		if err := os.MkdirAll(etcPancake, 0o755); err != nil {
			return layers, err
		}
		tmpPub := filepath.Join("/tmp", "_pancake-runtime-pubkey.pem")
		if err := signPubkeyFromCert(a.SignCert, tmpPub); err != nil {
			return layers, err
		}
		defer os.Remove(tmpPub)
		if err := copyFileLocal(tmpPub,
			filepath.Join(etcPancake, "manifest.pubkey")); err != nil {
			return layers, err
		}
	}

	pkgDir := filepath.Join(repo, "pancake-runtime")
	if _, err := os.Stat(pkgDir); err == nil {
		_ = runner.Run(runner.Cmd{
			Argv: []string{"rm", "-rf", pkgDir}, Sudo: true,
		})
	}
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		return layers, err
	}
	roothash, dataSize, err := layer.MakeVerity(staging,
		filepath.Join(pkgDir, "image.img"), "pancake-runtime", 0,
		"pancake-runtime")
	if err != nil {
		return layers, err
	}
	if err := kit.WritePackageManifest(pkgDir, kit.PackageManifest{
		Package: kit.PackageBlock{
			Name: "pancake-runtime", Version: "1.0.0", Arch: "all",
			Description: "pancake-os runtime defaults (systemd generator + boot-time policy)",
		},
		Image: kit.ImageBlock{DataSize: dataSize, Roothash: roothash},
	}); err != nil {
		return layers, err
	}
	layers = append(layers, laidOut{"pancake-runtime", "1.0.0", "all", "pancake-runtime"})
	return layers, nil
}

// isPerHostPath reports whether p is a path that should live exclusively
// in the pancake-host layer. Used to filter both per-package staging
// (so packages don't include host-specific content in their roothash)
// and the pancake-state orphan loop (so postinst-generated ssh host
// keys don't end up in pancake-state). The matching set is small and
// path-prefix; if you add anything here, add the corresponding write
// to packPancakeHostLayer.
func isPerHostPath(p string) bool {
	switch p {
	case "/etc/hostname",
		"/root/.ssh",
		"/root/.ssh/authorized_keys":
		return true
	}
	return strings.HasPrefix(p, "/etc/ssh/ssh_host_")
}

// packPancakeHostLayer synthesizes the per-host verity layer: hostname,
// ssh host keys, root authorized_keys. Produced fresh from the recipe /
// CLI args — never sourced from the mmdebstrap sandbox — so the rest of
// the kit is bit-identical across machines that bootstrap from the same
// recipe.
//
// Path → source:
//
//	/etc/hostname                        → a.Hostname
//	/etc/ssh/ssh_host_*_key{,.pub}       → a.SSHHostKeysDir, else generated
//	/root/.ssh/                          → mode 0700 (always)
//	/root/.ssh/authorized_keys           → a.SSHAuthKeysFile (skipped if empty)
//
// The layer sits at the very top of the overlay stack so its files win
// over base-files' /etc/hostname and any keys openssh-server's postinst
// may have generated into the per-package layer.
func packPancakeHostLayer(tmp, repo string, layers []laidOut, a bootstrapArgs) ([]laidOut, error) {
	fmt.Fprintln(os.Stderr,
		"\n[bootstrap] packing pancake-host layer (hostname + ssh identity)")

	staging := filepath.Join(tmp, "_pancake-host")
	etcSSH := filepath.Join(staging, "etc/ssh")
	rootSSH := filepath.Join(staging, "root/.ssh")
	for _, d := range []string{filepath.Join(staging, "etc"), etcSSH, rootSSH} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return layers, err
		}
	}
	// /root and /root/.ssh need 0700 so sshd accepts authorized_keys.
	if err := os.Chmod(filepath.Join(staging, "root"), 0o700); err != nil {
		return layers, err
	}
	if err := os.Chmod(rootSSH, 0o700); err != nil {
		return layers, err
	}

	// /etc/hostname (always — there's a default of "pancake").
	hostname := a.Hostname
	if hostname == "" {
		hostname = "pancake"
	}
	if err := os.WriteFile(filepath.Join(staging, "etc/hostname"),
		[]byte(hostname+"\n"), 0o644); err != nil {
		return layers, err
	}
	fmt.Fprintf(os.Stderr, "  hostname → %s\n", hostname)

	// SSH host keys: copy from --ssh-host-keys, else generate fresh.
	if a.SSHHostKeysDir != "" {
		fmt.Fprintf(os.Stderr, "  ssh host keys ← %s\n", a.SSHHostKeysDir)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"sh", "-c",
				fmt.Sprintf("cp -a %s/ssh_host_* %s/",
					a.SSHHostKeysDir, etcSSH)},
		}); err != nil {
			return layers, err
		}
	} else {
		fmt.Fprintf(os.Stderr, "  generating fresh ssh host keys\n")
		for _, kt := range []string{"rsa", "ecdsa", "ed25519"} {
			kf := filepath.Join(etcSSH, "ssh_host_"+kt+"_key")
			if err := runner.Run(runner.Cmd{
				Argv: []string{"ssh-keygen", "-q", "-N", "", "-t", kt, "-f", kf},
			}); err != nil {
				return layers, err
			}
		}
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"sh", "-c",
			fmt.Sprintf("chmod 600 %s/ssh_host_*_key && chmod 644 %s/ssh_host_*_key.pub",
				etcSSH, etcSSH)},
	}); err != nil {
		return layers, err
	}

	// /root/.ssh/authorized_keys (only when --ssh-authorized-keys set).
	if a.SSHAuthKeysFile != "" {
		if fi, err := os.Stat(a.SSHAuthKeysFile); err != nil || fi.IsDir() {
			return layers, fmt.Errorf("--ssh-authorized-keys: not a file: %s",
				a.SSHAuthKeysFile)
		}
		fmt.Fprintf(os.Stderr, "  /root/.ssh/authorized_keys ← %s\n",
			a.SSHAuthKeysFile)
		if err := copyFileLocal(a.SSHAuthKeysFile,
			filepath.Join(rootSSH, "authorized_keys")); err != nil {
			return layers, err
		}
		if err := os.Chmod(filepath.Join(rootSSH, "authorized_keys"),
			0o600); err != nil {
			return layers, err
		}
	}

	// /etc/ssh/sshd_config: pancake-os baseline. The .deb-shipped one
	// is a debconf stub we don't want; openssh-server's sshd_config.d/*
	// is NOT included unless we write the include line ourselves.
	const sshdConf = `# /etc/ssh/sshd_config — pancake-os baseline (pancake-host layer)
Port 22
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication no
UsePAM no
UseDNS no
GSSAPIAuthentication no
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
`
	if err := os.WriteFile(filepath.Join(etcSSH, "sshd_config"),
		[]byte(sshdConf), 0o644); err != nil {
		return layers, err
	}

	// /etc/resolv.conf: hardcoded for QEMU's user-mode-net DNS.
	if err := os.WriteFile(filepath.Join(staging, "etc/resolv.conf"),
		[]byte("nameserver 10.0.2.3\n"), 0o644); err != nil {
		return layers, err
	}

	// /etc/systemd/network/10-wired.network: DHCP via systemd-networkd.
	netDir := filepath.Join(staging, "etc/systemd/network")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		return layers, err
	}
	if err := os.WriteFile(filepath.Join(netDir, "10-wired.network"),
		[]byte("[Match]\nType=ether\n[Network]\nDHCP=yes\n"), 0o644); err != nil {
		return layers, err
	}

	// systemd-networkd's wants symlinks are created at boot by /init
	// in the tmpfs upper — see initramfs/init's "default enables"
	// block. Keeps pancake-host purely about identity, not policy.

	pkgDir := filepath.Join(repo, "pancake-host")
	if _, err := os.Stat(pkgDir); err == nil {
		_ = runner.Run(runner.Cmd{
			Argv: []string{"rm", "-rf", pkgDir}, Sudo: true,
		})
	}
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		return layers, err
	}
	roothash, dataSize, err := layer.MakeVerity(staging,
		filepath.Join(pkgDir, "image.img"), "pancake-host", 0, "pancake-host")
	if err != nil {
		return layers, err
	}
	if err := kit.WritePackageManifest(pkgDir, kit.PackageManifest{
		Package: kit.PackageBlock{
			Name: "pancake-host", Version: "1.0.0", Arch: "all",
			Description: "per-host identity (hostname, ssh keys, authorized_keys)",
		},
		Image: kit.ImageBlock{DataSize: dataSize, Roothash: roothash},
	}); err != nil {
		return layers, err
	}
	layers = append(layers, laidOut{"pancake-host", "1.0.0", "all", "pancake-host"})
	return layers, nil
}

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
