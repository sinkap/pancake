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
	"strings"
	"syscall"

	"github.com/sinkap/pancake/tools/pancake-go/internal/hoststate"
	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/recipe"
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
	// Resolve hoststate defaults (ignore error; flags can override)
	var builderDefault string
	if paths, err := hoststate.Resolve(); err == nil {
		builderDefault = paths.BuilderAddr
	}

	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	suite := fs.String("suite", "noble", "Debian/Ubuntu suite")
	mirror := fs.String("mirror",
		"http://archive.ubuntu.com/ubuntu/", "apt mirror URL")
	pkgs := fs.String("packages", "",
		"comma-separated extra packages on top of the system baseline")
	out := fs.String("output", ".", "kit output directory")
	fs.StringVar(out, "o", ".", "shorthand for --output")
	hostname := fs.String("hostname", "pancake", "/etc/hostname")
	sshHostKeys := fs.String("ssh-host-keys", "",
		"dir with ssh_host_*_key files (else generate fresh)")
	sshAuthKeys := fs.String("ssh-authorized-keys", "",
		"file installed at /root/.ssh/authorized_keys")
	image := fs.String("image", "./pancake-state.img",
		"pack the kit into an ext4 disk image at this path; empty to skip")
	initramfsPath := fs.String("initramfs", "./pancake-initramfs.cpio.gz",
		"build the manifest-driven initramfs at this path; empty to skip")
	kernel := fs.String("kernel", currentKVer(),
		"kernel VERSION under /lib/modules/<--kernel> whose modules get baked "+
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
	builder := fs.String("builder", builderDefault,
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
	var skipModules bool
	if recipePath != "" {
		r, err := recipe.Load(recipePath)
		if err != nil {
			return die(fmt.Errorf("recipe %s: %w", recipePath, err))
		}
		applyRecipeDefaults(r, flagSet,
			suite, mirror, pkgs, out, hostname,
			sshHostKeys, sshAuthKeys,
			image, initramfsPath, kernel, bzimage, bzimageOut,
			efiOut, cmdline, builder)

		// Auto-detect orchestrator URLs from environment if not in recipe
		caURL := r.Orchestrator.CAURL
		attestCAURL := r.Orchestrator.AttestCAURL

		if caURL == "" {
			if paths, err := hoststate.Resolve(); err == nil {
				caURL = paths.CAURL
			}
		}
		if attestCAURL == "" {
			if paths, err := hoststate.Resolve(); err == nil {
				attestCAURL = paths.AttestCAURL
			}
		}

		orch = OrchArgs{
			CAURL:       caURL,
			AttestCAURL: attestCAURL,
		}

		// Capture skip-modules flag from recipe
		skipModules = r.Kernel.SkipModules
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
		SSHHostKeysDir:  *sshHostKeys,
		SSHAuthKeysFile: *sshAuthKeys,
		ImagePath:       *image,
		InitramfsPath:   *initramfsPath,
		Kernel:          *kernel,
		BzImagePath:     *bzimage,
		BzImageOutPath:  *bzimageOut,
		EFIPath:         *efiOut,
		Cmdline:         *cmdline,
		BuilderAddr:     *builder,
		Orch:            orch,
		SkipModules:     skipModules,
	}); err != nil {
		return die(err)
	}
	return 0
}

// applyRecipeDefaults overrides any flag value that the user did NOT
// explicitly set on the command line with the corresponding value
// from the recipe (if non-empty). Precedence: CLI flag > recipe >
// flag's own default.
func applyRecipeDefaults(r *recipe.Recipe, flagSet map[string]bool,
	suite, mirror, pkgs, out, hostname *string,
	sshHostKeys, sshAuthKeys *string,
	image, initramfsPath, kernel, bzimage, bzimageOut, efiOut,
	cmdline, builder *string) {
	set := func(name, recipeVal string, dst *string) {
		if !flagSet[name] && recipeVal != "" {
			*dst = recipeVal
		}
	}

	set("output", r.Output, out)
	set("hostname", r.Hostname, hostname)
	set("builder", r.Builder, builder)
	if !flagSet["packages"] && len(r.Packages) > 0 {
		*pkgs = strings.Join(r.Packages, ",")
	}

	set("suite", r.Distro.Suite, suite)
	set("mirror", r.Distro.Mirror, mirror)

	set("ssh-authorized-keys", r.SSH.AuthorizedKeys, sshAuthKeys)
	set("ssh-host-keys", r.SSH.HostKeysDir, sshHostKeys)

	set("kernel", r.Kernel.Version, kernel)
	set("bzimage", r.Kernel.BzImage, bzimage)
	set("cmdline", r.Kernel.Cmdline, cmdline)

	set("image", r.Outputs.Image, image)
	set("initramfs", r.Outputs.Initramfs, initramfsPath)
	set("bzimage-out", r.Outputs.BzImage, bzimageOut)
	set("efi", r.Outputs.EFI, efiOut)
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
	// SkipModules: when true, don't upload modules layer (useful for kernel-only testing)
	SkipModules bool
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

// OrchArgs mirrors recipe.Orchestrator.
//
// Unified CA mode (recommended): CAURL only
//   VMs get AK certs locally from dev EK CA
//
// Legacy dual-CA mode: CAURL + AttestCAURL
//   VMs call separate attestation CA for AK certs
type OrchArgs struct {
	CAURL       string
	AttestCAURL string
}

// hasURLs reports whether orchestrator URLs were provided.
// Only CAURL is required; AttestCAURL is optional (unified CA mode).
func (o OrchArgs) hasURLs() bool {
	return o.CAURL != ""
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

