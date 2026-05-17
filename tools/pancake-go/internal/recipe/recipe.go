// Package recipe parses a YAML recipe file for `pancake bootstrap`.
//
// Layout (one canonical example, every field optional — `output`
// defaults to the current working directory and is overridable
// with `-o` / `--output` on the CLI):
//
//	output: /var/tmp/pancake-kit
//	hostname: pancake
//	builder: localhost:7879
//	packages:
//	  - openssh-server
//	  - chrony
//
//	distro:
//	  suite: noble
//	  mirror: http://archive.ubuntu.com/ubuntu/
//
//	ssh:
//	  authorized-keys: /home/foo/.ssh/authorized_keys
//	  host-keys-dir: ""    # empty → generate fresh
//
//	kernel:
//	  version: "7.0.0-g..."   # default uname -r; "tree"/"local" → read
//	                          # the version out of `bzimage` below
//	  bzimage: /path/to/bzImage   # empty → suite linux-image-generic
//	  cmdline: console=ttyS0 rdinit=/init pancake.state=LABEL=PANCAKE_STATE
//
//	outputs:
//	  image:     ./pancake-state.img
//	  initramfs: ./pancake-initramfs.cpio.gz
//	  bzimage:   ./pancake-bzImage
//	  efi:       ""           # empty → skip EFI disk
//
// Resolution rules:
//   - All paths in the recipe are interpreted relative to the current
//     working directory (NOT relative to the recipe file). `~` is
//     expanded to $HOME.
//   - CLI flags override recipe values: precedence is flag > recipe >
//     internal default. The bootstrap dispatcher uses flag.Visit() to
//     detect which flags the user actually set.
//   - Unknown YAML keys cause a parse error (catches typos).
package recipe

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Recipe mirrors the YAML schema. All fields are pointers OR slices so we
// can distinguish "not specified" (nil/empty) from "explicitly set to
// zero" — only "not specified" defers to flag/default.
type Recipe struct {
	Output   string   `yaml:"output"`
	Hostname string   `yaml:"hostname"`
	Packages []string `yaml:"packages"`

	// Platform specifies the deployment target: "self-hosted" (default),
	// "gce", "azure", "aws". Affects TPM backend, metadata sources, and
	// image format. Can be overridden by PANCAKE_PLATFORM env var or
	// --platform CLI flag.
	Platform string `yaml:"platform"`

	// Builder is the address of the pancake-build-server that will
	// assemble the kit (e.g. "localhost:7879"). The CLI's --builder
	// flag overrides this. Required: with no value from either
	// source, `pancake bootstrap` exits with an error — the local
	// build path is gone, "build offline" means run the build
	// server locally via the compose stack.
	Builder string `yaml:"builder"`

	Distro       Distro       `yaml:"distro"`
	SSH          SSH          `yaml:"ssh"`
	Kernel       Kernel       `yaml:"kernel"`
	Outputs      Outputs      `yaml:"outputs"`
	Orchestrator Orchestrator `yaml:"orchestrator"`
	GCE          GCE          `yaml:"gce"`
}

// Orchestrator declares the single endpoint of the orchestrator
// gateway. The build server expands this URL into the per-protocol
// paths the VM uses (URL/acme/tpm/directory for ACME-tpm,
// URL/attest-ca for AK enrollment), and bakes the trust root for
// the gateway's TLS cert — read from the build server's local
// trust volume, NOT from the recipe — into the signed verity layer
// at /etc/pancake/orch/ inside the running VM. Empty URL = no
// orch-config layer is built.
type Orchestrator struct {
	// CAURL is the step-ca ACME endpoint the VM hits to enroll its
	// TLS cert (e.g. https://10.0.2.2:8443/acme/tpm/directory).
	CAURL string `yaml:"ca-url"`
	// AttestCAURL is the pancake-attest-ca base URL the VM hits to
	// enroll its AK before the ACME order (e.g.
	// https://10.0.2.2:8444). Both must be reachable from inside
	// the VM at boot time.
	//
	// For QEMU/usernet that's typically https://10.0.2.2:<port>
	// and the host forwards the docker-published ports.
	AttestCAURL string `yaml:"attest-ca-url"`
}

type Distro struct {
	Suite  string `yaml:"suite"`
	Mirror string `yaml:"mirror"`
}

type SSH struct {
	AuthorizedKeys string `yaml:"authorized-keys"`
	HostKeysDir    string `yaml:"host-keys-dir"`
}

type Kernel struct {
	Version     string `yaml:"version"`
	BzImage     string `yaml:"bzimage"`
	Cmdline     string `yaml:"cmdline"`
	SkipModules bool   `yaml:"skip-modules"` // Skip modules upload (useful for kernel-only testing)
}

type Outputs struct {
	// Image is the rootfs ext4 disk; corresponds to bootstrap --image.
	Image string `yaml:"image"`
	// Initramfs is the cpio.gz blob; corresponds to --initramfs.
	Initramfs string `yaml:"initramfs"`
	// BzImage is the kernel binary copy for QEMU's -kernel arg;
	// corresponds to --bzimage-out (NOT --bzimage which is the input).
	BzImage string `yaml:"bzimage"`
	// EFI is the UEFI-bootable disk; corresponds to --efi.
	EFI string `yaml:"efi"`
}

// GCE holds Google Cloud-specific configuration (when platform: gce).
type GCE struct {
	Project         string `yaml:"project"`
	Zone            string `yaml:"zone"`
	ImageFamily     string `yaml:"image-family"`
	MachineType     string `yaml:"machine-type"`
	EnableVTPM      bool   `yaml:"enable-vtpm"`
	EnableSecureBoot bool  `yaml:"enable-secure-boot"`
	FleetServer     string `yaml:"fleet-server"` // Fleet orchestrator URL for auto-enrollment
}

// Load reads + parses a recipe file. Strict mode: unknown YAML keys
// cause a parse error so typos are caught early.
func Load(path string) (*Recipe, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read recipe: %w", err)
	}
	var r Recipe
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	r.expandPaths()
	return &r, nil
}

// expandPaths runs ExpandPath over every string field that's a filesystem
// path, so recipes can use ~/foo without bash expansion.
func (r *Recipe) expandPaths() {
	for _, p := range []*string{
		&r.Output,
		&r.SSH.AuthorizedKeys, &r.SSH.HostKeysDir,
		&r.Kernel.BzImage,
		&r.Outputs.Image, &r.Outputs.Initramfs, &r.Outputs.BzImage, &r.Outputs.EFI,
	} {
		*p = ExpandPath(*p)
	}
}

// ExpandPath expands a leading "~" to the invoking user's home. Stays a
// no-op for paths without that prefix (including absolute and relative
// paths). Bootstrap is typically run via sudo, so prefer SUDO_USER's
// home over $HOME (which sudo flips to /root) — almost no recipe
// author writing "~" means root's home.
func ExpandPath(p string) string {
	if p == "" || !strings.HasPrefix(p, "~") {
		return p
	}
	home := userHome()
	if home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	// Other forms ("~user/...") are not supported; leave as-is.
	return p
}

func userHome() string {
	if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
		if usr, err := user.Lookup(u); err == nil {
			return usr.HomeDir
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return ""
}

// DefaultRecipePath is the file pancake bootstrap auto-loads if no
// positional recipe arg is given and the file exists.
const DefaultRecipePath = "./pancake-recipe.yaml"
