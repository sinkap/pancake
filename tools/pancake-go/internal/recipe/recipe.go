// Package recipe parses a TOML recipe file for `pancake bootstrap`.
//
// Layout (one canonical example, with everything optional except
// `output`):
//
//	output   = "/var/tmp/pancake-kit"
//	hostname = "pancake"
//	packages = ["openssh-server", "chrony"]
//
//	[distro]
//	suite  = "noble"
//	mirror = "http://archive.ubuntu.com/ubuntu/"
//
//	[ssh]
//	authorized-keys = "/home/foo/.ssh/authorized_keys"
//	host-keys-dir   = ""    # empty → generate fresh
//
//	[kernel]
//	version = "7.0.0-g..."  # default uname -r; "tree"/"local" → read
//	                        # the version out of `bzimage` below
//	bzimage = "/path/to/bzImage"   # empty → suite linux-image-generic
//	cmdline = "console=ttyS0 rdinit=/init pancake.state=LABEL=PANCAKE_STATE"
//
//	[outputs]
//	image     = "./pancake-state.img"
//	initramfs = "./pancake-initramfs.cpio.gz"
//	bzimage   = "./pancake-bzImage"
//	efi       = ""          # empty → skip EFI disk
//
//	[signing]
//	key  = "./pancake-dev.key"
//	cert = "./pancake-dev.crt"
//
//	[advanced]
//	keep-sandbox = false
//	src-root     = ""
//	pancake-bin  = ""       # default sibling of running executable
//	pancaked-bin = ""       # default sibling
//
// Resolution rules:
//   - All paths in the recipe are interpreted relative to the current
//     working directory (NOT relative to the recipe file). `~` is
//     expanded to $HOME.
//   - CLI flags override recipe values: precedence is flag > recipe >
//     internal default. The bootstrap dispatcher uses flag.Visit() to
//     detect which flags the user actually set.
//   - Unknown TOML keys cause a parse error (catches typos).
package recipe

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Recipe mirrors the TOML schema. All fields are pointers OR slices so we
// can distinguish "not specified" (nil/empty) from "explicitly set to
// zero" — only "not specified" defers to flag/default.
type Recipe struct {
	Output   string   `toml:"output"`
	Hostname string   `toml:"hostname"`
	Packages []string `toml:"packages"`

	Distro   Distro   `toml:"distro"`
	SSH      SSH      `toml:"ssh"`
	Kernel   Kernel   `toml:"kernel"`
	Outputs  Outputs  `toml:"outputs"`
	Signing  Signing  `toml:"signing"`
	Advanced Advanced `toml:"advanced"`
}

type Distro struct {
	Suite  string `toml:"suite"`
	Mirror string `toml:"mirror"`
}

type SSH struct {
	AuthorizedKeys string `toml:"authorized-keys"`
	HostKeysDir    string `toml:"host-keys-dir"`
}

type Kernel struct {
	Version string `toml:"version"`
	BzImage string `toml:"bzimage"`
	Cmdline string `toml:"cmdline"`
}

type Outputs struct {
	// Image is the rootfs ext4 disk; corresponds to bootstrap --image.
	Image string `toml:"image"`
	// Initramfs is the cpio.gz blob; corresponds to --initramfs.
	Initramfs string `toml:"initramfs"`
	// BzImage is the kernel binary copy for QEMU's -kernel arg;
	// corresponds to --bzimage-out (NOT --bzimage which is the input).
	BzImage string `toml:"bzimage"`
	// EFI is the UEFI-bootable disk; corresponds to --efi.
	EFI string `toml:"efi"`
}

type Signing struct {
	Key  string `toml:"key"`
	Cert string `toml:"cert"`
}

type Advanced struct {
	KeepSandbox bool   `toml:"keep-sandbox"`
	SrcRoot     string `toml:"src-root"`
	PancakeBin  string `toml:"pancake-bin"`
	PancakedBin string `toml:"pancaked-bin"`
}

// Load reads + parses a recipe file. Strict mode: unknown TOML keys
// cause a parse error so typos are caught early.
func Load(path string) (*Recipe, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read recipe: %w", err)
	}
	var r Recipe
	dec := toml.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
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
		&r.Signing.Key, &r.Signing.Cert,
		&r.Advanced.SrcRoot, &r.Advanced.PancakeBin, &r.Advanced.PancakedBin,
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
const DefaultRecipePath = "./pancake-recipe.toml"
