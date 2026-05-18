// Package deb wraps dpkg/dpkg-query/dpkg-deb for the pancake build path.
// Mirrors the helpers in pancake_lib.py: deb_metadata, dpkg_query,
// installed_packages, package_field, package_files (with usrmerge
// canonicalization), stage_files, slugify_version, parse_depends.
package deb

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"
)

// SlugifyVersion reduces a Debian version to chars safe for dm-mapper device
// names AND TOML tags: keep [A-Za-z0-9._-], replace anything else with '_'.
// Identical to pancake_lib.slugify_version.
func SlugifyVersion(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		switch {
		case r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// ParseDepends splits a Depends: field into individual deps (alternatives
// and version constraints kept verbatim — caller decides whether to strip).
func ParseDepends(field string) []string {
	if field == "" {
		return nil
	}
	parts := strings.Split(field, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// FileSHA256 returns the lowercase hex digest of a file. Used for manifest
// provenance.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// Metadata is the parsed output of `dpkg-deb -f <foo.deb> Package Version
// Architecture Description Depends Pre-Depends`.
type Metadata struct {
	Package     string
	Version     string
	Arch        string
	Description string
	Depends     string
	PreDepends  string
}

// ReadDebMetadata invokes dpkg-deb. We follow the python parser: a
// continuation line (starts with space) is appended to the previous field
// for everything except Description (which is multi-line by design and we
// only ever want the synopsis anyway).
func ReadDebMetadata(deb string) (Metadata, error) {
	out, err := runner.Capture(runner.Cmd{
		Argv: []string{"dpkg-deb", "-f", deb,
			"Package", "Version", "Architecture", "Description",
			"Depends", "Pre-Depends"},
	})
	if err != nil {
		return Metadata{}, err
	}
	fields := map[string]string{}
	cur := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, " ") && cur != "" {
			if cur != "Description" {
				fields[cur] += " " + strings.TrimSpace(line)
			}
			continue
		}
		if i := strings.Index(line, ":"); i >= 0 {
			cur = strings.TrimSpace(line[:i])
			fields[cur] = strings.TrimSpace(line[i+1:])
		}
	}
	return Metadata{
		Package:     fields["Package"],
		Version:     fields["Version"],
		Arch:        fields["Architecture"],
		Description: fields["Description"],
		Depends:     fields["Depends"],
		PreDepends:  fields["Pre-Depends"],
	}, nil
}

// query runs `dpkg-query --admindir=<sandbox>/var/lib/dpkg <args...>`. All
// other dpkg-query helpers here go through this so admindir is consistent.
func query(sandbox string, args ...string) (string, error) {
	admindir := "--admindir=" + filepath.Join(sandbox, "var/lib/dpkg")
	return runner.Capture(runner.Cmd{
		Argv: append([]string{"dpkg-query", admindir}, args...),
		Sudo: true,
	})
}

// InstalledPackage is one row of `dpkg-query -W`.
type InstalledPackage struct{ Name, Version, Arch string }

func InstalledPackages(sandbox string) ([]InstalledPackage, error) {
	out, err := query(sandbox, "-W",
		`-f=${Package}\t${Version}\t${Architecture}\n`)
	if err != nil {
		return nil, err
	}
	var pkgs []InstalledPackage
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) == 3 {
			pkgs = append(pkgs, InstalledPackage{parts[0], parts[1], parts[2]})
		}
	}
	return pkgs, nil
}

// PackageField returns one dpkg-query --show field for one package
// (Description, Depends, ...).
func PackageField(sandbox, name, field string) (string, error) {
	out, err := query(sandbox, "-W", "-f=${"+field+"}", name)
	return strings.TrimSpace(out), err
}

// canonicalInSandbox resolves a dpkg-style path through sandbox symlinks
// (usrmerge: /sbin -> /usr/sbin etc). Returns "" if resolution leaves the
// sandbox or fails. Mirrors pancake_lib.canonical_in_sandbox.
func canonicalInSandbox(sandboxReal, logical string) string {
	full := filepath.Join(sandboxReal, strings.TrimPrefix(logical, "/"))
	parent, err := filepath.EvalSymlinks(filepath.Dir(full))
	if err != nil {
		return ""
	}
	canon := filepath.Join(parent, filepath.Base(full))
	rel, err := filepath.Rel(sandboxReal, canon)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	return "/" + rel
}

// PackageFiles returns dpkg-tracked files + symlinks + EMPTY directories
// owned by `name`. Non-empty directories are skipped because tar will
// recreate them implicitly when extracting their children — but empty dirs
// (e.g. /var/cache/apt/archives/partial) MUST be staged or apt will refuse
// to operate at runtime.
//
// All paths are canonicalized through the sandbox's usrmerge symlinks.
// Diversion-info lines from dpkg-query are filtered out by skipping
// anything that doesn't start with '/'.
func PackageFiles(sandbox, name string) ([]string, error) {
	raw, err := query(sandbox, "-L", name)
	if err != nil {
		return nil, err
	}
	sandboxReal, err := filepath.EvalSymlinks(sandbox)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if !strings.HasPrefix(line, "/") || line == "/." {
			continue
		}
		canon := canonicalInSandbox(sandboxReal, line)
		if canon == "" || seen[canon] {
			continue
		}
		full := filepath.Join(sandboxReal, strings.TrimPrefix(canon, "/"))
		fi, err := os.Lstat(full)
		if err != nil {
			continue
		}
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			// symlink: keep as-is (don't follow)
		case fi.IsDir():
			ents, err := os.ReadDir(full)
			if err != nil || len(ents) > 0 {
				continue // not empty → tar recreates implicitly
			}
			// empty: keep
		case !fi.Mode().IsRegular():
			continue
		}
		seen[canon] = true
		out = append(out, canon)
	}
	return out, nil
}

// AllRealFiles enumerates every regular file + symlink under sandbox, as
// paths starting with '/'. Used to compute orphans (postinst side effects
// not owned by any package). Equivalent of pancake_lib.all_real_files.
func AllRealFiles(sandbox string) (map[string]bool, error) {
	out, err := runner.Capture(runner.Cmd{
		Argv: []string{"find", sandbox,
			"(", "-type", "f", "-o", "-type", "l", ")",
			"-printf", "/%P\n"},
		Sudo: true,
	})
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line != "" {
			set[line] = true
		}
	}
	return set, nil
}

// StageFiles copies `files` (paths relative to /) from sandbox into
// staging, preserving structure. Uses tar -c | tar -x with -T listfile to
// avoid ARG_MAX limits on packages with thousands of files (e.g. iproute2).
//
// The two tar processes need sudo on the host (sandbox is root-owned), but
// inside the booted VM we're already root and there's no sudo binary —
// runner.Cmd.Sudo handles both transparently.
func StageFiles(sandbox string, files []string, staging string) error {
	if _, err := os.Stat(staging); err == nil {
		if err := runner.Run(runner.Cmd{
			Argv: []string{"rm", "-rf", staging}, Sudo: true,
		}); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}
	listfile := filepath.Join(filepath.Dir(staging),
		filepath.Base(staging)+".list")
	var lb strings.Builder
	for _, f := range files {
		lb.WriteString(strings.TrimPrefix(f, "/"))
		lb.WriteByte('\n')
	}
	if err := os.WriteFile(listfile, []byte(lb.String()), 0o644); err != nil {
		return err
	}
	defer os.Remove(listfile)

	return runner.Pipe(
		runner.Cmd{
			Argv: []string{"tar", "-cf", "-", "-C", sandbox,
				"--no-recursion", "-T", listfile},
			Sudo: true,
		},
		runner.Cmd{
			Argv: []string{"tar", "-xf", "-", "-C", staging},
			Sudo: true,
		},
	)
}

// SortPackages returns p sorted by Name (deterministic output for tests +
// reproducible builds).
func SortPackages(p []InstalledPackage) []InstalledPackage {
	out := make([]InstalledPackage, len(p))
	copy(out, p)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Name > out[j].Name; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// ErrNotInstalled is returned when a query is asked about a package the
// dpkg admindir doesn't have. Currently unused (callers tend to enumerate
// via InstalledPackages first), but exported in case future code wants to
// distinguish missing-pkg from other errors.
var ErrNotInstalled = errors.New("deb: package not installed in sandbox")
