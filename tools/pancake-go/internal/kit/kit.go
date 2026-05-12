// Package kit knows the on-disk layout of a pancake-os kit:
//
//	<kit>/repo/<name>-<slugified-version>/{image.img,image.hash,image.roothash,manifest.toml}
//	<kit>/generations/<n>/{manifest.toml,lowers}
//	<kit>/current   -> generations/<n>
//
// Two file formats live here: TOML manifests (one per package, one per
// generation) and a TSV "lowers" sidecar that the initramfs reads with shell
// since it has no TOML parser. Both formats are stable wire-compat with the
// Python pancake_lib so a Go binary and a Python one can coexist on the
// same kit.
package kit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Kit is a kit directory. Construct with Open which validates the layout.
type Kit struct{ Dir string }

func Open(dir string) (*Kit, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("kit: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("kit: not a directory: %s", dir)
	}
	return &Kit{Dir: dir}, nil
}

func (k *Kit) Repo() string        { return filepath.Join(k.Dir, "repo") }
func (k *Kit) Generations() string { return filepath.Join(k.Dir, "generations") }
func (k *Kit) Current() string     { return filepath.Join(k.Dir, "current") }

// PackageManifest is one .deb-derived layer.
type PackageManifest struct {
	Schema  int          `toml:"schema"`
	Package PackageBlock `toml:"package"`
	Image   ImageBlock   `toml:"image"`
	Depends DependsBlock `toml:"depends"`
	Prov    Provenance   `toml:"provenance"`
	Hooks   Hooks        `toml:"hooks"`
}

type PackageBlock struct {
	Name        string `toml:"name"`
	Version     string `toml:"version"`
	Arch        string `toml:"arch"`
	Description string `toml:"description"`
}
type ImageBlock struct {
	Data     string `toml:"data"`
	Hash     string `toml:"hash"`
	DataSize int64  `toml:"data-size"`
	Roothash string `toml:"roothash"`
	HashAlgo string `toml:"hash-algo"`
}
type DependsBlock struct {
	Runtime []string `toml:"runtime"`
}
type Provenance struct {
	DebName   string `toml:"deb-name"`
	DebSHA256 string `toml:"deb-sha256"`
	BuiltAt   string `toml:"built-at"`
	BuiltWith string `toml:"built-with"`
}
type Hooks struct {
	PostExtract  []string `toml:"post-extract"`
	PostActivate []string `toml:"post-activate"`
}

// WritePackageManifest writes <pkgDir>/manifest.toml plus image.roothash.
//
// Keep the field order + spacing aligned with what pancake_lib.write_manifest
// emits. We construct the text manually rather than letting go-toml render
// it, because the kit format historically uses fixed alignment columns and
// we don't want diffs against Python-built kits.
func WritePackageManifest(pkgDir string, m PackageManifest) error {
	if m.Schema == 0 {
		m.Schema = 1
	}
	if m.Image.Data == "" {
		m.Image.Data = "image.img"
	}
	if m.Image.Hash == "" {
		m.Image.Hash = "image.hash"
	}
	if m.Image.HashAlgo == "" {
		m.Image.HashAlgo = "sha256"
	}
	if m.Prov.BuiltAt == "" {
		m.Prov.BuiltAt = time.Now().UTC().Format("2006-01-02T15:04:05-07:00")
	}
	if m.Prov.BuiltWith == "" {
		m.Prov.BuiltWith = "pancake-go 0.1"
	}

	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	w(fmt.Sprintf("schema = %d", m.Schema))
	w("")
	w("[package]")
	w(fmt.Sprintf("name        = %q", m.Package.Name))
	w(fmt.Sprintf("version     = %q", m.Package.Version))
	w(fmt.Sprintf("arch        = %q", m.Package.Arch))
	w(fmt.Sprintf("description = %q", m.Package.Description))
	w("")
	w("[image]")
	w(fmt.Sprintf("data        = %q", m.Image.Data))
	w(fmt.Sprintf("hash        = %q", m.Image.Hash))
	w(fmt.Sprintf("data-size   = %d", m.Image.DataSize))
	w(fmt.Sprintf("roothash    = %q", m.Image.Roothash))
	w(fmt.Sprintf("hash-algo   = %q", m.Image.HashAlgo))
	w("")
	w("[depends]")
	w("runtime = [")
	for _, d := range m.Depends.Runtime {
		w(fmt.Sprintf("    %q,", d))
	}
	w("]")
	w("")
	w("[provenance]")
	w(fmt.Sprintf("deb-name   = %q", m.Prov.DebName))
	w(fmt.Sprintf("deb-sha256 = %q", m.Prov.DebSHA256))
	w(fmt.Sprintf("built-at   = %q", m.Prov.BuiltAt))
	w(fmt.Sprintf("built-with = %q", m.Prov.BuiltWith))
	w("")
	w("[hooks]")
	w("post-extract  = []")
	w("post-activate = []")
	w("")

	if err := os.WriteFile(filepath.Join(pkgDir, "manifest.toml"),
		[]byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(pkgDir, "image.roothash"),
		[]byte(m.Image.Roothash+"\n"), 0o644)
}

// ReadPackageManifest is the dual of Write. We use the toml lib here since
// we're parsing, not rendering — order doesn't matter on read.
func ReadPackageManifest(path string) (PackageManifest, error) {
	var m PackageManifest
	data, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := toml.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

// GenerationManifest lists the layers in one generation, in overlay order
// (leftmost = top of stack = wins on conflict).
type GenerationManifest struct {
	Schema     int             `toml:"schema"`
	Generation GenerationBlock `toml:"generation"`
	Layer      []LayerRef      `toml:"layer"`
}

type GenerationBlock struct {
	ID          int    `toml:"id"`
	Parent      int    `toml:"parent"`
	Created     string `toml:"created"`
	Description string `toml:"description"`
	// Counter is a monotonically-increasing integer signed into the
	// manifest. The initramfs compares it against a TPM NV index and
	// refuses to boot if the manifest's counter is *less* than what
	// the TPM has already seen — this is what defeats the "replace
	// current with an older signed manifest" rollback attack. New
	// generations get current_max + 1; gen 1 starts at 1.
	Counter int `toml:"counter"`
}

// LayerRef points at one repo/<slug>/manifest.toml. Name+Version are kept
// inline so `pancake list` doesn't need to read every per-package manifest.
type LayerRef struct {
	Name     string `toml:"name"`
	Version  string `toml:"version"`
	Manifest string `toml:"manifest"` // relative to kit dir, e.g. "repo/foo-1.0/manifest.toml"
}

// WriteGenerationManifest writes <gen>/manifest.toml + the lowers TSV
// sidecar that the initramfs consumes.
func WriteGenerationManifest(k *Kit, gen GenerationManifest) error {
	if gen.Schema == 0 {
		gen.Schema = 1
	}
	if gen.Generation.Created == "" {
		gen.Generation.Created = time.Now().UTC().Format("2006-01-02T15:04:05-07:00")
	}
	genDir := filepath.Join(k.Generations(), strconv.Itoa(gen.Generation.ID))
	if err := os.MkdirAll(genDir, 0o755); err != nil {
		return err
	}

	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	w(fmt.Sprintf("schema = %d", gen.Schema))
	w("")
	w("[generation]")
	w(fmt.Sprintf("id          = %d", gen.Generation.ID))
	w(fmt.Sprintf("parent      = %d", gen.Generation.Parent))
	w(fmt.Sprintf("counter     = %d", gen.Generation.Counter))
	w(fmt.Sprintf("created     = %q", gen.Generation.Created))
	w(fmt.Sprintf("description = %q", gen.Generation.Description))
	w("")
	for _, L := range gen.Layer {
		w("[[layer]]")
		w(fmt.Sprintf("name     = %q", L.Name))
		w(fmt.Sprintf("version  = %q", L.Version))
		w(fmt.Sprintf("manifest = %q", L.Manifest))
		w("")
	}
	if err := os.WriteFile(filepath.Join(genDir, "manifest.toml"),
		[]byte(b.String()), 0o644); err != nil {
		return err
	}

	// lowers TSV: # comments + slug<TAB>image_rel<TAB>hash_rel<TAB>roothash
	var lb strings.Builder
	lw := func(s string) { lb.WriteString(s); lb.WriteByte('\n') }
	lw(fmt.Sprintf("# fs-pancake generation %d lowers", gen.Generation.ID))
	lw("# slug<TAB>image<TAB>hash<TAB>roothash")
	lw("# overlay order: leftmost (top of stack) FIRST")
	for _, L := range gen.Layer {
		slug := filepath.Base(filepath.Dir(L.Manifest))
		rh, err := os.ReadFile(filepath.Join(k.Repo(), slug, "image.roothash"))
		if err != nil {
			return fmt.Errorf("missing roothash for %s: %w", slug, err)
		}
		lw(fmt.Sprintf("%s\trepo/%s/image.img\trepo/%s/image.hash\t%s",
			slug, slug, slug, strings.TrimSpace(string(rh))))
	}
	return os.WriteFile(filepath.Join(genDir, "lowers"),
		[]byte(lb.String()), 0o644)
}

// ReadGenerationManifest parses a generation/N/manifest.toml.
func ReadGenerationManifest(path string) (GenerationManifest, error) {
	var g GenerationManifest
	data, err := os.ReadFile(path)
	if err != nil {
		return g, err
	}
	if err := toml.Unmarshal(data, &g); err != nil {
		return g, fmt.Errorf("parse %s: %w", path, err)
	}
	return g, nil
}

// LowerEntry is one parsed line of a generations/N/lowers TSV.
type LowerEntry struct {
	Slug, ImageRel, HashRel, Roothash string
}

func ReadLowers(path string) ([]LowerEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []LowerEntry
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 {
			continue
		}
		out = append(out, LowerEntry{parts[0], parts[1], parts[2], parts[3]})
	}
	return out, nil
}

// CurrentGeneration resolves the `current` symlink and returns the path of
// the generation dir it points at. Errors if the symlink is missing or
// dangling.
func (k *Kit) CurrentGeneration() (string, error) {
	tgt, err := os.Readlink(k.Current())
	if err != nil {
		return "", fmt.Errorf("kit: no 'current' symlink: %w", err)
	}
	if !filepath.IsAbs(tgt) {
		tgt = filepath.Join(k.Dir, tgt)
	}
	if _, err := os.Stat(tgt); err != nil {
		return "", fmt.Errorf("kit: 'current' is dangling: %w", err)
	}
	return tgt, nil
}

func (k *Kit) CurrentID() (int, error) {
	gen, err := k.CurrentGeneration()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(filepath.Base(gen))
}

// LatestGenerationID scans generations/* and returns the max integer name.
// Returns 0 if generations/ doesn't exist or has no numeric children.
func (k *Kit) LatestGenerationID() (int, error) {
	ents, err := os.ReadDir(k.Generations())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	max := 0
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if n > max {
			max = n
		}
	}
	return max, nil
}

// SetCurrent atomically points current → generations/<id>. Uses
// rename-of-tmp-symlink so an interrupted update can never leave current
// dangling.
func (k *Kit) SetCurrent(id int) error {
	target := fmt.Sprintf("generations/%d", id)
	tmp := k.Current() + ".swap.tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, k.Current())
}

// MaxCounter returns the largest `counter` field across every existing
// generation manifest in the kit. New generations should be created with
// MaxCounter()+1 so the value is monotonic across kit history. Returns 0
// (and no error) if no generations exist yet.
func (k *Kit) MaxCounter() (int, error) {
	ids, err := k.SortGenerations()
	if err != nil {
		return 0, err
	}
	max := 0
	for _, id := range ids {
		path := filepath.Join(k.Generations(),
			strconv.Itoa(id), "manifest.toml")
		m, err := ReadGenerationManifest(path)
		if err != nil {
			continue
		}
		if m.Generation.Counter > max {
			max = m.Generation.Counter
		}
	}
	return max, nil
}

// SortGenerations returns IDs in ascending numeric order.
func (k *Kit) SortGenerations() ([]int, error) {
	ents, err := os.ReadDir(k.Generations())
	if err != nil {
		return nil, err
	}
	var ids []int
	for _, e := range ents {
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		ids = append(ids, n)
	}
	sort.Ints(ids)
	return ids, nil
}
