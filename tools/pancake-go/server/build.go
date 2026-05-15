package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/deb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/layer"
	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// BuildGeneration is the workhorse RPC. v1 implementation:
//   - Categorize incoming Packages: APT vs PancakeInternal{recipe="base"}.
//   - Validate all APT entries share suite + arch.
//   - One mmdebstrap call with ALL apt package names → sandbox.
//   - For each non-build-only APT pkg: dpkg-query -L → stage (filtered)
//     → MakeVerity → manifest.toml → cache/<roothash>/.
//   - For the optional base recipe: orphan computation → stage → MakeVerity.
//   - Compose GenerationManifest + return LayerHandles.
//
// No caching across calls (yet). No signing (yet). Other recipes
// (kernel/modules/pancaked/runtime) return Unimplemented; client
// builds those locally for v1.
func (s *Server) BuildGeneration(
	ctx context.Context,
	req *buildpb.BuildGenerationRequest,
) (*buildpb.GenerationManifest, error) {
	var aptPkgs []*buildpb.APT
	var baseSpec *buildpb.PancakeInternal
	var otherInternals []*buildpb.PancakeInternal
	var suite, arch, mirror string

	for _, p := range req.Packages {
		switch x := p.Manager.(type) {
		case *buildpb.Package_Apt:
			aptPkgs = append(aptPkgs, x.Apt)
			if suite == "" {
				suite, arch, mirror = x.Apt.Suite, x.Apt.Arch, x.Apt.Mirror
			} else if x.Apt.Suite != suite || (x.Apt.Arch != "" && x.Apt.Arch != arch) {
				return nil, status.Errorf(codes.InvalidArgument,
					"all APT entries must share suite + arch (saw %s/%s vs %s/%s)",
					x.Apt.Suite, x.Apt.Arch, suite, arch)
			}
		case *buildpb.Package_Internal:
			if x.Internal.Recipe == "base" {
				baseSpec = x.Internal
			} else {
				otherInternals = append(otherInternals, x.Internal)
			}
		default:
			return nil, status.Error(codes.InvalidArgument,
				"Package.manager not set")
		}
	}

	if len(aptPkgs) == 0 {
		return nil, status.Error(codes.InvalidArgument,
			"no APT packages in request")
	}
	if arch == "" {
		arch = "amd64"
	}
	if mirror == "" {
		mirror = "http://archive.ubuntu.com/ubuntu/"
	}

	work, err := s.newWorkDir()
	if err != nil {
		return nil, fmt.Errorf("workdir: %w", err)
	}
	defer os.RemoveAll(work)

	sandbox := filepath.Join(work, "sandbox")
	stage := filepath.Join(work, "stage")
	pkgNames := make([]string, 0, len(aptPkgs))
	seen := map[string]bool{}
	for _, p := range aptPkgs {
		if seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		pkgNames = append(pkgNames, p.Name)
	}

	fmt.Fprintf(os.Stderr, "[server] mmdebstrap %s → %s (%d packages)\n",
		suite, sandbox, len(pkgNames))
	if err := mmdebstrap(suite, mirror, pkgNames, sandbox); err != nil {
		return nil, fmt.Errorf("mmdebstrap: %w", err)
	}

	// Re-derive the actual installed set from the sandbox (deps pulled
	// in by mmdebstrap → also installed → also need extracting).
	installed, err := deb.InstalledPackages(sandbox)
	if err != nil {
		return nil, fmt.Errorf("InstalledPackages: %w", err)
	}
	installed = deb.SortPackages(installed)

	// Index incoming APT specs by name → lets us echo the right
	// (suite/version-pinned) field set in returned LayerHandles, while
	// also extracting deps that the client didn't explicitly list.
	specByName := map[string]*buildpb.APT{}
	for _, a := range aptPkgs {
		specByName[a.Name] = a
	}

	ownedPaths := map[string]bool{}
	var handles []*buildpb.LayerHandle

	for _, ip := range installed {
		files, err := deb.PackageFiles(sandbox, ip.Name)
		if err != nil {
			return nil, fmt.Errorf("PackageFiles %s: %w", ip.Name, err)
		}
		// Apply both filters: per-host paths and ignorePatterns. Both
		// also imply "do NOT register as ownedPath" — they're not
		// owned by anyone in the verity world.
		var kept []string
		for _, f := range files {
			if isPerHostPath(f) || shouldIgnore(f) {
				continue
			}
			ownedPaths[f] = true
			kept = append(kept, f)
		}

		if buildOnlyPackages[ip.Name] {
			continue
		}

		h, err := s.bakeLayer(work, stage, sandbox, ip.Name, ip.Version, ip.Arch, kept)
		if err != nil {
			return nil, fmt.Errorf("bake %s: %w", ip.Name, err)
		}
		// If the caller had a specific spec for this package, echo
		// its mirror back; otherwise use the sandbox-default.
		if spec, ok := specByName[ip.Name]; ok {
			_ = spec // placeholder for future fields
		}
		handles = append(handles, h)
	}

	// PancakeBase ("base" recipe): orphans for the sandbox we just
	// computed (deterministic from the same package set).
	if baseSpec != nil {
		every, err := deb.AllRealFiles(sandbox)
		if err != nil {
			return nil, fmt.Errorf("AllRealFiles: %w", err)
		}
		var orphans []string
		for f := range every {
			if ownedPaths[f] {
				continue
			}
			if isPerHostPath(f) || shouldIgnore(f) {
				continue
			}
			orphans = append(orphans, f)
		}
		sort.Strings(orphans)
		fmt.Fprintf(os.Stderr, "[server] base layer: %d orphan files\n",
			len(orphans))
		h, err := s.bakeLayer(work, stage, sandbox,
			"pancake-base", "1.0.0", "all", orphans)
		if err != nil {
			return nil, fmt.Errorf("bake pancake-base: %w", err)
		}
		// pancake-base goes at the TOP of the overlay (most-specific
		// baseline state wins). Insert at index 0.
		handles = append([]*buildpb.LayerHandle{h}, handles...)
	}

	// Other internal recipes: runtime / pancaked / kernel / modules /
	// pancake-host / orch-config. Each is independent of the apt
	// sandbox; bake them and merge into handles, then sort the whole
	// set into overlay order before composing the manifest.
	for _, in := range otherInternals {
		h, err := s.bakeInternal(work, in)
		if err != nil {
			return nil, fmt.Errorf("bake internal %s: %w", in.Recipe, err)
		}
		handles = append(handles, h)
	}
	handles = sortOverlayOrder(handles)

	// Compose generation manifest TOML using the same kit format the
	// client expects in kit/generations/<id>/manifest.toml. We DON'T
	// sign in v1 (manifest_sig is empty bytes).
	gm := composeGenerationManifest(req, handles)

	return &buildpb.GenerationManifest{
		ManifestToml:  []byte(gm),
		ManifestSig:   nil,
		Lowers:        []byte(composeLowers(handles, req.Counter)),
		Layer:         handles,
		GenerationId:  1, // v1: client controls actual numbering
		Counter:       req.Counter,
		SigningKeyId:  "",
	}, nil
}

// bakeLayer is the per-layer code path: stage selected files into a
// fresh dir, MakeVerity, write manifest.toml, return a LayerHandle.
// Layer artifacts land at cache/layers/<roothash>/.
func (s *Server) bakeLayer(
	workRoot, stageRoot, sandbox string,
	name, version, arch string,
	files []string,
) (*buildpb.LayerHandle, error) {
	dirName := name
	if version != "" {
		dirName = fmt.Sprintf("%s-%s", name, deb.SlugifyVersion(version))
	}
	staging := filepath.Join(stageRoot, dirName)
	if err := deb.StageFiles(sandbox, files, staging); err != nil {
		return nil, fmt.Errorf("stage: %w", err)
	}

	// Build into a temp layer dir; once we have the roothash we
	// rename to cache/layers/<roothash>/.
	tmpLayer := filepath.Join(workRoot, "L-"+dirName)
	if err := os.MkdirAll(tmpLayer, 0o755); err != nil {
		return nil, err
	}
	roothash, dataSize, err := layer.MakeVerity(staging,
		filepath.Join(tmpLayer, "image.img"),
		"pk-"+truncate(name, 12), 0, dirName)
	if err != nil {
		return nil, fmt.Errorf("MakeVerity: %w", err)
	}

	descRaw, _ := deb.PackageField(sandbox, name, "Description")
	depsRaw, _ := deb.PackageField(sandbox, name, "Depends")

	if err := kit.WritePackageManifest(tmpLayer, kit.PackageManifest{
		Package: kit.PackageBlock{
			Name: name, Version: version, Arch: arch,
			Description: firstLine(descRaw),
		},
		Image:   kit.ImageBlock{DataSize: dataSize, Roothash: roothash},
		Depends: kit.DependsBlock{Runtime: deb.ParseDepends(depsRaw)},
	}); err != nil {
		return nil, fmt.Errorf("WritePackageManifest: %w", err)
	}

	// Move into cache by roothash. If it already exists (concurrent
	// build with same content), drop ours and use the existing dir.
	final := s.layerDir(roothash)
	if _, err := os.Stat(final); err == nil {
		os.RemoveAll(tmpLayer)
	} else {
		if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
			return nil, err
		}
		if err := os.Rename(tmpLayer, final); err != nil {
			return nil, fmt.Errorf("rename layer to cache: %w", err)
		}
	}

	mf, err := os.ReadFile(filepath.Join(final, "manifest.toml"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	hashSize := int64(0)
	if fi, err := os.Stat(filepath.Join(final, "image.hash")); err == nil {
		hashSize = fi.Size()
	}

	return &buildpb.LayerHandle{
		Roothash:     roothash,
		ManifestToml: mf,
		Name:         name,
		Version:      version,
		Arch:         arch,
		DataSize:     dataSize,
		HashSize:     hashSize,
		// BuiltAt left nil in v1; clients check non-nil before using.
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func mmdebstrap(suite, mirror string, pkgs []string, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		_ = runner.Run(runner.Cmd{
			Argv: []string{"rm", "-rf", dest}, Sudo: true,
		})
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

// composeGenerationManifest produces the [generation] + [[layer]]
// TOML the kit expects, matching kit.WriteGenerationManifest's output.
func composeGenerationManifest(
	req *buildpb.BuildGenerationRequest,
	handles []*buildpb.LayerHandle,
) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	w("schema = 1")
	w("")
	w("[generation]")
	w(fmt.Sprintf("id          = %d", 1))
	w(fmt.Sprintf("parent      = %d", req.Parent))
	w(fmt.Sprintf("counter     = %d", req.Counter))
	w(fmt.Sprintf("created     = %q",
		time.Now().UTC().Format("2006-01-02T15:04:05-07:00")))
	w(fmt.Sprintf("description = %q", req.Description))
	w("")
	for _, h := range handles {
		dir := h.Name
		if h.Version != "" {
			dir = fmt.Sprintf("%s-%s", h.Name, deb.SlugifyVersion(h.Version))
		}
		w("[[layer]]")
		w(fmt.Sprintf("name     = %q", h.Name))
		w(fmt.Sprintf("version  = %q", h.Version))
		w(fmt.Sprintf("manifest = %q",
			fmt.Sprintf("repo/%s/manifest.toml", dir)))
		w("")
	}
	return b.String()
}

// composeLowers writes the lowers TSV sidecar that initramfs reads.
// Convention: # comment header + slug<TAB>image<TAB>hash<TAB>roothash.
func composeLowers(handles []*buildpb.LayerHandle, counter int32) string {
	var lb strings.Builder
	lw := func(s string) { lb.WriteString(s); lb.WriteByte('\n') }
	lw("# fs-pancake generation 1 lowers (server-built)")
	lw("# slug<TAB>image<TAB>hash<TAB>roothash")
	lw("# overlay order: leftmost (top of stack) FIRST")
	for _, h := range handles {
		dir := h.Name
		if h.Version != "" {
			dir = fmt.Sprintf("%s-%s", h.Name, deb.SlugifyVersion(h.Version))
		}
		lb.WriteString(dir)
		lb.WriteByte('\t')
		lb.WriteString(fmt.Sprintf("repo/%s/image.img", dir))
		lb.WriteByte('\t')
		lb.WriteString(fmt.Sprintf("repo/%s/image.hash", dir))
		lb.WriteByte('\t')
		lb.WriteString(h.Roothash)
		lb.WriteByte('\n')
	}
	return lb.String()
}

