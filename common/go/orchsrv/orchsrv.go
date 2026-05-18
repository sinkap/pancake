// Package orchsrv implements pancake's orchestrator-side gRPC service:
// GetCurrentManifest + Update from internal/pancakepb/pancake.proto.
//
// Used by the pancaked daemon (cmd/pancaked) and previously by the now-
// removed `pancake serve` subcommand. Server logic, auto-rebuild path,
// and TPM-sealed-token loading all live here so cmd/pancaked stays a
// thin entry point.
package orchsrv

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sinkap/pancake/common/gen/go/buildpb"
	"github.com/sinkap/pancake/common/go/deb"
	"github.com/sinkap/pancake/common/go/kit"
	"github.com/sinkap/pancake/common/go/layer"
	"github.com/sinkap/pancake/common/gen/go/pancakepb"
	"github.com/sinkap/pancake/common/go/pkitls"
	"github.com/sinkap/pancake/common/go/runner"
	"github.com/sinkap/pancake/common/go/sandbox"
	"github.com/sinkap/pancake/common/go/sign"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// DefaultPubKeyPath is where pancake bootstrap bakes the manifest pubkey
// into pancake-state, and where pancaked looks for it by default.
const DefaultPubKeyPath = "/etc/pancake/manifest.pubkey"

// Opts is what cmd/pancaked passes to Serve. Keep small + boring;
// flag parsing lives in main.
type Opts struct {
	Kit    *kit.Kit
	Listen string // address:port for gRPC listener
	PubKey string // PEM PKIX public key path

	// mTLS — the only transport auth pancaked supports. When all
	// three are set, pancaked listens on TLS and requires a peer
	// client cert signed by CAFile. KeyFile is either a PEM
	// PKCS#8 file (Slice 1, static CA) or "" + KeyMarkerFile set
	// (Slice 2, TPM-resident key resolved via internal/tpmkey).
	// When unset entirely, pancaked listens on plain TCP and
	// manifest signature is the only integrity gate.
	CAFile        string // PEM root cert
	CertFile      string // PEM server-auth leaf cert
	KeyFile       string // PEM PKCS#8 private key (mutually excl. with KeyMarkerFile)
	KeyMarkerFile string // TPM key marker JSON (Slice 2)

	// Builder is the address (host:port) of a pancake-build-server.
	// When set, missing-layer fetches in Update() pull bytes from
	// the build server's GetLayer instead of trying the in-VM
	// apt-rebuild path. Empty = no auto-fetch.
	Builder string
}

// Serve starts the gRPC server. Blocks until the listener errors.
// Returns nil on graceful shutdown, an error otherwise.
func Serve(o Opts) error {
	if o.Listen == "" {
		o.Listen = ":7878"
	}
	if o.PubKey == "" {
		o.PubKey = DefaultPubKeyPath
	}
	if o.KeyFile != "" && o.KeyMarkerFile != "" {
		return fmt.Errorf("orchsrv: KeyFile and KeyMarkerFile are mutually exclusive")
	}
	if _, err := os.Stat(o.PubKey); err != nil {
		return fmt.Errorf("pubkey not found at %s — was the kit "+
			"bootstrapped without --sign-key?", o.PubKey)
	}

	srv := &server{k: o.Kit, pubkey: o.PubKey}

	// Provision per-boot attestation context (AK + EK). Soft-fails on
	// no-TPM systems; the daemon still serves Update / GetCurrentManifest.
	ast, err := setupAttest()
	if err != nil {
		return fmt.Errorf("setup attest: %w", err)
	}
	srv.attest = ast

	// Dial the build server lazily — Update will fall back to the
	// in-VM apt-rebuild path if no builder is configured. Connection
	// stays alive for the daemon's lifetime; gRPC handles reconnects.
	if o.Builder != "" {
		cc, err := grpc.NewClient(o.Builder,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(64*1024*1024)))
		if err != nil {
			return fmt.Errorf("dial builder %s: %w", o.Builder, err)
		}
		srv.builderAddr = o.Builder
		srv.builderClient = buildpb.NewPancakeBuilderServiceClient(cc)
		fmt.Fprintf(os.Stderr,
			"[pancaked] build server: %s (auto-fetch missing layers on Update)\n",
			o.Builder)
	}

	lis, err := net.Listen("tcp", o.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", o.Listen, err)
	}

	srvOpts := []grpc.ServerOption{}
	authMode := "unauthenticated"
	switch {
	case o.CAFile != "" && o.CertFile != "" && o.KeyMarkerFile != "":
		cfg, err := pkitls.LoadServerConfigTPM(
			o.CertFile, o.KeyMarkerFile, o.CAFile)
		if err != nil {
			return fmt.Errorf("mTLS (TPM key): %w", err)
		}
		srvOpts = append(srvOpts, grpc.Creds(credentials.NewTLS(cfg)))
		authMode = "mTLS (TPM-resident key, client cert required)"
	case o.CAFile != "" && o.CertFile != "" && o.KeyFile != "":
		cfg, err := pkitls.LoadServerConfig(o.CertFile, o.KeyFile, o.CAFile)
		if err != nil {
			return fmt.Errorf("mTLS (PEM key): %w", err)
		}
		srvOpts = append(srvOpts, grpc.Creds(credentials.NewTLS(cfg)))
		authMode = "mTLS (PEM key, client cert required)"
	case o.CAFile != "" || o.CertFile != "" || o.KeyFile != "" || o.KeyMarkerFile != "":
		return fmt.Errorf("mTLS: need --ca-file + --cert-file + " +
			"(--key-file OR --tpm-key-marker); got partial")
	}

	g := grpc.NewServer(srvOpts...)
	pancakepb.RegisterPancakeAgentServiceServer(g, srv)

	fmt.Fprintf(os.Stderr,
		"[pancaked] gRPC listening on %s (auth: %s)\n", o.Listen, authMode)
	return g.Serve(lis)
}

// server is the pancakepb.PancakeAgentServiceServer implementation.
type server struct {
	pancakepb.UnimplementedPancakeAgentServiceServer
	k             *kit.Kit
	pubkey        string
	attest        *attestState // nil = no TPM, Attest RPC returns Unavailable
	builderAddr   string
	builderClient buildpb.PancakeBuilderServiceClient // nil = no auto-fetch
}

// GetCurrentManifest returns whatever generation `current` points at.
func (s *server) GetCurrentManifest(_ context.Context,
	_ *pancakepb.GetCurrentManifestRequest) (*pancakepb.Manifest, error) {
	curID, err := s.k.CurrentID()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return readManifestFromKit(s.k, curID)
}

// Update accepts a signed manifest, verifies it end-to-end, writes the
// generation directory atomically. Does NOT flip current.
func (s *server) Update(_ context.Context,
	m *pancakepb.Manifest) (*pancakepb.UpdateResponse, error) {
	if len(m.ManifestToml) == 0 || len(m.ManifestSig) == 0 {
		return nil, status.Error(codes.InvalidArgument,
			"manifest_toml and manifest_sig are required")
	}

	// Stage to /tmp so VerifyManifest (file-based) can run without
	// inventing an alternative API.
	stage, err := os.MkdirTemp("", "pancake-update-")
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	defer os.RemoveAll(stage)
	mPath := filepath.Join(stage, "manifest.toml")
	sPath := filepath.Join(stage, "manifest.toml.sig")
	lPath := filepath.Join(stage, "lowers")
	if err := os.WriteFile(mPath, m.ManifestToml, 0o644); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if err := os.WriteFile(sPath, m.ManifestSig, 0o644); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if err := os.WriteFile(lPath, m.Lowers, 0o644); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// 1. Signature.
	if err := sign.VerifyManifest(mPath, sPath, s.pubkey); err != nil {
		return &pancakepb.UpdateResponse{Error: "signature: " + err.Error()},
			status.Error(codes.PermissionDenied, err.Error())
	}

	// 2. Parse + counter check + new-id check.
	gm, err := kit.ReadGenerationManifest(mPath)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "parse manifest: "+err.Error())
	}
	maxCtr, err := s.k.MaxCounter()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if gm.Generation.Counter <= maxCtr {
		msg := fmt.Sprintf("counter %d not greater than local max %d",
			gm.Generation.Counter, maxCtr)
		return &pancakepb.UpdateResponse{Error: msg},
			status.Error(codes.FailedPrecondition, msg)
	}
	newID := gm.Generation.ID
	if _, err := os.Stat(filepath.Join(s.k.Generations(),
		strconv.Itoa(newID))); err == nil {
		msg := fmt.Sprintf("generation %d already exists locally", newID)
		return &pancakepb.UpdateResponse{Error: msg},
			status.Error(codes.AlreadyExists, msg)
	}

	// 3. Layer-presence check + auto-rebuild from apt for missing slugs.
	missingSlugs := []string{}
	missingLayers := []kit.LayerRef{}
	for _, L := range gm.Layer {
		slug := filepath.Base(filepath.Dir(L.Manifest))
		if _, err := os.Stat(filepath.Join(s.k.Repo(), slug, "image.img")); err != nil {
			missingSlugs = append(missingSlugs, slug)
			missingLayers = append(missingLayers, L)
		}
	}
	if len(missingSlugs) > 0 {
		// Preferred path: pull from the build server (content-addressed
		// by roothash; bytes are canonical, no in-VM rebuild noise).
		if s.builderClient != nil {
			fmt.Fprintf(os.Stderr,
				"[pancaked] %d missing layers; auto-fetching from build server %s\n",
				len(missingSlugs), s.builderAddr)
			if err := s.fetchLayersFromBuilder(missingLayers, m.Lowers); err != nil {
				fmt.Fprintf(os.Stderr,
					"[pancaked] build-server fetch failed: %v — will try apt rebuild\n", err)
			}
			missingSlugs = stillMissingSlugs(s.k, gm.Layer)
		}

		// Fallback: in-VM rebuild from apt. Only kicks in when (a) no
		// builder is configured, or (b) builder didn't have the layer.
		// Subject to the well-known mkfs.ext4 reproducibility caveat.
		if len(missingSlugs) > 0 {
			fmt.Fprintf(os.Stderr,
				"[pancaked] %d still missing; attempting local rebuild from apt\n",
				len(missingSlugs))
			expected, err := parseLowersRoothashes(m.Lowers)
			if err != nil {
				return &pancakepb.UpdateResponse{
						Error: "parse lowers: " + err.Error()},
					status.Error(codes.InvalidArgument, err.Error())
			}
			// Re-derive the missingLayers slice for the still-missing slugs.
			stillMissingRefs := []kit.LayerRef{}
			for _, L := range gm.Layer {
				slug := filepath.Base(filepath.Dir(L.Manifest))
				for _, m := range missingSlugs {
					if m == slug {
						stillMissingRefs = append(stillMissingRefs, L)
						break
					}
				}
			}
			if err := buildMissingLayers(s.k, stillMissingRefs, expected); err != nil {
				return &pancakepb.UpdateResponse{
						MissingLayerSlugs: missingSlugs,
						Error:             "auto-build: " + err.Error()},
					status.Error(codes.FailedPrecondition, err.Error())
			}
			missingSlugs = stillMissingSlugs(s.k, gm.Layer)
		}

		if len(missingSlugs) > 0 {
			return &pancakepb.UpdateResponse{
					MissingLayerSlugs: missingSlugs,
					Error:             "layers still missing after fetch + rebuild"},
				status.Error(codes.Internal, "still missing")
		}
		fmt.Fprintln(os.Stderr,
			"[pancaked] all previously-missing layers now present")
	}

	// 4. Atomic install of the gen dir.
	dst := filepath.Join(s.k.Generations(), strconv.Itoa(newID))
	tmp := dst + ".tmp"
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	for _, p := range []struct{ src, name string }{
		{mPath, "manifest.toml"},
		{sPath, "manifest.toml.sig"},
		{lPath, "lowers"},
	} {
		data, err := os.ReadFile(p.src)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		if err := os.WriteFile(filepath.Join(tmp, p.name), data, 0o644); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	fmt.Fprintf(os.Stderr,
		"[pancaked] installed generation %d (counter %d, %d layers)\n",
		newID, gm.Generation.Counter, len(gm.Layer))
	return &pancakepb.UpdateResponse{InstalledGeneration: int32(newID)}, nil
}

// stillMissingSlugs returns the subset of layer slugs whose
// repo/<slug>/image.img doesn't exist on disk. Used after a fetch
// or rebuild attempt to figure out which layers are still missing.
func stillMissingSlugs(k *kit.Kit, layers []kit.LayerRef) []string {
	var out []string
	for _, L := range layers {
		slug := filepath.Base(filepath.Dir(L.Manifest))
		if _, err := os.Stat(filepath.Join(k.Repo(), slug, "image.img")); err != nil {
			out = append(out, slug)
		}
	}
	return out
}

// readManifestFromKit reads the three sidecar files for genID into a
// proto Manifest. Used by GetCurrentManifest.
func readManifestFromKit(k *kit.Kit, genID int) (*pancakepb.Manifest, error) {
	dir := filepath.Join(k.Generations(), strconv.Itoa(genID))
	mt, err := os.ReadFile(filepath.Join(dir, "manifest.toml"))
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	ms, err := os.ReadFile(filepath.Join(dir, "manifest.toml.sig"))
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition,
			"manifest.toml.sig missing — kit was built without --sign-key")
	}
	lo, err := os.ReadFile(filepath.Join(dir, "lowers"))
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &pancakepb.Manifest{ManifestToml: mt, ManifestSig: ms, Lowers: lo}, nil
}

// parseLowersRoothashes parses a lowers TSV (slug<TAB>image<TAB>hash<TAB>roothash)
// into slug → expected roothash.
func parseLowersRoothashes(lowers []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(string(lowers), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 {
			continue
		}
		out[parts[0]] = parts[3]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no lowers rows parsed")
	}
	return out, nil
}

// buildMissingLayers materializes the current generation's overlay,
// runs `apt-get install <name>=<version> ...` for every missing layer,
// snapshots each newly-installed package as a verity layer with the
// deterministic-seed flags from layer.MakeVerity, and verifies the
// resulting roothash matches the orchestrator-claimed value. All-or-
// nothing: a single mismatch (or any apt failure) leaves repo/ untouched
// and returns an error.
func buildMissingLayers(k *kit.Kit, missing []kit.LayerRef,
	expectedRoothashes map[string]string) error {

	mountOverlay, err := sandbox.FindHelper("mount-overlay", "", "")
	if err != nil {
		return err
	}
	scratch, err := os.MkdirTemp("", "pancake-rebuild-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)

	tag := fmt.Sprintf("rebuild%d", os.Getpid())
	sb, err := sandbox.MaterializeCurrent(k, scratch, tag, mountOverlay)
	if err != nil {
		return fmt.Errorf("materialize: %w", err)
	}
	defer sb.Teardown()
	if err := sb.BindChrootRuntime(); err != nil {
		return fmt.Errorf("bind chroot: %w", err)
	}

	bySlug := map[string]kit.LayerRef{}
	var aptPkgs []string
	for _, L := range missing {
		slug := filepath.Base(filepath.Dir(L.Manifest))
		bySlug[slug] = L
		aptPkgs = append(aptPkgs, fmt.Sprintf("%s=%s", L.Name, L.Version))
	}

	env := []string{
		"DEBIAN_FRONTEND=noninteractive",
		"DPKG_FORCE=confnew",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
	}
	fmt.Fprintf(os.Stderr,
		"[pancaked] apt-get install %v in materialized chroot\n", aptPkgs)
	if err := runner.Run(runner.Cmd{
		Argv: []string{"chroot", sb.Path, "apt-get", "update", "-q", "-y"},
		Env:  env,
	}); err != nil {
		return fmt.Errorf("apt-get update: %w", err)
	}
	if err := runner.Run(runner.Cmd{
		Argv: append([]string{"chroot", sb.Path, "apt-get", "install", "-y",
			"--no-install-recommends",
			"-o", "Dpkg::Options::=--force-confnew"}, aptPkgs...),
		Env: env,
	}); err != nil {
		return fmt.Errorf("apt-get install: %w", err)
	}

	stageRoot, err := os.MkdirTemp("", "pancake-rebuild-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stageRoot)

	type built struct {
		slug, repoDir, tmpImg, tmpHash, roothash string
		dataSize                                 int64
		desc, deps                               string
	}
	var bs []built
	for slug, L := range bySlug {
		expected, ok := expectedRoothashes[slug]
		if !ok {
			return fmt.Errorf("no expected roothash for %s in lowers", slug)
		}
		files, err := deb.PackageFiles(sb.Path, L.Name)
		if err != nil {
			return fmt.Errorf("package_files %s: %w", L.Name, err)
		}
		stagingDir := filepath.Join(stageRoot, L.Name)
		if err := deb.StageFiles(sb.Path, files, stagingDir); err != nil {
			return fmt.Errorf("stage_files %s: %w", L.Name, err)
		}
		tmpImg := filepath.Join(stageRoot, slug+".img")
		labelName := L.Name
		if len(labelName) > 12 {
			labelName = labelName[:12]
		}
		roothash, dataSize, err := layer.MakeVerity(stagingDir, tmpImg,
			"pk-"+labelName, 0, slug)
		if err != nil {
			return fmt.Errorf("make_verity %s: %w", L.Name, err)
		}
		if roothash != expected {
			return fmt.Errorf("layer %s roothash mismatch:\n  built    = %s\n  expected = %s\n"+
				"(deterministic-build invariant violated; either mkfs.ext4/veritysetup "+
				"non-determinism or a different .deb version on this VM's apt repo)",
				slug, roothash, expected)
		}
		descRaw, _ := deb.PackageField(sb.Path, L.Name, "Description")
		depsRaw, _ := deb.PackageField(sb.Path, L.Name, "Depends")
		desc := descRaw
		if i := strings.IndexByte(desc, '\n'); i > 0 {
			desc = desc[:i]
		}
		bs = append(bs, built{
			slug: slug, repoDir: filepath.Join(k.Repo(), slug),
			tmpImg: tmpImg, tmpHash: tmpImg + ".hash",
			roothash: roothash, dataSize: dataSize,
			desc: desc, deps: depsRaw,
		})
	}

	for _, b := range bs {
		if err := os.MkdirAll(b.repoDir, 0o755); err != nil {
			return err
		}
		if err := os.Rename(b.tmpImg, filepath.Join(b.repoDir, "image.img")); err != nil {
			return err
		}
		if err := os.Rename(b.tmpHash, filepath.Join(b.repoDir, "image.hash")); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(b.repoDir, "image.roothash"),
			[]byte(b.roothash+"\n"), 0o644); err != nil {
			return err
		}
		L := bySlug[b.slug]
		if err := kit.WritePackageManifest(b.repoDir, kit.PackageManifest{
			Package: kit.PackageBlock{
				Name: L.Name, Version: L.Version, Arch: "amd64",
				Description: b.desc,
			},
			Image:   kit.ImageBlock{DataSize: b.dataSize, Roothash: b.roothash},
			Depends: kit.DependsBlock{Runtime: deb.ParseDepends(b.deps)},
		}); err != nil {
			return err
		}
	}
	return nil
}

