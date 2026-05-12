// `pancake serve`: gRPC service running on the VM. Implements the
// pancake.v1.Pancake service from internal/orchpb/pancake.proto.
//
// Two RPCs, no streaming, no transport bundle: the manifest IS the wire
// format. See internal/orchpb/pancake.proto for the contract.
//
// Auth: optional bearer token in metadata['authorization'] = "Bearer T".
// The signature on the manifest is the integrity floor; the token only
// thwarts trivial DoS.

package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/deb"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/layer"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/orchpb"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/runner"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/sandbox"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/sign"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const defaultPubKeyPath = "/etc/pancake/manifest.pubkey"

type pancakeServer struct {
	orchpb.UnimplementedPancakeServer
	k      *kit.Kit
	pubkey string
	token  string // empty = no auth
}

func cmdServe(k *kit.Kit, args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", ":7878", "address:port for gRPC listener")
	pubkey := fs.String("pubkey", defaultPubKeyPath,
		"PEM PKIX public key for verifying pushed manifests")
	tokenFile := fs.String("token-file", "",
		"file containing a bearer token; clients must send it as "+
			"metadata['authorization'] = \"Bearer <token>\". Empty disables auth.")
	tpmToken := fs.String("tpm-token", "",
		"path to a systemd-creds-sealed token blob (typically "+
			defaultSealedTokenPath+", produced by `pancake enroll`). "+
			"Decrypts at startup via TPM PCR 7+11; mismatched boot chain "+
			"→ decrypt fails → server refuses to start. Mutually "+
			"exclusive with --token-file.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tokenFile != "" && *tpmToken != "" {
		return die(fmt.Errorf("--token-file and --tpm-token are mutually exclusive"))
	}
	if _, err := os.Stat(*pubkey); err != nil {
		fmt.Fprintf(os.Stderr,
			"pancake serve: pubkey not found at %s — was the kit "+
				"bootstrapped without --sign-key?\n", *pubkey)
		return 1
	}
	srv := &pancakeServer{k: k, pubkey: *pubkey}
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return die(fmt.Errorf("read token-file: %w", err))
		}
		srv.token = strings.TrimSpace(string(b))
	} else if *tpmToken != "" {
		t, err := loadSealedToken(*tpmToken)
		if err != nil {
			return die(fmt.Errorf("unseal --tpm-token: %w "+
				"(boot chain doesn't match what was sealed at enroll? "+
				"re-run `pancake enroll`)", err))
		}
		srv.token = t
		fmt.Fprintln(os.Stderr,
			"[serve] auth token unsealed from TPM (PCR-bound to current boot chain)")
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		return die(fmt.Errorf("listen: %w", err))
	}
	g := grpc.NewServer(grpc.UnaryInterceptor(srv.authInterceptor))
	orchpb.RegisterPancakeServer(g, srv)

	fmt.Fprintf(os.Stderr,
		"[serve] gRPC listening on %s (auth=%t)\n",
		*listen, srv.token != "")
	if err := g.Serve(lis); err != nil {
		return die(err)
	}
	return 0
}

// authInterceptor checks the bearer token on every RPC if one is set.
func (s *pancakeServer) authInterceptor(ctx context.Context,
	req any, info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (any, error) {
	if s.token == "" {
		return handler(ctx, req)
	}
	md, _ := metadata.FromIncomingContext(ctx)
	got := ""
	if vs := md.Get("authorization"); len(vs) > 0 {
		got = strings.TrimPrefix(vs[0], "Bearer ")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
		return nil, status.Error(codes.Unauthenticated, "bad bearer token")
	}
	return handler(ctx, req)
}

// GetCurrentManifest returns whatever generation `current` points at.
func (s *pancakeServer) GetCurrentManifest(ctx context.Context,
	_ *orchpb.GetCurrentManifestRequest) (*orchpb.Manifest, error) {
	curID, err := s.k.CurrentID()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return readManifestFromKit(s.k, curID)
}

// Update accepts a signed manifest, verifies it end-to-end, writes the
// generation directory atomically. Does NOT flip current.
func (s *pancakeServer) Update(ctx context.Context,
	m *orchpb.Manifest) (*orchpb.UpdateResponse, error) {
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
		return &orchpb.UpdateResponse{Error: "signature: " + err.Error()},
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
		return &orchpb.UpdateResponse{Error: msg},
			status.Error(codes.FailedPrecondition, msg)
	}
	newID := gm.Generation.ID
	if _, err := os.Stat(filepath.Join(s.k.Generations(),
		strconv.Itoa(newID))); err == nil {
		msg := fmt.Sprintf("generation %d already exists locally", newID)
		return &orchpb.UpdateResponse{Error: msg},
			status.Error(codes.AlreadyExists, msg)
	}

	// 3. Layer-presence check. Every referenced slug MUST already be in
	// kit/repo/, but if any are missing we attempt to rebuild them
	// locally from apt — manifest already names (package, version), and
	// with deterministic mkfs.ext4 + veritysetup salt the roothash
	// matches the build host's. (See layer.MakeVerity's seed parameter.)
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
		fmt.Fprintf(os.Stderr,
			"[serve] %d missing layers; attempting local rebuild from apt\n",
			len(missingSlugs))
		expected, err := parseLowersRoothashes(m.Lowers)
		if err != nil {
			return &orchpb.UpdateResponse{
					Error: "parse lowers: " + err.Error()},
				status.Error(codes.InvalidArgument, err.Error())
		}
		if err := buildMissingLayers(s.k, missingLayers, expected); err != nil {
			return &orchpb.UpdateResponse{
					MissingLayerSlugs: missingSlugs,
					Error:             "auto-build: " + err.Error()},
				status.Error(codes.FailedPrecondition, err.Error())
		}
		// Re-verify presence; anything still missing is fatal.
		var stillMissing []string
		for _, slug := range missingSlugs {
			if _, err := os.Stat(filepath.Join(s.k.Repo(), slug, "image.img")); err != nil {
				stillMissing = append(stillMissing, slug)
			}
		}
		if len(stillMissing) > 0 {
			return &orchpb.UpdateResponse{
					MissingLayerSlugs: stillMissing,
					Error:             "some layers still missing after rebuild"},
				status.Error(codes.Internal, "still missing")
		}
		fmt.Fprintf(os.Stderr,
			"[serve] all %d missing layers rebuilt locally with matching roothashes\n",
			len(missingSlugs))
	}

	// 4. Atomic install.
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
		"[serve] installed generation %d (counter %d, %d layers)\n",
		newID, gm.Generation.Counter, len(gm.Layer))
	return &orchpb.UpdateResponse{InstalledGeneration: int32(newID)}, nil
}

// parseLowersRoothashes parses a lowers TSV (slug<TAB>image<TAB>hash<TAB>roothash)
// into slug → expected roothash. Used to verify that layers we rebuild
// locally produce the same verity tree the build host did.
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
// resulting roothash matches the orchestrator-claimed value (from the
// pushed lowers TSV). All-or-nothing: a single roothash mismatch (or
// any apt failure) leaves repo/ untouched and returns an error.
//
// Reproducibility caveats: this works ONLY when the local build
// produces byte-identical layer files to what the build host produced.
// Two factors:
//
//   - mkfs.ext4 determinism: handled by layer.MakeVerity's seed param
//     (-U + -E hash_seed= + veritysetup --uuid + --salt all derived
//     from the slug).
//   - Source content determinism: dpkg unpacking the same .deb on the
//     same arch yields the same file tree. Stage_files preserves mtimes
//     via tar -p (default behavior).
//
// If a roothash mismatch happens despite both, that points at a
// non-deterministic mkfs.ext4 detail we haven't pinned yet — fix
// upstream rather than weaken the check.
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

	// Build a list of pkg=version strings for apt and a slug → LayerRef map.
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
		"[serve] apt-get install %v in materialized chroot\n", aptPkgs)
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

	// Stage + verity-format each missing slug into a tmp dir; only move
	// to repo/ after roothash verification succeeds for ALL of them.
	stageRoot, err := os.MkdirTemp("", "pancake-rebuild-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stageRoot)

	type built struct {
		slug, repoDir, tmpImg, tmpHash, roothash string
		dataSize                                 int64
		desc, deps, arch                         string
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
		roothash, dataSize, err := layer.MakeVerity(stagingDir, tmpImg,
			"pk-"+truncateStr(L.Name, 12), 0, slug)
		if err != nil {
			return fmt.Errorf("make_verity %s: %w", L.Name, err)
		}
		if roothash != expected {
			return fmt.Errorf("layer %s roothash mismatch:\n  built    = %s\n  expected = %s\n"+
				"(deterministic-build invariant violated; either mkfs.ext4 / "+
				"veritysetup non-determinism or a different .deb version on this VM's apt repo)",
				slug, roothash, expected)
		}
		descRaw, _ := deb.PackageField(sb.Path, L.Name, "Description")
		depsRaw, _ := deb.PackageField(sb.Path, L.Name, "Depends")
		bs = append(bs, built{
			slug: slug, repoDir: filepath.Join(k.Repo(), slug),
			tmpImg: tmpImg, tmpHash: tmpImg + ".hash",
			roothash: roothash, dataSize: dataSize,
			desc: firstLine(descRaw), deps: depsRaw, arch: L.Version, // arch via L (TODO: include)
		})
	}

	// All built + verified. Move into repo/<slug>/ atomically (per layer).
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

// readManifestFromKit reads the three sidecar files for genID into a
// proto Manifest. Used by GetCurrentManifest and by `pancake orchestrate
// push --kit ...` (which builds a Manifest from a kit dir).
func readManifestFromKit(k *kit.Kit, genID int) (*orchpb.Manifest, error) {
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
	return &orchpb.Manifest{
		ManifestToml: mt,
		ManifestSig:  ms,
		Lowers:       lo,
	}, nil
}
