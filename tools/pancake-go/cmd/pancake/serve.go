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

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/orchpb"
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
	if err := fs.Parse(args); err != nil {
		return 2
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

	// 3. Layer-presence check. Every referenced slug MUST already be
	// in kit/repo/. Layer delivery is out-of-band by design.
	var missing []string
	for _, L := range gm.Layer {
		slug := filepath.Base(filepath.Dir(L.Manifest))
		if _, err := os.Stat(filepath.Join(s.k.Repo(), slug, "image.img")); err != nil {
			missing = append(missing, slug)
		}
	}
	if len(missing) > 0 {
		return &orchpb.UpdateResponse{
			MissingLayerSlugs: missing,
			Error: fmt.Sprintf("VM is missing %d layers; ship them via "+
				"pancake install or future PushLayer", len(missing)),
		}, nil
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
