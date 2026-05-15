// Package server implements the pancake-build-server gRPC service:
// builds and caches pancake-os verity layers on behalf of clients.
//
// Cache layout (Opts.CacheDir):
//
//   layers/<roothash>/
//     image.img
//     image.hash
//     image.roothash
//     manifest.toml
//   blobs/<sha256>            (uploads; not implemented in v1)
//   work/<random>/            (per-build sandbox dirs; cleaned on success)
//
// v1 scope: BuildGeneration + GetLayer. Other RPCs return Unimplemented.
package server

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/sign"
)

type Server struct {
	buildpb.UnimplementedPancakeBuilderServer
	cacheDir       string
	bundledBinsDir string
	// signer routes UKI + manifest signing through whatever the
	// server is configured to use: sign.LocalSigner for in-process
	// PEM-on-disk signing (dev / single-machine compose), or a
	// gRPC client to the pancake-sign service for the production
	// trust-isolation shape. Nil = no signing (returns unsigned
	// artifacts, which is appropriate for layer-cache pre-warm
	// calls that don't need bootable output).
	signer sign.Signer
}

type Opts struct {
	CacheDir string
	// BundledBinsDir is the directory where the server's container
	// image stages canonical binaries (pancake, pancaked,
	// mount-overlay, pivot-root) for use as recipe-input fallbacks
	// when the operator doesn't upload override blobs. Empty
	// disables the fallback (operator must upload everything).
	BundledBinsDir string
	// Signer (optional): when set, AssembleImage and any future
	// signed-artifact path routes through it. See Server.signer.
	Signer sign.Signer
}

func New(o Opts) (*Server, error) {
	if o.CacheDir == "" {
		return nil, fmt.Errorf("server: CacheDir required")
	}
	for _, sub := range []string{"layers", "blobs", "work", "staging"} {
		if err := os.MkdirAll(filepath.Join(o.CacheDir, sub), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", sub, err)
		}
	}
	return &Server{
		cacheDir:       o.CacheDir,
		bundledBinsDir: o.BundledBinsDir,
		signer:         o.Signer,
	}, nil
}

func (s *Server) layerDir(roothash string) string {
	return filepath.Join(s.cacheDir, "layers", roothash)
}

// layerStagingDir is the per-layer cached staging tree: the
// pre-verity file layout that bakeStaged copied into image.img.
// Synthetic recipes (kernel, modules, runtime, pancaked, host,
// orch-config) save their staging here so AssembleImage can read
// /boot/vmlinuz, /lib/modules/<ver>, etc. without loop-mounting
// the verity image. Empty when the layer was built via bakeLayer
// (per-package APT path), which doesn't preserve staging.
func (s *Server) layerStagingDir(roothash string) string {
	return filepath.Join(s.cacheDir, "staging", roothash)
}

func (s *Server) newWorkDir() (string, error) {
	return os.MkdirTemp(filepath.Join(s.cacheDir, "work"), "build-")
}
