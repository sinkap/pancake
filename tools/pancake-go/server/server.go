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
)

type Server struct {
	buildpb.UnimplementedPancakeBuilderServer
	cacheDir string
}

type Opts struct {
	CacheDir string
}

func New(o Opts) (*Server, error) {
	if o.CacheDir == "" {
		return nil, fmt.Errorf("server: CacheDir required")
	}
	for _, sub := range []string{"layers", "blobs", "work"} {
		if err := os.MkdirAll(filepath.Join(o.CacheDir, sub), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", sub, err)
		}
	}
	return &Server{cacheDir: o.CacheDir}, nil
}

func (s *Server) layerDir(roothash string) string {
	return filepath.Join(s.cacheDir, "layers", roothash)
}

func (s *Server) newWorkDir() (string, error) {
	return os.MkdirTemp(filepath.Join(s.cacheDir, "work"), "build-")
}
