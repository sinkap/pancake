package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
)

// UploadBlob streams arbitrary bytes (kernel bzImage, modules tarball,
// pancake binary, SSH key, even a tiny string like a hostname) and
// returns its sha256. Cached at <cacheDir>/blobs/<sha256>; re-uploads
// of the same content are idempotent (no-op write).
func (s *Server) UploadBlob(stream buildpb.PancakeBuilder_UploadBlobServer) error {
	tmp, err := os.CreateTemp(filepath.Join(s.cacheDir, "work"), "blob-*")
	if err != nil {
		return fmt.Errorf("blob: tmpfile: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		if _, err := os.Stat(tmpPath); err == nil {
			os.Remove(tmpPath)
		}
	}

	h := sha256.New()
	var size int64
	for {
		c, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			tmp.Close()
			cleanup()
			return err
		}
		if len(c.Data) > 0 {
			n, werr := tmp.Write(c.Data)
			if werr != nil {
				tmp.Close()
				cleanup()
				return werr
			}
			h.Write(c.Data[:n])
			size += int64(n)
		}
		if c.Last {
			break
		}
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	final := s.blobPath(sum)
	if _, err := os.Stat(final); err == nil {
		// Identical content already cached.
		cleanup()
	} else {
		if err := os.Rename(tmpPath, final); err != nil {
			cleanup()
			return fmt.Errorf("blob: rename → %s: %w", final, err)
		}
	}
	return stream.SendAndClose(&buildpb.BlobReference{
		Sha256: sum,
		Size:   size,
	})
}

// blobPath returns the canonical on-disk path for a blob.
func (s *Server) blobPath(sha string) string {
	return filepath.Join(s.cacheDir, "blobs", sha)
}

// readBlob reads a previously-uploaded blob's contents.
func (s *Server) readBlob(sha string) ([]byte, error) {
	if sha == "" {
		return nil, fmt.Errorf("readBlob: empty sha")
	}
	b, err := os.ReadFile(s.blobPath(sha))
	if err != nil {
		return nil, fmt.Errorf("blob %s: %w", sha, err)
	}
	return b, nil
}

// blobOrBundled returns the blob bytes when sha is non-empty; otherwise
// reads the server-bundled fallback file under bundledBinsDir/role.
// One of the two must yield bytes — when both are missing, returns an
// error naming the role so operator-side debugging is easy.
func (s *Server) blobOrBundled(sha, role string) ([]byte, error) {
	if sha != "" {
		return s.readBlob(sha)
	}
	if s.bundledBinsDir == "" {
		return nil, fmt.Errorf("blob role %q: no operator-uploaded blob and "+
			"server has no --bundled-bins-dir configured", role)
	}
	p := filepath.Join(s.bundledBinsDir, role)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("blob role %q (no upload, fell back to "+
			"bundled %s): %w", role, p, err)
	}
	return b, nil
}
