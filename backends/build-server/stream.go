package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// chunk is the wire-side payload size per LayerChunk message. Picked
// to fit comfortably under gRPC's default 4 MiB max message size.
const chunk = 256 * 1024

// SEEK_DATA / SEEK_HOLE — Linux lseek extensions for traversing
// sparse files. Available since 3.1; we're on much newer kernels.
const (
	seekData = 3
	seekHole = 4
)

// GetLayer streams artifact bytes for a previously built layer. The
// roothash is the canonical key; we look at cache/layers/<roothash>/.
//
// req.Want filters which parts to send (default: all four). req.Offset
// and req.Length apply only to LAYER_PART_IMAGE; HASH/MANIFEST/ROOTHASH
// always send in full.
func (s *Server) GetLayer(
	req *buildpb.GetLayerRequest,
	stream buildpb.PancakeBuilder_GetLayerServer,
) error {
	dir := s.layerDir(req.Roothash)
	if _, err := os.Stat(dir); err != nil {
		return status.Errorf(codes.NotFound,
			"layer %s not in cache", req.Roothash)
	}

	want := req.Want
	if len(want) == 0 {
		want = []buildpb.LayerPart{
			buildpb.LayerPart_LAYER_PART_IMAGE,
			buildpb.LayerPart_LAYER_PART_HASH,
			buildpb.LayerPart_LAYER_PART_MANIFEST,
			buildpb.LayerPart_LAYER_PART_ROOTHASH,
		}
	}

	for _, part := range want {
		path, ok := layerPartPath(dir, part)
		if !ok {
			continue
		}
		if part == buildpb.LayerPart_LAYER_PART_IMAGE {
			// IMAGE files are typically large + sparse (mkfs.ext4
			// of a barely-filled volume). Walk only the data
			// extents to save wire bandwidth + client disk.
			if err := streamSparseImage(stream, part, path,
				req.Offset, req.Length); err != nil {
				return err
			}
		} else {
			// Other parts are small + dense; send contiguously.
			if err := streamFile(stream, part, path, 0, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// streamSparseImage walks the file via SEEK_DATA/SEEK_HOLE and emits
// chunks only for non-hole regions, each tagged with its file offset.
// Client recreates sparseness via WriteAt + final Truncate.
func streamSparseImage(
	stream buildpb.PancakeBuilder_GetLayerServer,
	part buildpb.LayerPart,
	path string,
	clientOffset, clientLength int64,
) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	fileSize := fi.Size()

	// Honor optional client-supplied offset/length.
	startAt := clientOffset
	endAt := fileSize
	if clientLength > 0 && startAt+clientLength < endAt {
		endAt = startAt + clientLength
	}

	pos := startAt
	buf := make([]byte, chunk)
	for pos < endAt {
		// Find next data extent at or after `pos`.
		dataAt, err := f.Seek(pos, seekData)
		if err != nil {
			// ENXIO from SEEK_DATA = no more data; rest is hole.
			if errors.Is(err, syscall.ENXIO) {
				break
			}
			return fmt.Errorf("seek_data %s: %w", path, err)
		}
		if dataAt >= endAt {
			break
		}
		// Find end of this data extent (next hole or EOF).
		holeAt, err := f.Seek(dataAt, seekHole)
		if err != nil {
			holeAt = endAt
		}
		if holeAt > endAt {
			holeAt = endAt
		}
		// Read+send the [dataAt, holeAt) range in chunks.
		if _, err := f.Seek(dataAt, io.SeekStart); err != nil {
			return err
		}
		cur := dataAt
		for cur < holeAt {
			n := int64(len(buf))
			if n > holeAt-cur {
				n = holeAt - cur
			}
			nr, rerr := f.Read(buf[:n])
			if nr > 0 {
				if err := stream.Send(&buildpb.LayerChunk{
					Part:   part,
					Data:   buf[:nr],
					Offset: cur,
				}); err != nil {
					return err
				}
				cur += int64(nr)
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return fmt.Errorf("read %s: %w", path, rerr)
			}
		}
		pos = holeAt
	}
	// Terminator: empty chunk at fileSize signals "this is the
	// real EOF; client should Truncate to this offset."
	return stream.Send(&buildpb.LayerChunk{
		Part:   part,
		Last:   true,
		Offset: endAt,
	})
}

func layerPartPath(dir string, part buildpb.LayerPart) (string, bool) {
	switch part {
	case buildpb.LayerPart_LAYER_PART_IMAGE:
		return filepath.Join(dir, "image.img"), true
	case buildpb.LayerPart_LAYER_PART_HASH:
		return filepath.Join(dir, "image.hash"), true
	case buildpb.LayerPart_LAYER_PART_MANIFEST:
		return filepath.Join(dir, "manifest.toml"), true
	case buildpb.LayerPart_LAYER_PART_ROOTHASH:
		return filepath.Join(dir, "image.roothash"), true
	}
	return "", false
}

func streamFile(
	stream buildpb.PancakeBuilder_GetLayerServer,
	part buildpb.LayerPart,
	path string,
	offset, length int64,
) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return fmt.Errorf("seek %s: %w", path, err)
		}
	}

	remaining := int64(-1)
	if length > 0 {
		remaining = length
	}
	buf := make([]byte, chunk)
	for {
		n := len(buf)
		if remaining >= 0 && int64(n) > remaining {
			n = int(remaining)
		}
		if n == 0 {
			// Send terminator chunk.
			return stream.Send(&buildpb.LayerChunk{Part: part, Last: true})
		}
		nr, err := f.Read(buf[:n])
		if nr > 0 {
			last := false
			if err == io.EOF || (remaining > 0 && int64(nr) == remaining) {
				last = true
			}
			if err := stream.Send(&buildpb.LayerChunk{
				Part: part, Data: buf[:nr], Last: last,
			}); err != nil {
				return err
			}
			if remaining > 0 {
				remaining -= int64(nr)
			}
			if last {
				return nil
			}
		}
		if err == io.EOF {
			return stream.Send(&buildpb.LayerChunk{Part: part, Last: true})
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
	}
}
