// builder_client.go: pancaked-as-buildpb-client. Auto-fetches missing
// layers from a configured pancake-build-server when an Update arrives
// referencing layers we don't have locally. Closes the
// "orchestrator pushes manifest → VM heals from cache" loop.
//
// The build server's GetLayer is content-addressed by roothash. The
// generation manifest's lowers TSV carries (slug, image_rel,
// hash_rel, roothash) — we use roothash as the lookup key, write
// streamed bytes into kit/repo/<slug>/{image.img,image.hash,
// manifest.toml,image.roothash} matching the on-disk layout the
// initramfs expects.

package orchsrv

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
)

// fetchLayersFromBuilder pulls every requested layer from the build
// server (one streamed GetLayer per layer) and writes the artifacts
// into the local repo/<slug>/ dirs. Returns nil if all layers were
// fetched successfully; the caller re-checks presence afterwards.
//
// The roothash for each slug comes from the manifest's lowers TSV;
// the build server only knows layers by roothash.
func (s *server) fetchLayersFromBuilder(
	missing []kit.LayerRef, lowers []byte,
) error {
	if s.builderClient == nil {
		return fmt.Errorf("no builder configured")
	}
	roothashBySlug, err := parseLowersRoothashes(lowers)
	if err != nil {
		return fmt.Errorf("parse lowers: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	for _, L := range missing {
		slug := filepath.Base(filepath.Dir(L.Manifest))
		rh, ok := roothashBySlug[slug]
		if !ok || rh == "" {
			return fmt.Errorf("layer %s: no roothash in lowers", slug)
		}
		dest := filepath.Join(s.k.Repo(), slug)
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dest, err)
		}
		fmt.Fprintf(os.Stderr,
			"[pancaked] fetching missing layer %s (roothash %s…) from %s\n",
			slug, rh[:16], s.builderAddr)
		if err := pullLayerStream(ctx, s.builderClient, rh, dest); err != nil {
			return fmt.Errorf("GetLayer %s: %w", slug, err)
		}
	}
	return nil
}

// pullLayerStream is the receive half of build server GetLayer:
// stream of LayerChunk records, sparse-aware for the IMAGE part
// (server uses SEEK_DATA/SEEK_HOLE; client uses WriteAt + final
// Truncate to recreate the sparse file the same way bootstrap does).
//
// Mirrors cmd/pancake/bootstrap_builder.go's pullLayer; kept
// duplicated for the v1 — both will move to a shared
// internal/builderclient package once a third caller appears.
func pullLayerStream(
	ctx context.Context,
	cli buildpb.PancakeBuilderClient,
	roothash string,
	dest string,
) error {
	stream, err := cli.GetLayer(ctx, &buildpb.GetLayerRequest{
		Roothash: roothash,
	})
	if err != nil {
		return err
	}
	files := map[buildpb.LayerPart]*os.File{}
	imageEOF := int64(-1)
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	pathFor := func(p buildpb.LayerPart) string {
		switch p {
		case buildpb.LayerPart_LAYER_PART_IMAGE:
			return filepath.Join(dest, "image.img")
		case buildpb.LayerPart_LAYER_PART_HASH:
			return filepath.Join(dest, "image.hash")
		case buildpb.LayerPart_LAYER_PART_MANIFEST:
			return filepath.Join(dest, "manifest.toml")
		case buildpb.LayerPart_LAYER_PART_ROOTHASH:
			return filepath.Join(dest, "image.roothash")
		}
		return ""
	}
	for {
		c, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		f, ok := files[c.Part]
		if !ok {
			p := pathFor(c.Part)
			if p == "" {
				continue
			}
			nf, err := os.Create(p)
			if err != nil {
				return err
			}
			f = nf
			files[c.Part] = f
		}
		if len(c.Data) > 0 {
			if c.Part == buildpb.LayerPart_LAYER_PART_IMAGE {
				if _, err := f.WriteAt(c.Data, c.Offset); err != nil {
					return err
				}
			} else {
				if _, err := f.Write(c.Data); err != nil {
					return err
				}
			}
		}
		if c.Last && c.Part == buildpb.LayerPart_LAYER_PART_IMAGE {
			imageEOF = c.Offset
		}
	}
	if f, ok := files[buildpb.LayerPart_LAYER_PART_IMAGE]; ok && imageEOF >= 0 {
		if err := f.Truncate(imageEOF); err != nil {
			return fmt.Errorf("truncate image.img to %d: %w", imageEOF, err)
		}
	}
	return nil
}
