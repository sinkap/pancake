package server

import (
	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
)

// BuildImage is the gRPC handler that exposes AssembleImage on the
// wire. Translates the proto request to AssembleImageRequest, runs
// the assembly, and streams BuildImageChunk for each artifact field
// the operator asked for via the corresponding Want* boolean.
//
// Stream shape per artifact:
//   1..N   data chunks  (last==false)
//   1      terminator   (last==true, possibly empty data)
//
// Image-style artifacts (DISK_IMAGE, EFI_DISK) could later become
// sparse-aware by walking SEEK_DATA/SEEK_HOLE; v1 sends one
// contiguous chunk per artifact since AssembleImage returns the
// bytes as []byte.
func (s *Server) BuildImage(
	req *buildpb.BuildImageRequest,
	stream buildpb.PancakeBuilder_BuildImageServer,
) error {
	res, err := s.AssembleImage(stream.Context(), &AssembleImageRequest{
		Packages:      req.GetPackages(),
		Cmdline:       req.GetCmdline(),
		KernelUname:   req.GetKernelUname(),
		WantDiskImage: req.GetWantDiskImage(),
		WantInitramfs: req.GetWantInitramfs(),
		WantBzImage:   req.GetWantBzimage(),
		WantUKI:       req.GetWantUki(),
		WantEFIDisk:   req.GetWantEfiDisk(),
		WantManifest:  req.GetWantManifest(),
		WantPubkey:    req.GetWantPubkey(),
		SigningKeyID:  req.GetSigningKeyId(),
		Parent:        req.GetParent(),
		Counter:       req.GetCounter(),
		Description:   req.GetDescription(),
	})
	if err != nil {
		return err
	}

	type emit struct {
		kind  buildpb.BuildImageChunk_Artifact
		bytes []byte
	}
	for _, e := range []emit{
		{buildpb.BuildImageChunk_ARTIFACT_DISK_IMAGE, res.DiskImage},
		{buildpb.BuildImageChunk_ARTIFACT_INITRAMFS, res.Initramfs},
		{buildpb.BuildImageChunk_ARTIFACT_BZIMAGE, res.BzImage},
		{buildpb.BuildImageChunk_ARTIFACT_UKI, res.UKI},
		{buildpb.BuildImageChunk_ARTIFACT_EFI_DISK, res.EFIDisk},
		{buildpb.BuildImageChunk_ARTIFACT_MANIFEST, res.Manifest},
		{buildpb.BuildImageChunk_ARTIFACT_PUBKEY, res.PubkeyPEM},
	} {
		if len(e.bytes) == 0 {
			continue
		}
		if err := streamArtifact(stream, e.kind, e.bytes); err != nil {
			return err
		}
	}
	// Manifest signature, when present, rides along as a sibling
	// chunk under the same MANIFEST artifact kind, distinguished by
	// the fact that it follows the manifest's terminator. v1
	// keeps it simple: emit it as a separate MANIFEST chunk if
	// non-empty (clients need to handle sequential MANIFEST emits).
	if len(res.ManifestSig) > 0 {
		if err := streamArtifact(stream,
			buildpb.BuildImageChunk_ARTIFACT_MANIFEST, res.ManifestSig); err != nil {
			return err
		}
	}
	if len(res.Lowers) > 0 {
		if err := streamArtifact(stream,
			buildpb.BuildImageChunk_ARTIFACT_MANIFEST, res.Lowers); err != nil {
			return err
		}
	}
	return nil
}

// streamArtifact splits payload into ~1 MiB gRPC frames, marking
// the final frame Last=true. Holding 1 MiB per frame gives gRPC
// some headroom under its default 4 MiB per-message limit.
func streamArtifact(
	stream buildpb.PancakeBuilder_BuildImageServer,
	kind buildpb.BuildImageChunk_Artifact, payload []byte,
) error {
	const chunkSize = 1 << 20 // 1 MiB
	if len(payload) == 0 {
		return stream.Send(&buildpb.BuildImageChunk{
			Artifact: kind, Last: true,
		})
	}
	var off int64
	for off < int64(len(payload)) {
		end := off + chunkSize
		if end > int64(len(payload)) {
			end = int64(len(payload))
		}
		last := end == int64(len(payload))
		if err := stream.Send(&buildpb.BuildImageChunk{
			Artifact: kind,
			Data:     payload[off:end],
			Offset:   off,
			Last:     last,
		}); err != nil {
			return err
		}
		off = end
	}
	return nil
}
