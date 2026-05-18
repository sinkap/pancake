// gcs_upload.go: server-side handler for the GCSUpload field on
// BuildImageRequest. Wraps internal/platform/gce/image.go (the same
// code path the CLI used to call client-side before this refactor)
// so the build server can push the EFI image directly to GCS using
// its own ADC.
//
// On the GCE build VM, ADC = pancake-build-server@<proj>.iam GSA,
// which terraform grants roles/storage.objectAdmin (for the upload)
// + roles/compute.storageAdmin (for the optional image create).

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sinkap/pancake/common/go/platform/gce"
)

// uploadEFIToGCS converts the on-disk EFI image to tar.gz, uploads to
// GCS, optionally creates a GCE image, and returns a JSON metadata
// blob the streamer ships back as ARTIFACT_GCS_INFO data.
func (s *Server) uploadEFIToGCS(
	ctx context.Context, efiPath string, opts *GCSUploadOpts,
) ([]byte, error) {
	if opts.Bucket == "" {
		return nil, fmt.Errorf("gcs_upload: bucket required")
	}
	if opts.ObjectName == "" {
		return nil, fmt.Errorf("gcs_upload: object_name required")
	}
	if opts.CreateImage && opts.Project == "" {
		return nil, fmt.Errorf("gcs_upload: project required when create_image=true")
	}

	// 1. Stage the tar.gz in the same working tree as the EFI image.
	workDir := filepath.Dir(efiPath)
	tarPath, err := gce.ConvertToGCETarGz(efiPath, workDir)
	if err != nil {
		return nil, fmt.Errorf("ConvertToGCETarGz: %w", err)
	}
	defer os.Remove(tarPath)

	// 2. Upload. ObjectName may already be prefixed with the bucket
	// (gs://bucket/object); gce.UploadToGCS will parse either shape,
	// but we normalise here for the metadata we return.
	gsPath := opts.ObjectName
	if !strings.Contains(gsPath, "/") || strings.HasPrefix(gsPath, "gs://") {
		// object_name didn't include a bucket prefix; assemble.
		bucket := strings.TrimPrefix(opts.Bucket, "gs://")
		gsPath = fmt.Sprintf("gs://%s/%s", bucket, opts.ObjectName)
	}
	uploadedURI, err := gce.UploadToGCS(ctx, tarPath, gsPath)
	if err != nil {
		return nil, fmt.Errorf("UploadToGCS: %w", err)
	}
	// UploadToGCS normalises gs://-prefixed paths and returns the
	// canonical URI; prefer it in the metadata we ship to the client.
	if uploadedURI != "" {
		gsPath = uploadedURI
	}

	// 3. Optional: create a GCE image referencing the uploaded tar.gz.
	imageName := opts.ImageName
	if imageName == "" {
		imageName = deriveImageName(opts.ObjectName)
	}
	if opts.CreateImage {
		if err := gce.CreateGCEImage(
			ctx, gsPath, imageName, opts.ImageFamily, opts.Project,
		); err != nil {
			return nil, fmt.Errorf("CreateGCEImage: %w", err)
		}
	}

	// 4. Metadata blob the client will print as a single chunk.
	fi, _ := os.Stat(tarPath)
	var size int64
	if fi != nil {
		size = fi.Size()
	}
	type info struct {
		GCSURI    string `json:"gcs_uri"`
		ImageName string `json:"image_name,omitempty"`
		SizeBytes int64  `json:"size_bytes"`
	}
	out := info{GCSURI: gsPath, SizeBytes: size}
	if opts.CreateImage {
		out.ImageName = imageName
	}
	return json.Marshal(out)
}

// deriveImageName strips a typical "pancake-os-XYZ.tar.gz" suffix to
// produce a valid GCE image name. Lowercases + replaces dots/underscores
// with dashes (GCE image-name rules: [a-z]([-a-z0-9]*[a-z0-9])?).
func deriveImageName(objectName string) string {
	base := filepath.Base(objectName)
	base = strings.TrimSuffix(base, ".tar.gz")
	base = strings.TrimSuffix(base, ".tgz")
	base = strings.ToLower(base)
	repl := func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '-':
			return r
		case r == '_', r == '.':
			return '-'
		}
		return '-'
	}
	return strings.Map(repl, base)
}
