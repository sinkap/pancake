// Package gce: image conversion + GCS upload + GCE image creation.
//
// Bootstrap calls these helpers transparently when recipe.platform == "gce".
// All auth uses Application Default Credentials:
//   - Local dev: `gcloud auth application-default login`
//   - GCE: instance service account
//   - CI: $GOOGLE_APPLICATION_CREDENTIALS = service account JSON
package gce

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"cloud.google.com/go/storage"
)

// ConvertToGCETarGz converts a raw disk image to GCE's required format:
// a tar.gz containing exactly one file named "disk.raw".
//
// efiImg is the path to the source raw disk image (e.g. pancake-efi.img).
// outDir is where the resulting .tar.gz is written.
// Returns the path to the created tar.gz file.
func ConvertToGCETarGz(efiImg, outDir string) (string, error) {
	src, err := os.Open(efiImg)
	if err != nil {
		return "", fmt.Errorf("open source image: %w", err)
	}
	defer src.Close()

	fi, err := src.Stat()
	if err != nil {
		return "", fmt.Errorf("stat source image: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir output: %w", err)
	}
	outPath := filepath.Join(outDir, "image.tar.gz")

	dst, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("create output: %w", err)
	}
	defer dst.Close()

	gzw := gzip.NewWriter(dst)
	defer gzw.Close()
	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// GCE requires the disk image inside the tar to be named "disk.raw"
	hdr := &tar.Header{
		Name:    "disk.raw",
		Mode:    0o644,
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
		Format:  tar.FormatGNU,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return "", fmt.Errorf("write tar header: %w", err)
	}
	if _, err := io.Copy(tw, src); err != nil {
		return "", fmt.Errorf("copy image into tar: %w", err)
	}

	// Close in reverse order, propagate errors
	if err := tw.Close(); err != nil {
		return "", fmt.Errorf("close tar: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return "", fmt.Errorf("close gzip: %w", err)
	}
	if err := dst.Close(); err != nil {
		return "", fmt.Errorf("close output file: %w", err)
	}

	return outPath, nil
}

// UploadToGCS uploads local to gsPath. gsPath may be either:
//   - "gs://bucket/object"
//   - "bucket/object"
//   - "bucket" (object name derived from local basename)
//
// Returns the canonical "gs://bucket/object" URI of the uploaded object.
func UploadToGCS(ctx context.Context, local, gsPath string) (string, error) {
	bucket, object, err := parseGSPath(gsPath, filepath.Base(local))
	if err != nil {
		return "", err
	}

	client, err := storage.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("storage client (check Application Default Credentials): %w", err)
	}
	defer client.Close()

	f, err := os.Open(local)
	if err != nil {
		return "", fmt.Errorf("open local file: %w", err)
	}
	defer f.Close()

	w := client.Bucket(bucket).Object(object).NewWriter(ctx)
	if _, err := io.Copy(w, f); err != nil {
		w.Close()
		return "", fmt.Errorf("upload to gs://%s/%s: %w", bucket, object, err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("close GCS writer: %w", err)
	}

	return fmt.Sprintf("gs://%s/%s", bucket, object), nil
}

// CreateGCEImage creates a GCE custom image from an object in GCS.
// gsURI is the source URI ("gs://bucket/object.tar.gz").
// imageName must be unique within the project.
// imageFamily is optional (empty string = no family).
// project is the GCP project ID.
//
// The created image has guest-os features UEFI_COMPATIBLE, GVNIC, SEV_CAPABLE
// to support modern GCE features (Secure Boot, gVNIC networking,
// Confidential Computing).
func CreateGCEImage(ctx context.Context, gsURI, imageName, imageFamily, project string) error {
	client, err := compute.NewImagesRESTClient(ctx)
	if err != nil {
		return fmt.Errorf("compute images client: %w", err)
	}
	defer client.Close()

	img := &computepb.Image{
		Name:        ptr(imageName),
		Description: ptr("pancake-os image uploaded by `pancake bootstrap`"),
		RawDisk: &computepb.RawDisk{
			Source: ptr(httpsURIForGSPath(gsURI)),
		},
		GuestOsFeatures: []*computepb.GuestOsFeature{
			{Type: ptr("UEFI_COMPATIBLE")},
			{Type: ptr("GVNIC")},
			{Type: ptr("SEV_CAPABLE")},
		},
	}
	if imageFamily != "" {
		img.Family = ptr(imageFamily)
	}

	op, err := client.Insert(ctx, &computepb.InsertImageRequest{
		Project:      project,
		ImageResource: img,
	})
	if err != nil {
		return fmt.Errorf("insert image: %w", err)
	}
	if err := op.Wait(ctx); err != nil {
		return fmt.Errorf("wait for image creation: %w", err)
	}
	return nil
}

// parseGSPath normalizes a user-supplied GCS path.
// Examples:
//
//	"gs://my-bucket/foo.tar.gz" → bucket="my-bucket", object="foo.tar.gz"
//	"my-bucket/foo.tar.gz"      → bucket="my-bucket", object="foo.tar.gz"
//	"my-bucket"                  → bucket="my-bucket", object=defaultName
func parseGSPath(p, defaultName string) (bucket, object string, err error) {
	p = strings.TrimPrefix(p, "gs://")
	p = strings.Trim(p, "/")
	if p == "" {
		return "", "", fmt.Errorf("empty GCS path")
	}
	parts := strings.SplitN(p, "/", 2)
	bucket = parts[0]
	if len(parts) == 2 && parts[1] != "" {
		object = parts[1]
	} else {
		object = defaultName
	}
	return bucket, object, nil
}

// httpsURIForGSPath converts gs://bucket/object to the HTTPS form
// GCE's Image.RawDisk.Source expects.
func httpsURIForGSPath(gs string) string {
	stripped := strings.TrimPrefix(gs, "gs://")
	return "https://storage.googleapis.com/" + stripped
}

func ptr[T any](v T) *T { return &v }
