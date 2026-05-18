// bootstrap_builder_test.go: unit tests for buildImageRequest, the
// pure-data helper that shapes a BuildImageRequest from bootstrapArgs.
//
// These intentionally do NOT spin up a gRPC server or run mksquashfs.
// The point of the tests is to lock in the BRANCHING contract:
//
//   - platform empty / dev:   want_efi_disk = true, gcs_upload = nil
//   - platform gcp + bucket:  want_efi_disk = false, gcs_upload populated
//   - platform gcp + no bucket: same as dev (fallback to streaming)
//
// If a future change accidentally flips one of these branches, the
// local-dev loop breaks silently (artifacts disappear from the operator
// laptop) or the gcp path regresses to WAN-uploading. This test catches
// either before the build server is even built.

package main

import (
	"testing"
	"time"
)

// fixedNow is the timestamp we feed buildImageRequest so the GcsUpload
// object name is deterministic across runs.
var fixedNow = time.Date(2026, 5, 18, 14, 42, 2, 0, time.UTC)

func TestBuildImageRequest_LocalDev(t *testing.T) {
	args := bootstrapArgs{
		Platform:       "dev",
		ImagePath:      "/tmp/pancake-state.img",
		InitramfsPath:  "/tmp/pancake-initramfs.cpio.gz",
		BzImageOutPath: "/tmp/pancake-bzImage",
		EFIPath:        "/tmp/pancake-efi.img",
	}
	req := buildImageRequest(args, nil, fixedNow)

	if got, want := req.WantEfiDisk, true; got != want {
		t.Errorf("WantEfiDisk = %v, want %v (local dev MUST receive EFI bytes locally)", got, want)
	}
	if req.GcsUpload != nil {
		t.Errorf("GcsUpload = %+v, want nil (local dev must NOT trigger server-side upload)", req.GcsUpload)
	}
	if !req.WantDiskImage || !req.WantInitramfs || !req.WantBzimage {
		t.Errorf("local dev should request all artifacts; got DiskImage=%v Initramfs=%v Bzimage=%v",
			req.WantDiskImage, req.WantInitramfs, req.WantBzimage)
	}
}

func TestBuildImageRequest_PlatformEmptyTreatedAsDev(t *testing.T) {
	// Operators who haven't migrated their recipe yet may have no
	// 'platform:' line at all. Behavior must match dev: stream
	// everything, no GCS upload.
	args := bootstrapArgs{Platform: "", EFIPath: "/tmp/efi.img"}
	req := buildImageRequest(args, nil, fixedNow)

	if !req.WantEfiDisk {
		t.Error("empty Platform: WantEfiDisk should be true (treat as local dev)")
	}
	if req.GcsUpload != nil {
		t.Errorf("empty Platform: GcsUpload should be nil, got %+v", req.GcsUpload)
	}
}

func TestBuildImageRequest_GCPWithBucket(t *testing.T) {
	args := bootstrapArgs{
		Platform:       "gcp",
		EFIPath:        "/tmp/efi.img",
		InitramfsPath:  "/tmp/initramfs.cpio.gz",
		BzImageOutPath: "/tmp/bzImage",
		GCE: GCEUploadArgs{
			Project:     "test-proj",
			Bucket:      "pancake-images",
			CreateImage: true,
			ImageFamily: "pancake-os",
		},
	}
	req := buildImageRequest(args, nil, fixedNow)

	if req.WantEfiDisk {
		t.Error("gcp + bucket: WantEfiDisk should be FALSE (server uploads, doesn't stream)")
	}
	if req.GcsUpload == nil {
		t.Fatal("gcp + bucket: GcsUpload should be populated")
	}
	if req.GcsUpload.Bucket != "pancake-images" {
		t.Errorf("Bucket = %q, want %q", req.GcsUpload.Bucket, "pancake-images")
	}
	if got, want := req.GcsUpload.ObjectName, "pancake-os-20260518T144202Z.tar.gz"; got != want {
		t.Errorf("ObjectName = %q, want %q", got, want)
	}
	if !req.GcsUpload.CreateImage {
		t.Error("CreateImage should propagate (true in args, must be true on wire)")
	}
	if req.GcsUpload.ImageFamily != "pancake-os" || req.GcsUpload.Project != "test-proj" {
		t.Errorf("GcsUpload pass-through wrong: family=%q project=%q",
			req.GcsUpload.ImageFamily, req.GcsUpload.Project)
	}
	// The other Want* fields are still honoured (operator may still
	// want initramfs/bzimage locally for debugging).
	if !req.WantInitramfs || !req.WantBzimage {
		t.Error("Want{Initramfs,Bzimage} should still follow the recipe's output paths in gcp mode")
	}
}

func TestBuildImageRequest_GCPNoBucketFallsBackToStreaming(t *testing.T) {
	// Operator set platform=gcp but forgot gce.bucket. Don't break —
	// fall back to streaming the EFI image like local-dev so the build
	// still produces an output the operator can do something with.
	args := bootstrapArgs{Platform: "gcp", EFIPath: "/tmp/efi.img"}
	req := buildImageRequest(args, nil, fixedNow)

	if !req.WantEfiDisk {
		t.Error("gcp + NO bucket: should fall back to streaming (WantEfiDisk=true)")
	}
	if req.GcsUpload != nil {
		t.Errorf("gcp + NO bucket: GcsUpload should be nil, got %+v", req.GcsUpload)
	}
}

func TestBuildImageRequest_LegacyGCEAlias(t *testing.T) {
	// platform="gce" is the deprecated alias for "gcp" — same behavior.
	args := bootstrapArgs{
		Platform: "gce",
		EFIPath:  "/tmp/efi.img",
		GCE:      GCEUploadArgs{Bucket: "b"},
	}
	req := buildImageRequest(args, nil, fixedNow)
	if req.WantEfiDisk {
		t.Error("platform=gce alias: should suppress EFI streaming just like 'gcp'")
	}
	if req.GcsUpload == nil || req.GcsUpload.Bucket != "b" {
		t.Errorf("platform=gce alias: GcsUpload bucket not set correctly (%+v)", req.GcsUpload)
	}
}
