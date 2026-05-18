// bootstrap_builder.go: the thin-client bootstrap path.
//
// Operator runs `pancake bootstrap recipe.yaml`; this file is what
// happens next. It:
//
//   1. Dials the build server named in recipe.builder / --builder.
//   2. UploadBlob for each operator-supplied input that the server
//      can't reproduce: hostname (as tiny string blob), SSH
//      authorized_keys, optionally a custom-built bzImage + its
//      modules tarball.
//   3. Composes a BuildImageRequest carrying every layer the kit
//      needs — apt packages plus the synthetic recipes
//      (base, runtime, pancaked, pancake-host, orch-config, and
//      optionally kernel + modules). The server bakes everything;
//      no layer is built locally.
//   4. Calls BuildImage and streams the resulting artifacts (disk
//      image, initramfs, bzImage copy, signed UKI, EFI disk,
//      signed manifest, pubkey) directly to the recipe-specified
//      output paths.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sinkap/pancake/common/gen/go/buildpb"
	"github.com/sinkap/pancake/common/go/platform/gce"
	"github.com/sinkap/pancake/common/go/runner"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// wantsEFI reports whether the server should build the EFI disk for
// this run. True if the operator either:
//   - asked for a local EFI file (outputs.efi: in recipe), OR
//   - asked for a GCP GCS upload (platform=gcp + gce.bucket).
// Either trigger means "build the EFI"; the difference is only WHERE
// the bytes land (local disk vs server-side GCS upload).
func (a bootstrapArgs) wantsEFI() bool {
	if a.EFIPath != "" {
		return true
	}
	if (a.Platform == "gcp" || a.Platform == "gce") && a.GCE.Bucket != "" {
		return true
	}
	return false
}

// buildImageRequest assembles the BuildImageRequest for the wire. Pulled
// out of bootstrapViaBuilder so it's testable without dialing gRPC or
// running mksquashfs. `now` is plumbed in (rather than time.Now()) so
// tests can assert on the GcsUpload.ObjectName format deterministically.
func buildImageRequest(a bootstrapArgs, packages []*buildpb.Package, now time.Time) *buildpb.BuildImageRequest {
	wantsEFI := a.wantsEFI()
	req := &buildpb.BuildImageRequest{
		Packages:      packages,
		Cmdline:       a.Cmdline,
		KernelUname:   a.Kernel,
		WantDiskImage: a.ImagePath != "",
		WantInitramfs: a.InitramfsPath != "",
		WantBzimage:   a.BzImageOutPath != "",
		WantUki:       wantsEFI,
		WantEfiDisk:   wantsEFI && a.EFIPath != "", // local stream only when path set
		WantManifest:  true,
		WantPubkey:    true,
		Counter:       1,
		Description:   "initial generation (thin-client)",
	}
	// platform=gcp + bucket: server uploads EFI to GCS directly. Build
	// it on the server, but don't stream the bytes back. ObjectName
	// derives from gce.image-family when set (e.g.
	// pancake-os-20260518T192532Z.tar.gz), keeping the URI's "name in
	// the bucket" stable + meaningful.
	if (a.Platform == "gcp" || a.Platform == "gce") && a.GCE.Bucket != "" {
		stem := a.GCE.ImageFamily
		if stem == "" {
			stem = "pancake-os"
		}
		req.GcsUpload = &buildpb.GCSUpload{
			Bucket:      a.GCE.Bucket,
			ObjectName:  fmt.Sprintf("%s-%s.tar.gz", stem, now.UTC().Format("20060102T150405Z")),
			CreateImage: a.GCE.CreateImage,
			ImageFamily: a.GCE.ImageFamily,
			Project:     a.GCE.Project,
		}
		req.WantEfiDisk = false // server uploads, doesn't stream
	}
	return req
}

func bootstrapViaBuilder(a bootstrapArgs) error {
	if err := os.MkdirAll(a.Output, 0o755); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "[bootstrap] dialing builder %s\n", a.BuilderAddr)
	cc, err := grpc.NewClient(a.BuilderAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(64*1024*1024)))
	if err != nil {
		return fmt.Errorf("dial builder: %w", err)
	}
	defer cc.Close()
	cli := buildpb.NewPancakeBuilderServiceClient(cc)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// 1. Upload operator inputs as content-addressed blobs.
	uploadBytes := func(role string, content []byte) (string, error) {
		stream, err := cli.UploadBlob(ctx)
		if err != nil {
			return "", fmt.Errorf("upload %s: %w", role, err)
		}
		const cs = 1 << 20
		for off := 0; off < len(content); off += cs {
			end := off + cs
			if end > len(content) {
				end = len(content)
			}
			if err := stream.Send(&buildpb.BlobChunk{
				Data: content[off:end],
				Last: end == len(content),
			}); err != nil {
				return "", fmt.Errorf("upload %s send: %w", role, err)
			}
		}
		ref, err := stream.CloseAndRecv()
		if err != nil {
			return "", fmt.Errorf("upload %s close: %w", role, err)
		}
		return ref.Sha256, nil
	}
	uploadFile := func(role, path string) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s for upload: %w", path, err)
		}
		return uploadBytes(role, b)
	}

	// 1a. pancake-host inputs: hostname + SSH material.
	hostBlobs := map[string]string{}
	hn := a.Hostname
	if hn == "" {
		hn = "pancake"
	}
	if sha, err := uploadBytes("hostname", []byte(hn)); err != nil {
		return err
	} else {
		hostBlobs["hostname"] = sha
	}
	if a.SSHAuthKeysFile != "" {
		sha, err := uploadFile("ssh-authorized-keys", a.SSHAuthKeysFile)
		if err != nil {
			return err
		}
		hostBlobs["ssh-authorized-keys"] = sha
	}
	// Operator-supplied SSH host keys. When --ssh-host-keys is
	// empty the server generates fresh ones via ssh-keygen.
	if a.SSHHostKeysDir != "" {
		for _, kt := range []string{"rsa", "ecdsa", "ed25519"} {
			for _, suffix := range []string{"", ".pub"} {
				p := filepath.Join(a.SSHHostKeysDir,
					"ssh_host_"+kt+"_key"+suffix)
				if _, err := os.Stat(p); err != nil {
					continue
				}
				role := "ssh-host-" + kt + "-key" + suffix
				sha, err := uploadFile(role, p)
				if err != nil {
					return err
				}
				hostBlobs[role] = sha
			}
		}
	}

	// 1b. Custom kernel + modules (when --bzimage is set).
	var kernelBlobs, modulesBlobs map[string]string
	if a.BzImagePath != "" {
		sha, err := uploadFile("bzimage", a.BzImagePath)
		if err != nil {
			return err
		}
		kernelBlobs = map[string]string{"bzimage": sha}

		// Stage modules from kernel tree via `make modules_install` to
		// a temp dir, then tar for upload. This avoids touching the
		// host's /lib/modules.
		kernelSrcDir := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(a.BzImagePath)))) // /<tree>/arch/x86/boot/bzImage -> /<tree>
		modStageDir, err := os.MkdirTemp("", "pancake-modules-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(modStageDir)

		fmt.Fprintf(os.Stderr,
			"[bootstrap] staging modules from kernel tree via make modules_install\n")
		if err := runner.Run(runner.Cmd{
			Argv: []string{"sh", "-c",
				fmt.Sprintf("cd %s && make modules_install INSTALL_MOD_PATH=%s",
					kernelSrcDir, modStageDir)},
		}); err != nil {
			return fmt.Errorf("make modules_install: %w", err)
		}

		// Tar the staged lib/modules/<ver> tree.
		modSrc := filepath.Join(modStageDir, "lib/modules", a.Kernel)
		if _, err := os.Stat(modSrc); err != nil {
			return fmt.Errorf("modules staging failed: %s not found after "+
				"make modules_install", modSrc)
		}
		tarTmp, err := os.CreateTemp("", "modules-*.tar")
		if err != nil {
			return err
		}
		tarPath := tarTmp.Name()
		tarTmp.Close()
		defer os.Remove(tarPath)

		fmt.Fprintf(os.Stderr,
			"[bootstrap] tarring staged modules for upload\n")
		if err := runner.Run(runner.Cmd{
			Argv: []string{"tar", "-cf", tarPath,
				"-C", modStageDir,
				"lib"},
		}); err != nil {
			return fmt.Errorf("tar modules: %w", err)
		}
		sha, err = uploadFile("tarball", tarPath)
		if err != nil {
			return err
		}
		modulesBlobs = map[string]string{"tarball": sha}
	}

	// 2. Compose BuildImageRequest. APT packages first, then the
	// synthetic recipes the server stitches into the kit.
	pkgList := dedup(append(append([]string{}, SystemBaseline...), a.Packages...))
	if a.BzImagePath == "" {
		pkgList = append(pkgList, "linux-image-generic")
	}
	var packages []*buildpb.Package
	for _, name := range pkgList {
		packages = append(packages, &buildpb.Package{
			Manager: &buildpb.Package_Apt{Apt: &buildpb.APT{
				Name:   name,
				Suite:  a.Suite,
				Arch:   "amd64",
				Mirror: a.Mirror,
			}},
		})
	}
	addInternal := func(recipe, version string, blobs map[string]string) {
		packages = append(packages, &buildpb.Package{
			Manager: &buildpb.Package_Internal{
				Internal: &buildpb.PancakeInternal{
					Recipe:  recipe,
					Version: version,
					Blobs:   blobs,
				},
			},
		})
	}
	addInternal("base", "", nil)
	addInternal("runtime", "", nil)  // server uses bundled binaries
	// Pass hostname to pancaked so auto-enroll unit can hardcode the SAN
	packages = append(packages, &buildpb.Package{
		Manager: &buildpb.Package_Internal{
			Internal: &buildpb.PancakeInternal{
				Recipe:  "pancaked",
				Version: "2.0.0-autoenroll",
				Params: map[string]string{
					"hostname": hn,
				},
			},
		},
	})
	addInternal("pancake-host", "", hostBlobs)
	if a.Orch.hasURLs() {
		params := map[string]string{
			"ca-url": a.Orch.CAURL,
		}
		// Only include attest-ca-url if set (legacy dual-CA mode)
		if a.Orch.AttestCAURL != "" {
			params["attest-ca-url"] = a.Orch.AttestCAURL
		}
		// Fleet server URL for VM auto-enrollment (optional)
		if a.Orch.FleetServer != "" {
			params["fleet-server"] = a.Orch.FleetServer
		}
		// EK trust anchor selection (one of dev-ek-ca/manufacturer/google-vtpm)
		if a.Orch.EKTrust != "" {
			params["ek-trust"] = a.Orch.EKTrust
		}
		// Cert issuer selection (one of step-ca/gcp-cas)
		if a.Orch.IssuanceCA != "" {
			params["issuance-ca"] = a.Orch.IssuanceCA
		}
		// CAS pool resource name (required when issuance-ca=gcp-cas)
		if a.Orch.CASPool != "" {
			params["cas-pool"] = a.Orch.CASPool
		}
		packages = append(packages, &buildpb.Package{
			Manager: &buildpb.Package_Internal{
				Internal: &buildpb.PancakeInternal{
					Recipe: "orch-config",
					Params: params,
				},
			},
		})
	}
	if a.BzImagePath != "" {
		addInternal("kernel", a.Kernel, kernelBlobs)
		addInternal("modules", a.Kernel, modulesBlobs)
	}

	// 3. BuildImage.
	internalCount := 4 // base + runtime + pancaked + pancake-host
	if a.Orch.hasURLs() {
		internalCount++
	}
	if a.BzImagePath != "" {
		internalCount += 2 // kernel + modules
	}
	fmt.Fprintf(os.Stderr,
		"[bootstrap] BuildImage(%d apt + %d internal) — server-built\n",
		len(pkgList), internalCount)

	req := buildImageRequest(a, packages, time.Now())
	gcpUploadActive := req.GcsUpload != nil
	if gcpUploadActive {
		fmt.Fprintf(os.Stderr,
			"[bootstrap] gcs_upload: server will push EFI directly to %s/%s\n",
			a.GCE.Bucket, req.GcsUpload.ObjectName)
	}
	stream, err := cli.BuildImage(ctx, req)
	if err != nil {
		return fmt.Errorf("BuildImage: %w", err)
	}

	// 4. Stream artifacts to the requested output paths.
	artifactPath := map[buildpb.BuildImageChunk_Artifact]string{
		buildpb.BuildImageChunk_ARTIFACT_DISK_IMAGE: a.ImagePath,
		buildpb.BuildImageChunk_ARTIFACT_INITRAMFS:  a.InitramfsPath,
		buildpb.BuildImageChunk_ARTIFACT_BZIMAGE:    a.BzImageOutPath,
		buildpb.BuildImageChunk_ARTIFACT_EFI_DISK:   a.EFIPath,
	}
	files := map[buildpb.BuildImageChunk_Artifact]*os.File{}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()

	// MANIFEST emits three streams: body, sig, lowers.
	var manifestBody, manifestSig, lowers, pubkeyPEM []byte
	var gcsInfoJSON []byte
	manifestPhase := 0

	for {
		c, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("BuildImage stream: %w", err)
		}
		switch c.Artifact {
		case buildpb.BuildImageChunk_ARTIFACT_GCS_INFO:
			// Server uploaded the EFI image to GCS; a single chunk
			// carries the metadata. last=true is expected but the
			// append-and-keep-going pattern below is robust to either.
			gcsInfoJSON = append(gcsInfoJSON, c.Data...)
		case buildpb.BuildImageChunk_ARTIFACT_MANIFEST:
			switch manifestPhase {
			case 0:
				manifestBody = append(manifestBody, c.Data...)
				if c.Last {
					manifestPhase = 1
				}
			case 1:
				manifestSig = append(manifestSig, c.Data...)
				if c.Last {
					manifestPhase = 2
				}
			case 2:
				lowers = append(lowers, c.Data...)
			}
		case buildpb.BuildImageChunk_ARTIFACT_PUBKEY:
			pubkeyPEM = append(pubkeyPEM, c.Data...)
		default:
			path := artifactPath[c.Artifact]
			if path == "" {
				continue
			}
			f, ok := files[c.Artifact]
			if !ok {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					return err
				}
				nf, err := os.Create(path)
				if err != nil {
					return err
				}
				f = nf
				files[c.Artifact] = f
				fmt.Fprintf(os.Stderr,
					"[bootstrap] receiving %s → %s\n",
					c.Artifact, path)
			}
			if len(c.Data) > 0 {
				if _, err := f.Write(c.Data); err != nil {
					return err
				}
			}
		}
	}

	// 5. Write the kit's on-disk layout (generations/1/...) so
	// pancake attest finds manifest.toml + lowers + sig at the same
	// paths the VM has them.
	genDir := filepath.Join(a.Output, "generations", "1")
	if err := os.MkdirAll(genDir, 0o755); err != nil {
		return err
	}
	if len(manifestBody) > 0 {
		if err := os.WriteFile(filepath.Join(genDir, "manifest.toml"), manifestBody, 0o644); err != nil {
			return err
		}
	}
	if len(manifestSig) > 0 {
		if err := os.WriteFile(filepath.Join(genDir, "manifest.toml.sig"), manifestSig, 0o644); err != nil {
			return err
		}
	}
	if len(lowers) > 0 {
		if err := os.WriteFile(filepath.Join(genDir, "lowers"), lowers, 0o644); err != nil {
			return err
		}
	}
	if len(pubkeyPEM) > 0 {
		if err := os.WriteFile(filepath.Join(a.Output, "manifest.pubkey"), pubkeyPEM, 0o644); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr,
		"[bootstrap] done — kit + artifacts under %s\n", a.Output)

	// Platform-specific post-processing.
	switch {
	case gcpUploadActive:
		// Server already did the upload + (optionally) image create.
		// Parse the metadata blob and print the operator-visible URI.
		var info struct {
			GCSURI    string `json:"gcs_uri"`
			ImageName string `json:"image_name"`
			SizeBytes int64  `json:"size_bytes"`
		}
		if len(gcsInfoJSON) == 0 {
			return fmt.Errorf("gcs_upload requested but server emitted no GCS_INFO chunk")
		}
		if err := json.Unmarshal(gcsInfoJSON, &info); err != nil {
			return fmt.Errorf("parse GCS_INFO: %w (raw=%q)", err, gcsInfoJSON)
		}
		fmt.Fprintf(os.Stderr,
			"[bootstrap] image uploaded server-side: %s (%d MB)\n",
			info.GCSURI, info.SizeBytes>>20)
		if info.ImageName != "" {
			fmt.Fprintf(os.Stderr,
				"[bootstrap] GCE image created: %s\n", info.ImageName)
		}
	case a.Platform == "gce":
		// Legacy fallback: bucket wasn't set, do the client-side upload
		// path the way we used to. Only triggers when the operator
		// somehow set Platform=gce without a bucket; the gcpUploadActive
		// branch above is the normal case.
		if err := uploadToGCE(ctx, a); err != nil {
			return fmt.Errorf("gce upload: %w", err)
		}
	}
	return nil
}

// uploadToGCE handles the platform=gce flow: convert local EFI image to
// the GCE tar.gz format, upload to the configured GCS bucket, and
// optionally create a GCE custom image via the Compute API.
func uploadToGCE(ctx context.Context, a bootstrapArgs) error {
	if a.EFIPath == "" {
		return fmt.Errorf("platform=gce requires outputs.efi to be set (no EFI image was built)")
	}
	if a.GCE.Bucket == "" {
		return fmt.Errorf("platform=gce requires gce.bucket in recipe (where to upload)")
	}

	fmt.Fprintf(os.Stderr,
		"[bootstrap] platform=gce: converting %s to GCE tar.gz\n", a.EFIPath)

	stagingDir := filepath.Join(a.Output, "gce-staging")
	tarPath, err := gce.ConvertToGCETarGz(a.EFIPath, stagingDir)
	if err != nil {
		return fmt.Errorf("convert to tar.gz: %w", err)
	}
	defer os.Remove(tarPath) // keep stagingDir for visibility, drop the big archive

	// Build object name: pancake-os-<timestamp>.tar.gz
	objectName := fmt.Sprintf("pancake-os-%s.tar.gz",
		time.Now().UTC().Format("20060102-150405"))

	// Normalize bucket spec: caller may give "gs://bucket" or "bucket".
	bucketSpec := a.GCE.Bucket
	gsPath := bucketSpec + "/" + objectName

	fmt.Fprintf(os.Stderr, "[bootstrap] uploading to %s\n", gsPath)
	uri, err := gce.UploadToGCS(ctx, tarPath, gsPath)
	if err != nil {
		return fmt.Errorf("upload to GCS: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[bootstrap] uploaded: %s\n", uri)

	imageName := ""
	if a.GCE.CreateImage {
		if a.GCE.Project == "" {
			return fmt.Errorf("gce.create-image requires gce.project")
		}
		// Image name = object name minus .tar.gz, GCE-name-safe
		imageName = "pancake-os-" + time.Now().UTC().Format("20060102-150405")
		fmt.Fprintf(os.Stderr,
			"[bootstrap] creating GCE image %s (family=%s, project=%s)\n",
			imageName, a.GCE.ImageFamily, a.GCE.Project)
		if err := gce.CreateGCEImage(ctx, uri, imageName, a.GCE.ImageFamily, a.GCE.Project); err != nil {
			return fmt.Errorf("create GCE image: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[bootstrap] image created: %s\n", imageName)
	}

	// Print next steps
	fmt.Fprintln(os.Stderr, "\n[bootstrap] platform=gce: ready to deploy.")
	fmt.Fprintf(os.Stderr, "  GCS object: %s\n", uri)
	if imageName != "" {
		fmt.Fprintf(os.Stderr, "  GCE image:  %s\n", imageName)
		fmt.Fprintln(os.Stderr, "  Create instance:")
		fmt.Fprintf(os.Stderr,
			"    gcloud compute instances create test-vm \\\n"+
				"      --image=%s --image-project=%s \\\n"+
				"      --enable-vtpm --shielded-secure-boot \\\n"+
				"      --machine-type=n2-standard-2\n",
			imageName, a.GCE.Project)
	} else {
		fmt.Fprintln(os.Stderr, "  Create GCE image:")
		fmt.Fprintf(os.Stderr,
			"    gcloud compute images create pancake-os-v1 \\\n"+
				"      --source-uri=%s \\\n"+
				"      --guest-os-features=UEFI_COMPATIBLE,GVNIC,SEV_CAPABLE\n",
			uri)
	}
	return nil
}
