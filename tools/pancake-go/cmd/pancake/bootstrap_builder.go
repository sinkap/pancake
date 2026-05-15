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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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
	cli := buildpb.NewPancakeBuilderClient(cc)
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

		// Tar /lib/modules/<a.Kernel> for the modules layer.
		modSrc := filepath.Join("/lib/modules", a.Kernel)
		if _, err := os.Stat(modSrc); err != nil {
			return fmt.Errorf("--bzimage given but %s missing — pass "+
				"--kernel <ver> matching the bzImage and ensure "+
				"`make modules_install` has been run", modSrc)
		}
		tarTmp, err := os.CreateTemp("", "modules-*.tar")
		if err != nil {
			return err
		}
		tarPath := tarTmp.Name()
		tarTmp.Close()
		defer os.Remove(tarPath)
		fmt.Fprintf(os.Stderr,
			"[bootstrap] tarring %s for modules layer upload\n", modSrc)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"tar", "-cf", tarPath,
				"-C", filepath.Dir(modSrc), filepath.Base(modSrc)},
			Sudo: true,
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
	addInternal("pancaked", "", nil) // server uses bundled binary
	addInternal("pancake-host", "", hostBlobs)
	if a.Orch.hasURLs() {
		packages = append(packages, &buildpb.Package{
			Manager: &buildpb.Package_Internal{
				Internal: &buildpb.PancakeInternal{
					Recipe: "orch-config",
					Params: map[string]string{
						"ca-url":        a.Orch.CAURL,
						"attest-ca-url": a.Orch.AttestCAURL,
					},
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
		internalCount += 2
	}
	fmt.Fprintf(os.Stderr,
		"[bootstrap] BuildImage(%d apt + %d internal) — server-built\n",
		len(pkgList), internalCount)

	req := &buildpb.BuildImageRequest{
		Packages:      packages,
		Cmdline:       a.Cmdline,
		KernelUname:   a.Kernel,
		WantDiskImage: a.ImagePath != "",
		WantInitramfs: a.InitramfsPath != "",
		WantBzimage:   a.BzImageOutPath != "",
		WantUki:       a.EFIPath != "",
		WantEfiDisk:   a.EFIPath != "",
		WantManifest:  true,
		WantPubkey:    true,
		Counter:       1,
		Description:   "initial generation (thin-client)",
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

	// MANIFEST emits two streams sequentially: body then sig.
	var manifestBody, manifestSig, pubkeyPEM []byte
	manifestBodyDone := false

	for {
		c, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("BuildImage stream: %w", err)
		}
		switch c.Artifact {
		case buildpb.BuildImageChunk_ARTIFACT_MANIFEST:
			if !manifestBodyDone {
				manifestBody = append(manifestBody, c.Data...)
				if c.Last {
					manifestBodyDone = true
				}
			} else {
				manifestSig = append(manifestSig, c.Data...)
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

	// 5. Write the manifest sidecar trio.
	if len(manifestBody) > 0 {
		manifestPath := filepath.Join(a.Output, "manifest.toml")
		if err := os.WriteFile(manifestPath, manifestBody, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[bootstrap] manifest → %s\n", manifestPath)
	}
	if len(manifestSig) > 0 {
		if err := os.WriteFile(filepath.Join(a.Output, "manifest.toml.sig"),
			manifestSig, 0o644); err != nil {
			return err
		}
	}
	if len(pubkeyPEM) > 0 {
		if err := os.WriteFile(filepath.Join(a.Output, "manifest.pubkey"),
			pubkeyPEM, 0o644); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr,
		"[bootstrap] done — kit + artifacts under %s\n", a.Output)
	return nil
}
