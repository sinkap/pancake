// build_image.go: the operator-facing one-shot assembly path.
//
// AssembleImage is the engine behind the BuildImage RPC defined in
// build.proto (the matching gRPC handler is wired in once `protoc`
// regenerates internal/buildpb — see HACKING.md for the regen
// command). Today AssembleImage is reachable as a Server method so
// the Phase 5 sign-server hookup and any Go-level integration tests
// can drive it without going through gRPC.
//
// Pipeline (client used to run all of these locally; the move
// server-side is the whole point of the thin-client refactor):
//
//   1. BuildGeneration → layer handles + signed kit manifest
//   2. Materialize kit on disk (symlinks into the layer cache)
//   3. pack.Disk            → ext4 disk image (optional)
//   4. initramfs.Build      → cpio.gz (optional; bundled init +
//                             mount-overlay binary)
//   5. efi.BuildUKI         → UKI .efi (optional; signed via
//                             s.signer when set)
//   6. efi.PackEFIDisk      → bootable ESP+rootfs disk (optional)
//   7. sign.SignManifest    → manifest.toml.sig (via s.signer)
//   8. Return all bytes in AssembleImageResult.

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/deb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/efi"
	"github.com/sinkap/pancake/tools/pancake-go/internal/initramfs"
	"github.com/sinkap/pancake/tools/pancake-go/internal/pack"
	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"
	"github.com/sinkap/pancake/tools/pancake-go/internal/sign"
)

// AssembleImageRequest mirrors BuildImageRequest in build.proto. It
// stays a Go-native struct until protoc regen exposes the proto
// version; the field set is identical so swapping is mechanical.
type AssembleImageRequest struct {
	// Same package set BuildGeneration takes.
	Packages []*buildpb.Package

	// Assembly knobs.
	Cmdline     string
	KernelUname string

	WantDiskImage bool
	WantInitramfs bool
	WantBzImage   bool
	WantUKI       bool
	WantEFIDisk   bool
	WantManifest  bool
	WantPubkey    bool

	SigningKeyID string

	Parent      int32
	Counter     int32
	Description string
}

// AssembleImageResult bundles every artifact produced by a single
// BuildImage call. Only fields the caller asked for via Want* are
// populated; the rest stay nil. Streaming back to the wire (when the
// proto-generated BuildImageChunk type lands) iterates these fields.
type AssembleImageResult struct {
	DiskImage []byte
	Initramfs []byte
	BzImage   []byte
	UKI       []byte
	EFIDisk   []byte
	Manifest    []byte
	ManifestSig []byte
	Lowers      []byte
	PubkeyPEM   []byte
}

// AssembleImage runs the BuildImage pipeline. Caller-side work is
// limited to "stream the resulting bytes wherever you want them."
func (s *Server) AssembleImage(
	ctx context.Context, req *AssembleImageRequest,
) (*AssembleImageResult, error) {
	// 1. BuildGeneration — reuses every layer the operator just
	// uploaded blobs for.
	gm, err := s.BuildGeneration(ctx, &buildpb.BuildGenerationRequest{
		Packages:      req.Packages,
		Parent:        req.Parent,
		Counter:       req.Counter,
		Description:   req.Description,
		SigningKeyId:  req.SigningKeyID,
	})
	if err != nil {
		return nil, fmt.Errorf("BuildGeneration: %w", err)
	}

	// Sign the generation manifest BEFORE materializing the kit
	// so manifest.toml.sig is included in the on-disk kit (and
	// therefore in the disk image + EFI disk packed from it).
	// /init refuses to mount when manifest.pubkey is baked into
	// the initramfs but the sig is missing on disk.
	if s.signer != nil {
		sig, err := s.signer.SignManifest(ctx, gm.ManifestToml)
		if err != nil {
			return nil, fmt.Errorf("signer.SignManifest: %w", err)
		}
		gm.ManifestSig = sig
	}

	// 2. Materialize kit dir from the cache. Each layer's
	// image.img / image.hash / manifest.toml / image.roothash live
	// at <cache>/layers/<roothash>/; we symlink them into a
	// transient kit dir at <work>/kit/repo/<dirName>/. The cache
	// stays canonical; the kit is a per-build view.
	work, err := s.newWorkDir()
	if err != nil {
		return nil, fmt.Errorf("workdir: %w", err)
	}
	defer os.RemoveAll(work)

	kitDir := filepath.Join(work, "kit")
	if err := s.materializeKit(kitDir, gm); err != nil {
		return nil, fmt.Errorf("materialize kit: %w", err)
	}

	out := &AssembleImageResult{}

	// 3. Disk image (ext4 with the kit).
	if req.WantDiskImage {
		imgPath := filepath.Join(work, "pancake-state.img")
		if err := pack.Disk(kitDir, imgPath); err != nil {
			return nil, fmt.Errorf("pack.Disk: %w", err)
		}
		out.DiskImage, err = os.ReadFile(imgPath)
		if err != nil {
			return nil, err
		}
	}

	// 4. Initramfs — server-bundled init script + mount-overlay
	// binary, modules from the unpacked pancake-modules layer (when
	// the recipe shipped one) or the host's /lib/modules fallback.
	// Find kernel + modules first so we know the actual KVer
	// before any artifact assembly. KVer for the apt path may
	// differ from req.KernelUname (server takes whatever apt
	// installed); custom-kernel path uses req.KernelUname.
	var bzimagePath, kver string
	if req.WantInitramfs || req.WantUKI || req.WantEFIDisk || req.WantBzImage {
		bzimagePath, kver, err = s.findKernel(gm, req.KernelUname)
		if err != nil {
			return nil, fmt.Errorf("find kernel: %w", err)
		}
	}

	var initramfsPath string
	if req.WantInitramfs || req.WantUKI || req.WantEFIDisk {
		initramfsPath = filepath.Join(work, "pancake-initramfs.cpio.gz")
		modulesDir := s.findModulesDir(gm, kver)
		var pubBytes []byte
		if s.signer != nil {
			cert, err := s.signer.Cert(ctx)
			if err != nil {
				return nil, fmt.Errorf("signer.Cert: %w", err)
			}
			pub, err := pubkeyFromCertBytes(cert)
			if err != nil {
				return nil, fmt.Errorf("derive pubkey: %w", err)
			}
			pubBytes = pub
			if req.WantPubkey {
				out.PubkeyPEM = pub
			}
		}
		if err := initramfs.Build(initramfs.Opts{
			OutPath:         initramfsPath,
			KVer:            kver,
			ModulesDir:      modulesDir,
			InitSrcPath:     filepath.Join(s.bundledBinsDir, "init"),
			MountOverlayBin: filepath.Join(s.bundledBinsDir, "mount-overlay"),
			PubKeyBytes:     pubBytes,
		}); err != nil {
			return nil, fmt.Errorf("initramfs.Build: %w", err)
		}
		if req.WantInitramfs {
			out.Initramfs, err = os.ReadFile(initramfsPath)
			if err != nil {
				return nil, err
			}
		}
	}

	// 5. Bzimage copy (used by QEMU's -kernel arg). bzimagePath
	// was already resolved by findKernel above.
	if req.WantBzImage {
		out.BzImage, err = os.ReadFile(bzimagePath)
		if err != nil {
			return nil, err
		}
	}

	// 6. UKI (signed via s.signer when set).
	var ukiPath string
	if req.WantUKI || req.WantEFIDisk {
		ukiPath = filepath.Join(work, "pancake.uki.efi")
		if err := efi.BuildUKI(efi.UKIOpts{
			Linux:   bzimagePath,
			Initrd:  initramfsPath,
			Cmdline: req.Cmdline,
			Out:     ukiPath,
			UName:   kver,
			Signer:  s.signer,
		}); err != nil {
			return nil, fmt.Errorf("efi.BuildUKI: %w", err)
		}
		if req.WantUKI {
			out.UKI, err = os.ReadFile(ukiPath)
			if err != nil {
				return nil, err
			}
		}
	}

	// 7. EFI disk (GPT + ESP + rootfs).
	if req.WantEFIDisk {
		efiPath := filepath.Join(work, "pancake-efi.img")
		if err := efi.PackEFIDisk(efi.EFIDiskOpts{
			Out:    efiPath,
			KitDir: kitDir,
			UKI:    ukiPath,
			GenID:  int(gm.GenerationId),
		}); err != nil {
			return nil, fmt.Errorf("efi.PackEFIDisk: %w", err)
		}
		out.EFIDisk, err = os.ReadFile(efiPath)
		if err != nil {
			return nil, err
		}
	}



	if req.WantManifest {
		out.Manifest = gm.ManifestToml
		out.ManifestSig = gm.ManifestSig
		out.Lowers = gm.Lowers
	}
	return out, nil
}

// materializeKit lays out the kit on disk by symlinking each layer's
// cached artifacts into <kitDir>/repo/<dirName>/, then writing the
// generation manifest + lowers the same way kit.WriteGenerationManifest
// would, and finally pointing the `current` symlink.
func (s *Server) materializeKit(
	kitDir string, gm *buildpb.GenerationManifest,
) error {
	repo := filepath.Join(kitDir, "repo")
	gen1 := filepath.Join(kitDir, "generations", "1")
	for _, d := range []string{repo, gen1} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	for _, h := range gm.Layer {
		dirName := h.Name
		if h.Version != "" {
			dirName = fmt.Sprintf("%s-%s", h.Name, deb.SlugifyVersion(h.Version))
		}
		src := s.layerDir(h.Roothash)
		dst := filepath.Join(repo, dirName)
		// cp -al: hardlink files into the kit dir (zero copy when
		// the cache + workdir live on the same filesystem, which
		// they do inside the build server container). Plain
		// symlinks break once pack.Disk seals the kit into a fresh
		// ext4 image — the symlink targets only exist on the build
		// server, not inside the resulting disk.
		if err := runner.Run(runner.Cmd{
			Argv: []string{"cp", "-al", src, dst},
		}); err != nil {
			return fmt.Errorf("cp -al %s → %s: %w", src, dst, err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(gen1, "manifest.toml"),
		gm.ManifestToml, 0o644); err != nil {
		return err
	}
	if len(gm.ManifestSig) > 0 {
		if err := os.WriteFile(
			filepath.Join(gen1, "manifest.toml.sig"),
			gm.ManifestSig, 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(
		filepath.Join(gen1, "lowers"),
		gm.Lowers, 0o644); err != nil {
		return err
	}
	if err := os.Symlink("generations/1",
		filepath.Join(kitDir, "current")); err != nil {
		return err
	}
	return nil
}

// findKernel returns (path-to-bzImage, kernel-version) for the
// generation. Search order:
//
//  1. pancake-kernel layer — operator-uploaded custom bzImage.
//     Caller-provided kver (in.KernelUname) is authoritative.
//  2. linux-image-* APT layer — scan its staging cache for
//     /boot/vmlinuz-<X>; return that vmlinuz + the discovered X
//     as the kernel version.
//
// Returns an error when neither is found. The kver discovered in
// case (2) overrides in.KernelUname so the rest of the pipeline
// uses the kernel apt actually installed.
func (s *Server) findKernel(
	gm *buildpb.GenerationManifest, requestedKver string,
) (path, kver string, err error) {
	// (1) custom kernel layer wins
	for _, h := range gm.Layer {
		if h.Name == "pancake-kernel" {
			p := filepath.Join(s.layerStagingDir(h.Roothash),
				"boot", "vmlinuz")
			if _, e := os.Stat(p); e == nil {
				return p, requestedKver, nil
			}
		}
	}
	// (2) apt linux-image-*'s /boot/vmlinuz-<ver>
	for _, h := range gm.Layer {
		if !strings.HasPrefix(h.Name, "linux-image-") {
			continue
		}
		st := s.layerStagingDir(h.Roothash)
		bootDir := filepath.Join(st, "boot")
		ents, e := os.ReadDir(bootDir)
		if e != nil {
			continue
		}
		for _, ent := range ents {
			if !strings.HasPrefix(ent.Name(), "vmlinuz-") {
				continue
			}
			ver := strings.TrimPrefix(ent.Name(), "vmlinuz-")
			return filepath.Join(bootDir, ent.Name()), ver, nil
		}
	}
	return "", "", fmt.Errorf("findKernel: no pancake-kernel layer " +
		"with cached staging and no linux-image-* layer with " +
		"/boot/vmlinuz-* in its staging cache")
}

// findModulesDir returns the layer-staging dir whose
// /lib/modules/<kver>/ subtree exists. Search order matches
// findKernel: pancake-modules layer first, then linux-modules-*
// layer. Returns "" when not found (initramfs.Build then falls
// back to host /lib/modules — useful only when host kernel
// matches kver, which it usually doesn't).
func (s *Server) findModulesDir(
	gm *buildpb.GenerationManifest, kver string,
) string {
	check := func(roothash string) string {
		st := s.layerStagingDir(roothash)
		if _, err := os.Stat(filepath.Join(st, "lib/modules", kver)); err == nil {
			return st
		}
		return ""
	}
	for _, h := range gm.Layer {
		if h.Name == "pancake-modules" && h.Version == kver {
			if d := check(h.Roothash); d != "" {
				return d
			}
		}
	}
	for _, h := range gm.Layer {
		if strings.HasPrefix(h.Name, "linux-modules-") ||
			strings.HasPrefix(h.Name, "linux-image-") {
			if d := check(h.Roothash); d != "" {
				return d
			}
		}
	}
	return ""
}

// pubkeyFromCertBytes parses a PEM cert and returns its
// SubjectPublicKeyInfo as a PEM PUBLIC KEY block. Same operation
// sign.PubkeyFromCert does for files; this version is byte-in /
// byte-out so we don't have to spill the cert to disk.
func pubkeyFromCertBytes(certPEM []byte) ([]byte, error) {
	tmp, err := os.CreateTemp("", "pancake-cert-*.pem")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(certPEM); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Close()
	pubPath := tmpPath + ".pub"
	defer os.Remove(pubPath)
	if err := sign.PubkeyFromCert(tmpPath, pubPath); err != nil {
		return nil, err
	}
	return os.ReadFile(pubPath)
}
