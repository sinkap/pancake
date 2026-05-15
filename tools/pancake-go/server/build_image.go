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

	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/deb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/efi"
	"github.com/sinkap/pancake/tools/pancake-go/internal/initramfs"
	"github.com/sinkap/pancake/tools/pancake-go/internal/pack"
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
	Manifest  []byte // signed generation manifest (toml + sibling .sig)
	ManifestSig []byte
	PubkeyPEM []byte
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
	var initramfsPath string
	if req.WantInitramfs || req.WantUKI || req.WantEFIDisk {
		initramfsPath = filepath.Join(work, "pancake-initramfs.cpio.gz")
		modulesDir := s.unpackedModulesDirIfPresent(gm, req.KernelUname)
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
			KVer:            req.KernelUname,
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

	// 5. Bzimage copy (used by QEMU's -kernel arg). Sourced from
	// the unpacked pancake-kernel layer when present; otherwise
	// from the suite's linux-image-* package's /boot.
	var bzimagePath string
	if req.WantBzImage || req.WantUKI || req.WantEFIDisk {
		bzimagePath, err = s.findKernelBzImage(gm)
		if err != nil {
			return nil, fmt.Errorf("find bzImage: %w", err)
		}
		if req.WantBzImage {
			out.BzImage, err = os.ReadFile(bzimagePath)
			if err != nil {
				return nil, err
			}
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
			UName:   req.KernelUname,
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

	// 8. Sign the generation manifest via s.signer (if set).
	// BuildGeneration left manifest_sig empty — Phase 5's
	// sign-server is the one trust boundary that fills it in.
	if req.WantManifest {
		out.Manifest = gm.ManifestToml
		if s.signer != nil {
			sig, err := s.signer.SignManifest(ctx, gm.ManifestToml)
			if err != nil {
				return nil, fmt.Errorf("signer.SignManifest: %w", err)
			}
			out.ManifestSig = sig
		}
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
		if err := os.Symlink(src, dst); err != nil {
			return fmt.Errorf("symlink %s → %s: %w", dst, src, err)
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

// unpackedModulesDirIfPresent returns the layer-staging cache dir
// for the pancake-modules layer that matches kver, when present.
// initramfs.Build reads <return>/lib/modules/<kver>/ from there
// without having to loop-mount the verity image.
//
// Returns "" when no matching modules layer is in the generation
// (initramfs.Build then falls back to /lib/modules on the host).
func (s *Server) unpackedModulesDirIfPresent(
	gm *buildpb.GenerationManifest, kver string,
) string {
	for _, h := range gm.Layer {
		if h.Name != "pancake-modules" {
			continue
		}
		// Match the version (kver) — multiple module layers
		// could in principle coexist, only the one matching the
		// kernel we're building applies.
		if h.Version != kver {
			continue
		}
		st := s.layerStagingDir(h.Roothash)
		if _, err := os.Stat(st); err == nil {
			return st
		}
	}
	return ""
}

// findKernelBzImage returns the path to /boot/vmlinuz inside the
// staging cache of the pancake-kernel layer in this generation.
// Falls through to scanning a linux-image-* layer's /boot when no
// custom kernel was uploaded.
func (s *Server) findKernelBzImage(
	gm *buildpb.GenerationManifest,
) (string, error) {
	for _, h := range gm.Layer {
		if h.Name == "pancake-kernel" {
			p := filepath.Join(s.layerStagingDir(h.Roothash), "boot", "vmlinuz")
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	// Fall back to a linux-image-* layer's /boot/vmlinuz-*. Those
	// layers are baked via bakeLayer (APT path) which doesn't
	// preserve staging — return an actionable error explaining how
	// to enable the staged path.
	return "", fmt.Errorf("findKernelBzImage: no pancake-kernel " +
		"layer with cached staging in this generation. Either " +
		"upload a custom kernel via the kernel recipe (operator " +
		"side) or extend the APT bakeLayer path to optionally " +
		"preserve staging (server side, future work)")
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
