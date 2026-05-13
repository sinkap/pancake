// bootstrap_builder.go: alternate bootstrap path that delegates the
// heavy work (mmdebstrap, per-package layer building, orphan
// extraction) to a remote pancake-build-server over gRPC. Client still
// builds per-host layers (pancake-host) and synthetic kernel layers
// locally — those have either per-host inputs or build-host inputs
// that don't belong in a shared cache.
//
// Wire: BuildGeneration(packages + base recipe) → []LayerHandle, then
// GetLayer for each to pull bytes into kit/repo/<dir>/.
//
// v1 SCOPE: APT layers + pancake-base come from the server. The
// pancake CLI runtime layer (pancake binary, helpers, systemd units),
// pancaked daemon layer, kernel/modules layers, and per-host layer
// all stay client-built (server doesn't yet implement those recipes).
// For v1 we skip the runtime + pancaked layers entirely — kits boot
// and sshd works, but no in-VM `pancake` CLI.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/deb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/efi"
	"github.com/sinkap/pancake/tools/pancake-go/internal/initramfs"
	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/pack"
	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"
	"github.com/sinkap/pancake/tools/pancake-go/internal/sign"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func bootstrapViaBuilder(a bootstrapArgs) error {
	if err := os.MkdirAll(a.Output, 0o755); err != nil {
		return err
	}
	repo := filepath.Join(a.Output, "repo")
	gen1 := filepath.Join(a.Output, "generations", "1")
	for _, d := range []string{repo, gen1} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	// 1. Connect to builder.
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

	// 2. Compose Package list: SystemBaseline + recipe.Packages, all
	// as APT entries (server pulls deps via mmdebstrap), plus the
	// "base" PancakeInternal recipe to get the orphans layer.
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
	packages = append(packages, &buildpb.Package{
		Manager: &buildpb.Package_Internal{
			Internal: &buildpb.PancakeInternal{Recipe: "base"},
		},
	})

	// 3. BuildGeneration.
	fmt.Fprintf(os.Stderr,
		"[bootstrap] BuildGeneration(%d packages + base) — this runs mmdebstrap server-side, may take a few minutes\n",
		len(pkgList))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	gen, err := cli.BuildGeneration(ctx, &buildpb.BuildGenerationRequest{
		Packages:    packages,
		Parent:      0,
		Counter:     1,
		Description: "initial generation (server-built)",
	})
	if err != nil {
		return fmt.Errorf("BuildGeneration: %w", err)
	}
	fmt.Fprintf(os.Stderr,
		"[bootstrap] server returned %d layer handles\n", len(gen.Layer))

	// 4. For each LayerHandle, GetLayer → write into kit/repo/<dir>/.
	for _, h := range gen.Layer {
		dir := h.Name
		if h.Version != "" {
			dir = fmt.Sprintf("%s-%s", h.Name, deb.SlugifyVersion(h.Version))
		}
		dest := filepath.Join(repo, dir)
		if err := pullLayer(ctx, cli, h, dest); err != nil {
			return fmt.Errorf("pull %s: %w", dir, err)
		}
	}

	// 4b. If signing is requested, ensure the dev key+cert pair
	// exists BEFORE the runtime layer is packed (it embeds
	// manifest.pubkey extracted from the cert) and BEFORE the
	// generation manifest gets signed below.
	if a.SignKey != "" && a.SignCert != "" {
		hn := a.Hostname
		if hn == "" {
			hn = "pancake"
		}
		if generated, err := sign.EnsureKeyAndCert(
			a.SignKey, a.SignCert, hn); err != nil {
			return fmt.Errorf("sign-key/sign-cert: %w", err)
		} else if generated {
			fmt.Fprintf(os.Stderr,
				"\n[bootstrap] generated dev signing pair:\n"+
					"  key:  %s\n  cert: %s\n", a.SignKey, a.SignCert)
		}
	} else if a.SignKey != "" || a.SignCert != "" {
		return fmt.Errorf("--sign-key and --sign-cert must both be set")
	}

	// 5. Build pancake-host locally (per-host inputs).
	tmp, err := os.MkdirTemp("", "pancake-host-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	var laidOuts []laidOut
	for _, h := range gen.Layer {
		dir := h.Name
		if h.Version != "" {
			dir = fmt.Sprintf("%s-%s", h.Name, deb.SlugifyVersion(h.Version))
		}
		laidOuts = append(laidOuts, laidOut{h.Name, h.Version, h.Arch, dir})
	}
	laidOuts, err = packPancakeHostLayer(tmp, repo, laidOuts, a)
	if err != nil {
		return fmt.Errorf("pancake-host: %w", err)
	}

	// 5b. pancake-runtime layer: ships the systemd generator that
	// enables networkd at boot (without it: no DHCP, no SSH).
	laidOuts, err = packPancakeRuntimeLayer(tmp, repo, laidOuts, a)
	if err != nil {
		return fmt.Errorf("pancake-runtime: %w", err)
	}

	// 5c. pancaked daemon layer: the in-VM agent that serves the
	// orchestrator (and now the Attest RPC). Same packer the
	// classic path uses.
	laidOuts, err = packPancakedLayer(tmp, repo, laidOuts, a)
	if err != nil {
		return fmt.Errorf("pancaked: %w", err)
	}

	// 6. Custom kernel + modules layers (when --bzimage given).
	if a.BzImagePath != "" {
		laidOuts, err = packCustomKernel(tmp, repo, laidOuts, a)
		if err != nil {
			return fmt.Errorf("custom kernel: %w", err)
		}
	}

	// 7. Compose final generation manifest in the order:
	//   pancake-host, pancake-base, pancaked (skip in v1), pancake-kernel,
	//   pancake-modules, then per-package APTs.
	overlay := orderLayers(laidOuts)
	gm := kit.GenerationManifest{
		Generation: kit.GenerationBlock{
			ID: 1, Parent: 0, Counter: 1,
			Description: fmt.Sprintf(
				"initial generation, server-built (%d layers)",
				len(overlay)),
		},
	}
	for _, L := range overlay {
		gm.Layer = append(gm.Layer, kit.LayerRef{
			Name: L.Name, Version: L.Version,
			Manifest: fmt.Sprintf("repo/%s/manifest.toml", L.Dir),
		})
	}
	k := &kit.Kit{Dir: a.Output}
	if err := kit.WriteGenerationManifest(k, gm); err != nil {
		return fmt.Errorf("WriteGenerationManifest: %w", err)
	}
	if err := k.SetCurrent(1); err != nil {
		return err
	}

	// Sign the generation manifest if signing was configured. Same
	// logic as the classic path (sign.SignManifest writes a sibling
	// .sig file the initramfs verifies before mounting).
	if a.SignKey != "" {
		manifestPath := filepath.Join(k.Generations(), "1", "manifest.toml")
		if _, err := sign.SignManifest(manifestPath, a.SignKey); err != nil {
			return fmt.Errorf("sign manifest: %w", err)
		}
		fmt.Fprintf(os.Stderr,
			"  → signed %s.sig\n", manifestPath)
	}

	fmt.Fprintf(os.Stderr,
		"\n[bootstrap] kit ready at %s (%d layers, server+client built)\n",
		a.Output, len(overlay))

	// 8. Pack disk image, build initramfs, hand off bzImage — same
	// post-build steps as the classic bootstrap path.
	if a.ImagePath != "" {
		fmt.Fprintf(os.Stderr,
			"\n[bootstrap] packing disk image → %s\n", a.ImagePath)
		if err := pack.Disk(a.Output, a.ImagePath); err != nil {
			return fmt.Errorf("pack: %w", err)
		}
	}
	if a.InitramfsPath != "" {
		fmt.Fprintf(os.Stderr,
			"\n[bootstrap] building initramfs (kernel=%s) → %s\n",
			a.Kernel, a.InitramfsPath)
		srcRoot := a.SrcRoot
		if srcRoot == "" {
			if exe, err := os.Executable(); err == nil {
				srcRoot = filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(exe))))
			}
		}
		// Bake manifest.pubkey into initramfs when signing is on, so
		// /init can verify the manifest signature before mounting.
		var pubkeyPath string
		if a.SignCert != "" {
			pubkeyPath = filepath.Join(a.Output, ".pancake-manifest.pubkey")
			if err := sign.PubkeyFromCert(a.SignCert, pubkeyPath); err != nil {
				return fmt.Errorf("extract pubkey: %w", err)
			}
			defer os.Remove(pubkeyPath)
		}
		if err := initramfs.Build(initramfs.Opts{
			OutPath:    a.InitramfsPath,
			KVer:       a.Kernel,
			SrcRoot:    srcRoot,
			Suite:      a.Suite,
			Mirror:     a.Mirror,
			PubKeyPath: pubkeyPath,
		}); err != nil {
			return fmt.Errorf("initramfs: %w", err)
		}
	}
	if a.BzImageOutPath != "" && a.BzImagePath != "" {
		if err := runner.Run(runner.Cmd{
			Argv: []string{"install", "-m", "0644",
				a.BzImagePath, a.BzImageOutPath},
			Sudo: true,
		}); err != nil {
			return fmt.Errorf("bzImage hand-off: %w", err)
		}
		fmt.Fprintf(os.Stderr, "  → bzImage at %s\n", a.BzImageOutPath)
	}

	// Optional: build UEFI-bootable disk (UKI + ESP) — same path the
	// classic bootstrap uses. Lets the kit boot directly under OVMF
	// without QEMU's -kernel/-initrd, which gives systemd-stub a
	// chance to measure the UKI sections into PCR 11.
	if a.EFIPath != "" {
		if a.BzImageOutPath == "" || a.InitramfsPath == "" {
			return fmt.Errorf(
				"--efi requires --bzimage-out + --initramfs to bundle into the UKI")
		}
		fmt.Fprintf(os.Stderr,
			"\n[bootstrap] building UKI + EFI disk → %s\n", a.EFIPath)
		uki := strings.TrimSuffix(a.EFIPath, filepath.Ext(a.EFIPath)) + ".uki.efi"
		if err := efi.BuildUKI(efi.UKIOpts{
			Linux:    a.BzImageOutPath,
			Initrd:   a.InitramfsPath,
			Cmdline:  a.Cmdline,
			Out:      uki,
			UName:    a.Kernel,
			SignKey:  a.SignKey,
			SignCert: a.SignCert,
		}); err != nil {
			return fmt.Errorf("uki: %w", err)
		}
		if err := efi.PackEFIDisk(efi.EFIDiskOpts{
			Out:    a.EFIPath,
			KitDir: a.Output,
			UKI:    uki,
			GenID:  1,
		}); err != nil {
			return fmt.Errorf("efi disk: %w", err)
		}
	}
	return nil
}

// orderLayers sorts the laidOut slice into overlay order: pancake-host
// at the top (most-specific identity), then pancake-base, then
// kernel/modules, then per-package APT layers in stable order.
func orderLayers(in []laidOut) []laidOut {
	priority := map[string]int{
		"pancake-host":    0,
		"pancake-runtime": 1,
		"pancaked":        2,
		"pancake-base":    3,
		"pancake-kernel":  4,
		"pancake-modules": 5,
	}
	hi := []laidOut{}
	rest := []laidOut{}
	for _, L := range in {
		if _, ok := priority[L.Name]; ok {
			hi = append(hi, L)
		} else {
			rest = append(rest, L)
		}
	}
	// stable sort hi by priority
	for i := 1; i < len(hi); i++ {
		for j := i; j > 0 && priority[hi[j-1].Name] > priority[hi[j].Name]; j-- {
			hi[j-1], hi[j] = hi[j], hi[j-1]
		}
	}
	return append(hi, rest...)
}

// pullLayer fans the four LayerParts out of GetLayer back to disk
// at dest/{image.img,image.hash,manifest.toml,image.roothash}.
//
// IMAGE chunks may be sparse-aware (chunk.Offset is the file offset
// where chunk.Data begins; ranges between consecutive chunks are
// holes). We use WriteAt at the offset and Truncate to the final
// size from the terminator chunk so the on-disk file is sparse,
// matching the server's cache layout. Other parts arrive
// contiguously and are written as-is.
func pullLayer(
	ctx context.Context,
	cli buildpb.PancakeBuilderClient,
	h *buildpb.LayerHandle,
	dest string,
) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	stream, err := cli.GetLayer(ctx, &buildpb.GetLayerRequest{
		Roothash: h.Roothash,
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
	// Truncate IMAGE to the declared EOF so trailing holes have the
	// right size. Without this, a fully-sparse tail would leave the
	// file shorter than the server's original.
	if f, ok := files[buildpb.LayerPart_LAYER_PART_IMAGE]; ok && imageEOF >= 0 {
		if err := f.Truncate(imageEOF); err != nil {
			return fmt.Errorf("truncate image.img to %d: %w", imageEOF, err)
		}
	}
	return nil
}
