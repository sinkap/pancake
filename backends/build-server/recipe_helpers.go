package server

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/sinkap/pancake/common/gen/go/buildpb"
	"github.com/sinkap/pancake/common/go/runner"
)

// overlayPriority assigns each known synthetic layer a slot in the
// overlay stack: lower index = higher in stack (most-specific wins).
// APT layers (anything not named here) go after the synthetic block,
// preserving their incoming order.
var overlayPriority = map[string]int{
	"pancake-host":        0,
	"pancake-orch-config": 1,
	"pancake-runtime":     2,
	"pancaked":            3,
	"pancake-base":        4,
	"pancake-kernel":      5,
	"pancake-modules":     6,
}

// sortOverlayOrder returns handles re-ordered for the generation
// manifest: synthetic layers in priority order first, then APT
// packages in their original incoming order. Stable for APT
// (matters: kit's overlay semantics depend on it).
func sortOverlayOrder(in []*buildpb.LayerHandle) []*buildpb.LayerHandle {
	var hi, rest []*buildpb.LayerHandle
	for _, h := range in {
		if _, ok := overlayPriority[h.Name]; ok {
			hi = append(hi, h)
		} else {
			rest = append(rest, h)
		}
	}
	sort.SliceStable(hi, func(i, j int) bool {
		return overlayPriority[hi[i].Name] < overlayPriority[hi[j].Name]
	})
	return append(hi, rest...)
}

// untarInto extracts tarPath into destDir. Accepts .tar / .tar.gz /
// .tar.zst — tar autodetects via magic bytes.
func untarInto(tarPath, destDir string) error {
	return runner.Run(runner.Cmd{
		Argv: []string{"tar",
			"--no-same-owner",
			"-xf", tarPath,
			"-C", destDir,
		},
		Sudo: true,
	})
}

// generateHostKeys mints fresh ssh_host_{rsa,ecdsa,ed25519}_key pairs
// in dir using ssh-keygen. Same fallback the classic client-side
// pancake-host helper used.
func generateHostKeys(dir string) error {
	for _, kt := range []string{"rsa", "ecdsa", "ed25519"} {
		kf := filepath.Join(dir, "ssh_host_"+kt+"_key")
		if err := runner.Run(runner.Cmd{
			Argv: []string{"ssh-keygen", "-q", "-N", "", "-t", kt, "-f", kf},
		}); err != nil {
			return fmt.Errorf("ssh-keygen %s: %w", kt, err)
		}
	}
	return nil
}
