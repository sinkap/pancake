// `pancake push`: read a signed manifest from a local kit and call
// Update on a VM's pancaked. The signing key never leaves the
// machine that ran `pancake bootstrap` originally — push just
// relays the artifacts that bootstrap already signed.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/sinkap/pancake/common/gen/go/pancakepb"
	"github.com/sinkap/pancake/common/go/kit"
)

func cmdPush(_ *kit.Kit, args []string) int {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	var d dialOpts
	registerDialFlags(fs, &d)
	kitDir := fs.String("kit", "", "kit directory containing the manifest (required)")
	genID := fs.Int("gen-id", 0, "generation id to push (default: latest)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if d.target == "" || *kitDir == "" {
		fmt.Fprintln(os.Stderr,
			"usage: pancake push --target HOST:PORT --kit DIR\n"+
				"       [--gen-id N]\n"+
				"       [--ca-file F --cert-file F --key-file F [--server-name N]]")
		return 2
	}
	k, err := kit.Open(*kitDir)
	if err != nil {
		return die(err)
	}
	gid := *genID
	if gid == 0 {
		gid, err = k.LatestGenerationID()
		if err != nil {
			return die(err)
		}
	}

	dir := filepath.Join(k.Generations(), strconv.Itoa(gid))
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", name, err)
			os.Exit(1)
		}
		return b
	}
	m := &pancakepb.Manifest{
		ManifestToml: read("manifest.toml"),
		ManifestSig:  read("manifest.toml.sig"),
		Lowers:       read("lowers"),
	}

	cli, conn, ctx, err := dialTarget(d)
	if err != nil {
		return die(err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "[push] kit %s gen %d → %s\n",
		*kitDir, gid, d.target)
	resp, err := cli.Update(ctx, m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[push] Update: %v\n", err)
		if resp != nil && len(resp.MissingLayerSlugs) > 0 {
			fmt.Fprintf(os.Stderr,
				"  missing layers (%d):\n", len(resp.MissingLayerSlugs))
			for _, s := range resp.MissingLayerSlugs {
				fmt.Fprintf(os.Stderr, "    %s\n", s)
			}
		}
		return 1
	}
	if len(resp.MissingLayerSlugs) > 0 {
		fmt.Fprintf(os.Stderr,
			"[push] VM is missing %d layers:\n",
			len(resp.MissingLayerSlugs))
		for _, s := range resp.MissingLayerSlugs {
			fmt.Fprintf(os.Stderr, "    %s\n", s)
		}
		fmt.Fprintf(os.Stderr,
			"  ship them via `pancake install` in-VM, then retry push.\n")
		return 1
	}
	fmt.Fprintf(os.Stderr,
		"[push] installed generation %d on %s. Run `pancake swap %d` "+
			"in-VM (or have it auto-swap on next boot via current symlink).\n",
		resp.InstalledGeneration, d.target, resp.InstalledGeneration)
	return 0
}
