// `pancake get-current`: query a VM's pancaked for the manifest of
// the generation its `current` symlink points to. Read-only.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sinkap/pancake/common/gen/go/pancakepb"
	"github.com/sinkap/pancake/common/go/kit"
)

func cmdGetCurrent(_ *kit.Kit, args []string) int {
	fs := flag.NewFlagSet("get-current", flag.ContinueOnError)
	var d dialOpts
	registerDialFlags(fs, &d)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if d.target == "" {
		fmt.Fprintln(os.Stderr,
			"usage: pancake get-current --target HOST:PORT\n"+
				"       [--ca-file F --cert-file F --key-file F [--server-name N]]")
		return 2
	}
	cli, conn, ctx, err := dialTarget(d)
	if err != nil {
		return die(err)
	}
	defer conn.Close()
	m, err := cli.GetCurrentManifest(ctx, &pancakepb.GetCurrentManifestRequest{})
	if err != nil {
		return die(err)
	}
	tmp, _ := os.CreateTemp("", "current-*.toml")
	tmp.Write(m.ManifestToml)
	tmp.Close()
	defer os.Remove(tmp.Name())
	gm, err := kit.ReadGenerationManifest(tmp.Name())
	if err != nil {
		return die(err)
	}
	fmt.Printf("VM %s is on generation %d (counter %d, %d layers)\n",
		d.target, gm.Generation.ID, gm.Generation.Counter, len(gm.Layer))
	fmt.Printf("  description: %s\n", gm.Generation.Description)
	fmt.Printf("  created:     %s\n", gm.Generation.Created)
	return 0
}
