// `pancake orchestrate`: build/admin-side gRPC client. Two subcommands:
//
//   get-current  — connect to a VM, print its current manifest's [generation]
//                  block (so you can see what the VM is currently on)
//   push         — read a signed manifest from a local kit and call
//                  Update on the VM
//
// The signing key never leaves the machine that ran `pancake bootstrap`
// originally — orchestrate just relays the artifacts that bootstrap
// already signed.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/orchpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func cmdOrchestrate(_ *kit.Kit, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr,
			"usage: pancake orchestrate <subcommand> [flags]\n"+
				"  get-current   query a VM for the manifest it's running\n"+
				"  push          push a kit's gen N manifest to a VM")
		return 2
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "get-current":
		return cmdOrchGetCurrent(args)
	case "push":
		return cmdOrchPush(args)
	default:
		fmt.Fprintf(os.Stderr,
			"pancake orchestrate: unknown subcommand %q\n", sub)
		return 2
	}
}

func dialTarget(target, tokenFile string) (orchpb.PancakeClient, *grpc.ClientConn, context.Context, error) {
	target = strings.TrimPrefix(target, "grpc://")
	target = strings.TrimRight(target, "/")
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial %s: %w", target, err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			conn.Close()
			return nil, nil, nil, fmt.Errorf("token-file: %w", err)
		}
		ctx = metadata.AppendToOutgoingContext(ctx,
			"authorization", "Bearer "+strings.TrimSpace(string(b)))
	}
	return orchpb.NewPancakeClient(conn), conn, ctx, nil
}

func cmdOrchGetCurrent(args []string) int {
	fs := flag.NewFlagSet("get-current", flag.ContinueOnError)
	target := fs.String("target", "", "VM gRPC address, e.g. localhost:7878 (required)")
	tokenFile := fs.String("token-file", "", "bearer token file (optional)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr,
			"usage: pancake orchestrate get-current --target HOST:PORT [--token-file F]")
		return 2
	}
	cli, conn, ctx, err := dialTarget(*target, *tokenFile)
	if err != nil {
		return die(err)
	}
	defer conn.Close()
	m, err := cli.GetCurrentManifest(ctx, &orchpb.GetCurrentManifestRequest{})
	if err != nil {
		return die(err)
	}
	tmp, _ := os.CreateTemp("", "orch-current-*.toml")
	tmp.Write(m.ManifestToml)
	tmp.Close()
	defer os.Remove(tmp.Name())
	gm, err := kit.ReadGenerationManifest(tmp.Name())
	if err != nil {
		return die(err)
	}
	fmt.Printf("VM %s is on generation %d (counter %d, %d layers)\n",
		*target, gm.Generation.ID, gm.Generation.Counter, len(gm.Layer))
	fmt.Printf("  description: %s\n", gm.Generation.Description)
	fmt.Printf("  created:     %s\n", gm.Generation.Created)
	return 0
}

func cmdOrchPush(args []string) int {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	target := fs.String("target", "", "VM gRPC address (required)")
	kitDir := fs.String("kit", "", "kit directory containing the manifest (required)")
	genID := fs.Int("gen-id", 0, "generation id to push (default: latest)")
	tokenFile := fs.String("token-file", "", "bearer token file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *target == "" || *kitDir == "" {
		fmt.Fprintln(os.Stderr,
			"usage: pancake orchestrate push --target HOST:PORT --kit DIR "+
				"[--gen-id N] [--token-file F]")
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

	// Read the three signed files locally.
	dir := filepath.Join(k.Generations(), strconv.Itoa(gid))
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", name, err)
			os.Exit(1)
		}
		return b
	}
	m := &orchpb.Manifest{
		ManifestToml: read("manifest.toml"),
		ManifestSig:  read("manifest.toml.sig"),
		Lowers:       read("lowers"),
	}

	cli, conn, ctx, err := dialTarget(*target, *tokenFile)
	if err != nil {
		return die(err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr,
		"[orchestrate] pushing kit %s gen %d → %s\n",
		*kitDir, gid, *target)
	resp, err := cli.Update(ctx, m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[orchestrate] Update: %v\n", err)
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
			"[orchestrate] VM is missing %d layers:\n",
			len(resp.MissingLayerSlugs))
		for _, s := range resp.MissingLayerSlugs {
			fmt.Fprintf(os.Stderr, "    %s\n", s)
		}
		fmt.Fprintf(os.Stderr,
			"  ship them via `pancake install` in-VM, then retry push.\n")
		return 1
	}
	fmt.Fprintf(os.Stderr,
		"[orchestrate] installed generation %d on %s. Run `pancake swap %d` "+
			"in-VM (or have it auto-swap on next boot via current symlink).\n",
		resp.InstalledGeneration, *target, resp.InstalledGeneration)
	return 0
}
