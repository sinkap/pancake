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
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sinkap/pancake/tools/pancake-go/internal/hoststate"
	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/orchpb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/pkitls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// dialOpts gathers the auth-related flags both `get-current` and
// `push` accept. mTLS only — bearer-token plumbing is gone.
type dialOpts struct {
	target     string
	caFile     string
	certFile   string
	keyFile    string
	serverName string
}

func registerDialFlags(fs *flag.FlagSet, o *dialOpts) {
	fs.StringVar(&o.target, "target", "",
		"VM gRPC address, e.g. localhost:7878 (required)")
	fs.StringVar(&o.caFile, "ca-file", "",
		"PEM root CA that signed the server's cert (mTLS).")
	fs.StringVar(&o.certFile, "cert-file", "",
		"PEM client-auth leaf cert presented to pancaked (mTLS).")
	fs.StringVar(&o.keyFile, "key-file", "",
		"PKCS#8 PEM private key for --cert-file (mTLS).")
	fs.StringVar(&o.serverName, "server-name", "",
		"override SNI / server cert hostname check. Default: dial host.")
}

func cmdOrchestrate(_ *kit.Kit, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr,
			"usage: pancake orchestrate <subcommand> [flags]\n"+
				"  get-current   query a VM for the manifest it's running\n"+
				"  push          push a kit's gen N manifest to a VM\n"+
				"  attest        get TPM attestation from a VM")
		return 2
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "get-current":
		return cmdOrchGetCurrent(args)
	case "push":
		return cmdOrchPush(args)
	case "attest":
		return cmdOrchAttest(args)
	default:
		fmt.Fprintf(os.Stderr,
			"pancake orchestrate: unknown subcommand %q\n", sub)
		return 2
	}
}

func dialTarget(o dialOpts) (orchpb.PancakeClient, *grpc.ClientConn, context.Context, error) {
	target := strings.TrimPrefix(o.target, "grpc://")
	target = strings.TrimRight(target, "/")

	// mTLS path. All three files set → TLS with mutual auth. Any
	// subset that's nonempty without the others is a config error
	// because there's no graceful "half mTLS" fallback worth having.
	var dialOpt grpc.DialOption
	mtlsAny := o.caFile != "" || o.certFile != "" || o.keyFile != ""
	mtlsAll := o.caFile != "" && o.certFile != "" && o.keyFile != ""
	switch {
	case mtlsAll:
		serverName := o.serverName
		if serverName == "" {
			// Strip the :port off "host:7878" so the cert hostname
			// check sees the bare host.
			serverName = target
			if i := strings.LastIndex(serverName, ":"); i >= 0 {
				serverName = serverName[:i]
			}
		}
		cfg, err := pkitls.LoadClientConfig(
			o.certFile, o.keyFile, o.caFile, serverName)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("mTLS config: %w", err)
		}
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(cfg))
	case mtlsAny:
		return nil, nil, nil, fmt.Errorf(
			"--ca-file, --cert-file, --key-file must be set together")
	default:
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	conn, err := grpc.NewClient(target, dialOpt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial %s: %w", target, err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	return orchpb.NewPancakeClient(conn), conn, ctx, nil
}

func cmdOrchGetCurrent(args []string) int {
	fs := flag.NewFlagSet("get-current", flag.ContinueOnError)
	var d dialOpts
	registerDialFlags(fs, &d)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if d.target == "" {
		fmt.Fprintln(os.Stderr,
			"usage: pancake orchestrate get-current --target HOST:PORT\n"+
				"       [--ca-file F --cert-file F --key-file F [--server-name N]]")
		return 2
	}
	cli, conn, ctx, err := dialTarget(d)
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
		d.target, gm.Generation.ID, gm.Generation.Counter, len(gm.Layer))
	fmt.Printf("  description: %s\n", gm.Generation.Description)
	fmt.Printf("  created:     %s\n", gm.Generation.Created)
	return 0
}

func cmdOrchPush(args []string) int {
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
			"usage: pancake orchestrate push --target HOST:PORT --kit DIR\n"+
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

	cli, conn, ctx, err := dialTarget(d)
	if err != nil {
		return die(err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr,
		"[orchestrate] pushing kit %s gen %d → %s\n",
		*kitDir, gid, d.target)
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
		resp.InstalledGeneration, d.target, resp.InstalledGeneration)
	return 0
}

func cmdOrchAttest(args []string) int {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	target := fs.String("target", "", "VM address (e.g., localhost:7878 or 10.0.2.15:7878)")
	serverName := fs.String("server-name", "", "server hostname for cert validation (default: derive from target)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr,
			"usage: pancake orchestrate attest --target HOST:PORT [--server-name NAME]\n"+
				"\nClient certs auto-detected from pancake-host-state (same as bootstrap)")
		return 2
	}

	// Auto-detect client credentials from hoststate
	paths, err := hoststate.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve hoststate: %v\n", err)
		fmt.Fprintln(os.Stderr, "hint: run `source pancake-host-state/pancake.env` first")
		return 1
	}

	// Dial VM with auto-detected client certs
	d := dialOpts{
		target:     *target,
		caFile:     paths.TrustRoot,
		certFile:   paths.ClientCert,
		keyFile:    paths.ClientKey,
		serverName: *serverName,
	}
	fmt.Fprintf(os.Stderr, "[debug] using certs: ca=%s cert=%s key=%s\n",
		d.caFile, d.certFile, d.keyFile)
	cli, conn, ctx, err := dialTarget(d)
	if err != nil {
		return die(fmt.Errorf("connect to VM: %w", err))
	}
	defer conn.Close()

	// Generate random nonce for freshness
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return die(fmt.Errorf("generate nonce: %w", err))
	}

	fmt.Fprintf(os.Stderr, "[orchestrate] requesting attestation from %s\n", *target)
	fmt.Fprintf(os.Stderr, "  nonce: %s\n", hex.EncodeToString(nonce))

	resp, err := cli.Attest(ctx, &orchpb.AttestRequest{
		Nonce: nonce,
		// Empty PCRs = use pancake-os defaults (7, 11, 12, 13, 14)
	})
	if err != nil {
		return die(fmt.Errorf("Attest RPC: %w", err))
	}

	fmt.Fprintf(os.Stderr, "\n[attestation report]\n")
	fmt.Fprintf(os.Stderr, "  quote:     %d bytes\n", len(resp.Quote))
	fmt.Fprintf(os.Stderr, "  signature: %d bytes\n", len(resp.Signature))
	fmt.Fprintf(os.Stderr, "  ak_pub:    %d bytes\n", len(resp.AkPub))
	fmt.Fprintf(os.Stderr, "  ek_pub:    %d bytes\n", len(resp.EkPub))
	fmt.Fprintf(os.Stderr, "\nPCR values:\n")
	for _, p := range resp.Pcr {
		fmt.Fprintf(os.Stderr, "  PCR[%2d]: %s\n", p.Index, hex.EncodeToString(p.Sha256))
	}

	fmt.Fprintf(os.Stderr, "\n✓ Attestation successful\n")
	fmt.Fprintf(os.Stderr, "  (Full verification: compare PCRs against expected, verify quote signature with AK)\n")
	return 0
}
