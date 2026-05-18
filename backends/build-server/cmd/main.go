// pancake-build-server: gRPC build daemon for pancake-os verity layers.
// See internal/buildpb/build.proto for the wire schema.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/sinkap/pancake/common/gen/go/buildpb"
	"github.com/sinkap/pancake/common/go/sign"
	"github.com/sinkap/pancake/backends/build-server"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("listen", ":7879", "gRPC listen address")
	cacheDir := flag.String("cache", "/var/lib/pancake-build-server",
		"cache directory root (created if missing)")
	trustDir := flag.String("trust-dir",
		"/var/lib/pancake-build-server/trust",
		"directory holding trust-root.crt + other PEMs the build server "+
			"reads when baking the orch-config layer. Mounted RO from the "+
			"shared pancake-trust docker volume in compose.")
	bundledBinsDir := flag.String("bundled-bins-dir",
		"/usr/local/share/pancake-bundled",
		"directory where the container image stages pancake / pancaked "+
			"/ mount-overlay / pivot-root for recipes that don't get "+
			"operator-uploaded override blobs. Empty = no fallback.")
	signKey := flag.String("sign-key", "",
		"PEM RSA private key for in-process UKI + manifest signing. "+
			"Mutually exclusive with --sign-addr. Empty = no signing.")
	signCert := flag.String("sign-cert", "",
		"PEM X.509 cert paired with --sign-key. Required when --sign-key is set.")
	signAddr := flag.String("sign-addr", "",
		"gRPC target of a pancake-sign service (e.g. "+
			"pancake-sign:7880). Legacy 'http://host:port' URLs are "+
			"accepted and the scheme is stripped. When set, UKI + "+
			"manifest signing routes there over gRPC and the build "+
			"server holds no private key. Mutually exclusive with "+
			"--sign-key.")
	flag.Parse()

	if err := os.MkdirAll(*cacheDir, 0o755); err != nil {
		log.Fatalf("mkdir cache: %v", err)
	}

	var signer sign.Signer
	switch {
	case *signKey != "" && *signAddr != "":
		log.Fatalf("--sign-key and --sign-addr are mutually exclusive")
	case *signKey != "":
		if *signCert == "" {
			log.Fatalf("--sign-key requires --sign-cert")
		}
		signer = &sign.LocalSigner{KeyPath: *signKey, CertPath: *signCert}
		fmt.Fprintf(os.Stderr,
			"[pancake-build-server] signer: local PEM (%s)\n", *signKey)
	case *signAddr != "":
		signer = &sign.RemoteSigner{Target: *signAddr}
		fmt.Fprintf(os.Stderr,
			"[pancake-build-server] signer: remote (%s)\n", *signAddr)
	}

	srv, err := server.New(server.Opts{
		CacheDir:       *cacheDir,
		BundledBinsDir: *bundledBinsDir,
		TrustDir:       *trustDir,
		Signer:         signer,
	})
	if err != nil {
		log.Fatalf("server.New: %v", err)
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	g := grpc.NewServer()
	buildpb.RegisterPancakeBuilderServiceServer(g, srv)

	fmt.Fprintf(os.Stderr,
		"[pancake-build-server] listening on %s, cache=%s\n", *addr, *cacheDir)
	if err := g.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
