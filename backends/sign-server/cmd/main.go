// pancake-sign — gRPC service that owns the code-signing leaf cert
// + private key. Build server delegates UKI + manifest signing here
// so the key never enters the build process.
//
// gRPC, not HTTP: keeps the surface symmetric with the other Pancake
// services (PancakeBuilderService, PancakeFleetService,
// PancakeAgentService), and lets the build server reuse a single
// transport / max-message setup.
//
// RPCs (see common/protos/sign.proto):
//   SignUKI         — unsigned PE bytes → signed PE bytes (sbsign(1))
//   SignManifest    — raw manifest bytes → RSA-PKCS1v15-SHA256 sig
//   GetSigningCert  — returns leaf cert PEM
//
// Auth: none in v1. Same network-trust assumption the build server
// uses (compose-internal). Phase 5.1 adds mTLS between build and
// sign servers.
//
// Defaults:
//   --listen   :7880
//   --key      /var/lib/pancake-sign/sign.key
//   --cert     /var/lib/pancake-sign/sign.crt
//
// On first start (neither key nor cert exists) the server mints a
// self-signed dev pair via sign.EnsureKeyAndCert. Production deploys
// should pre-provision the pair (volume-mounted from a secret store
// or fetched from step-ca's code-sign provisioner).

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"github.com/sinkap/pancake/common/gen/go/signpb"
	signsrv "github.com/sinkap/pancake/backends/sign-server"
	"github.com/sinkap/pancake/common/go/sign"
)

const maxSignMsgBytes = 128 * 1024 * 1024 // 128MB; matches RemoteSigner.

func main() {
	addr := flag.String("listen", ":7880", "gRPC listen address")
	keyPath := flag.String("key", "/var/lib/pancake-sign/sign.key",
		"PEM RSA private key path. Auto-generated as a self-signed "+
			"dev pair (with --cert) on first start if neither file exists.")
	certPath := flag.String("cert", "/var/lib/pancake-sign/sign.crt",
		"PEM X.509 cert path. Paired with --key.")
	flag.Parse()

	if err := os.MkdirAll(stateDir(*keyPath), 0o700); err != nil {
		log.Fatalf("mkdir state: %v", err)
	}
	hn, _ := os.Hostname()
	generated, err := sign.EnsureKeyAndCert(*keyPath, *certPath, hn)
	if err != nil {
		log.Fatalf("ensure key/cert: %v", err)
	}
	if generated {
		fmt.Fprintf(os.Stderr,
			"[pancake-sign] minted dev key+cert at %s / %s\n",
			*keyPath, *certPath)
	} else {
		fmt.Fprintf(os.Stderr,
			"[pancake-sign] using existing key+cert at %s / %s\n",
			*keyPath, *certPath)
	}

	signer := &sign.LocalSigner{KeyPath: *keyPath, CertPath: *certPath}
	srv := signsrv.New(signer)

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	gs := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxSignMsgBytes),
		grpc.MaxSendMsgSize(maxSignMsgBytes),
	)
	signpb.RegisterPancakeSignerServiceServer(gs, srv)

	fmt.Fprintf(os.Stderr, "[pancake-sign] listening on %s (gRPC)\n", *addr)
	if err := gs.Serve(lis); err != nil {
		log.Fatalf("grpc serve: %v", err)
	}
}

func stateDir(keyPath string) string {
	for i := len(keyPath) - 1; i >= 0; i-- {
		if keyPath[i] == '/' {
			return keyPath[:i]
		}
	}
	return "."
}
