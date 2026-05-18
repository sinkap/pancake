// pancake-sign — HTTP service that owns the code-signing leaf cert
// + private key. Build server delegates UKI + manifest signing here
// so the key never enters the build process.
//
// HTTP, not gRPC: surface is three endpoints with byte-in / byte-out
// shapes, all small enough that adding a proto file would be more
// ceremony than benefit. Trust boundary is the compose-internal
// network; production deployments should front this with mTLS or
// network policy.
//
// Endpoints:
//   POST /sign/uki         body: unsigned PE bytes; returns signed PE.
//                          Internally shells out to sbsign(1).
//   POST /sign/manifest    body: raw bytes; returns RSA-PKCS1v15-SHA256
//                          detached signature.
//   GET  /signing-cert     returns leaf cert PEM. Operators bake the
//                          SubjectPublicKeyInfo into the initramfs;
//                          enroll the cert (or its CA chain) in UEFI db.
//   GET  /healthz          returns 200 once cert is loaded.
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
	"net/http"
	"os"

	"github.com/sinkap/pancake/tools/pancake-go/internal/sign"
	signsrv "github.com/sinkap/pancake/tools/pancake-go/sign-server"
)

func main() {
	addr := flag.String("listen", ":7880", "HTTP listen address")
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
	http.Handle("/", srv)

	fmt.Fprintf(os.Stderr, "[pancake-sign] listening on %s\n", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatalf("listen: %v", err)
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
