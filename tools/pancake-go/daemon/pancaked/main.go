// pancaked — long-running gRPC service that accepts orchestrator-pushed
// signed manifests and applies them to the local kit.
//
// Implements the pancake.v1.Pancake service from
// internal/orchpb/pancake.proto via internal/orchsrv. Runs as a systemd
// unit (etc/systemd/system/pancaked.service in the pancaked layer); not
// meant to be invoked manually except for ad-hoc debugging.
//
// Defaults:
//
//	--listen           :7878
//	--kit              /var/lib/pancake
//	--pubkey           /etc/pancake/manifest.pubkey
//	--ca-file          (auto: /etc/pancake/ca.crt        if present)
//	--cert-file        (auto: /etc/pancake/server.crt    if present)
//	--key-file         (auto: /etc/pancake/server.key    if present)
//	--tpm-key-marker   (auto: /etc/pancake/server.tpmkey if present)
//
// Auth model:
//   - --ca-file + --cert-file + --tpm-key-marker  →  mTLS, TPM-resident
//     server key (Slice 2 ACME-tpm flow). Preferred path.
//   - --ca-file + --cert-file + --key-file        →  mTLS, on-disk PEM
//     PKCS#8 server key (Slice 1, static-CA flow).
//   - none of the above                            →  unauthenticated
//     transport. Manifest signature is still the integrity floor.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/orchsrv"
)

const (
	// defaultOrchCAFile: client-cert trust root baked into the
	// signed pancake-orch-config verity layer at bootstrap time.
	// Preferred over defaultCAFile, which is the legacy Slice 1
	// path where the operator scp'd a cert post-boot.
	defaultOrchCAFile   = "/etc/pancake/orch/trust-root.crt"
	defaultCAFile       = "/etc/pancake/ca.crt"
	defaultCertFile     = "/etc/pancake/server.crt"
	defaultKeyFile      = "/etc/pancake/server.key"
	defaultTPMKeyMarker = "/etc/pancake/server.tpmkey"
)

func main() {
	listen := flag.String("listen", ":7878", "address:port for gRPC listener")
	kitDir := flag.String("kit", "/var/lib/pancake",
		"path to the pancake kit directory")
	pubkey := flag.String("pubkey", orchsrv.DefaultPubKeyPath,
		"PEM PKIX public key for verifying pushed manifests")
	caFile := flag.String("ca-file", "",
		"PEM root CA that signed the orchestrator's client cert. "+
			"When unset, defaults to "+defaultCAFile+" if it exists.")
	certFile := flag.String("cert-file", "",
		"PEM server-auth leaf cert. When unset, defaults to "+
			defaultCertFile+" if it exists.")
	keyFile := flag.String("key-file", "",
		"PKCS#8 PEM private key for --cert-file. When unset, "+
			"defaults to "+defaultKeyFile+" if it exists. Mutually "+
			"exclusive with --tpm-key-marker.")
	tpmKeyMarker := flag.String("tpm-key-marker", "",
		"JSON marker (storage_dir + ak_name + key_name) pointing at "+
			"a TPM-resident key from `pancake enroll`. When unset, "+
			"defaults to "+defaultTPMKeyMarker+" if it exists.")
	builder := flag.String("builder", "",
		"address (host:port) of a pancake-build-server. When set, "+
			"Update auto-fetches missing layers via GetLayer instead "+
			"of failing with missing_layer_slugs[]. Falls back to the "+
			"in-VM apt rebuild path if the build server doesn't have "+
			"the layer. Empty disables auto-fetch.")
	flag.Parse()

	// Auto-pick up the standard mTLS file locations. Prefer the
	// TPM marker over a PEM key when both exist (Slice 2 over
	// Slice 1) — the TPM-bound key is the going-forward path.
	// For the client-cert CA, prefer the layer-baked path
	// (verity-protected, signed) over the writable /etc/pancake
	// fallback (Slice 1 SSH-delivered).
	if *caFile == "" {
		if _, err := os.Stat(defaultOrchCAFile); err == nil {
			*caFile = defaultOrchCAFile
		} else if _, err := os.Stat(defaultCAFile); err == nil {
			*caFile = defaultCAFile
		}
	}
	if *certFile == "" {
		if _, err := os.Stat(defaultCertFile); err == nil {
			*certFile = defaultCertFile
		}
	}
	if *tpmKeyMarker == "" && *keyFile == "" {
		if _, err := os.Stat(defaultTPMKeyMarker); err == nil {
			*tpmKeyMarker = defaultTPMKeyMarker
		} else if _, err := os.Stat(defaultKeyFile); err == nil {
			*keyFile = defaultKeyFile
		}
	}
	if *caFile != "" && *certFile != "" && (*keyFile != "" || *tpmKeyMarker != "") {
		mode := "PEM key"
		if *tpmKeyMarker != "" {
			mode = "TPM marker"
		}
		fmt.Fprintf(os.Stderr,
			"pancaked: mTLS auto-detected (%s)\n", mode)
	}

	k, err := kit.Open(*kitDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pancaked: %v\n", err)
		os.Exit(1)
	}
	if err := orchsrv.Serve(orchsrv.Opts{
		Kit:           k,
		Listen:        *listen,
		PubKey:        *pubkey,
		CAFile:        *caFile,
		CertFile:      *certFile,
		KeyFile:       *keyFile,
		KeyMarkerFile: *tpmKeyMarker,
		Builder:       *builder,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "pancaked: %v\n", err)
		os.Exit(1)
	}
}
