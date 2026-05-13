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
//	--listen      :7878
//	--kit         /var/lib/pancake
//	--pubkey      /etc/pancake/manifest.pubkey
//	--token-file  (none)
//	--tpm-token   (none; if set without value, /etc/pancake/orch-token.creds)
//
// Auth model:
//   - Neither --token-file nor --tpm-token  →  unauthenticated. Manifest
//     signature is still the integrity floor.
//   - --token-file F                        →  bearer = file content.
//   - --tpm-token [F]                       →  bearer = systemd-creds
//     decryption of F (defaults to /etc/pancake/orch-token.creds);
//     PCR mismatch → daemon refuses to start.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/orchsrv"
)

func main() {
	listen := flag.String("listen", ":7878", "address:port for gRPC listener")
	kitDir := flag.String("kit", "/var/lib/pancake",
		"path to the pancake kit directory")
	pubkey := flag.String("pubkey", orchsrv.DefaultPubKeyPath,
		"PEM PKIX public key for verifying pushed manifests")
	tokenFile := flag.String("token-file", "",
		"plaintext bearer-token file; clients must send the same value as "+
			"metadata['authorization'] = \"Bearer <token>\". Empty disables auth.")
	tpmToken := flag.String("tpm-token", "",
		"systemd-creds-sealed bearer-token blob. Decrypts at startup via "+
			"TPM PCR 7+11; mismatched boot chain → refuse to start. "+
			"Pass an explicit path or use the implicit default by setting "+
			"--tpm-token=auto. Mutually exclusive with --token-file.")
	builder := flag.String("builder", "",
		"address (host:port) of a pancake-build-server. When set, "+
			"Update auto-fetches missing layers via GetLayer instead "+
			"of failing with missing_layer_slugs[]. Falls back to the "+
			"in-VM apt rebuild path if the build server doesn't have "+
			"the layer. Empty disables auto-fetch.")
	flag.Parse()

	if *tpmToken == "auto" {
		// "auto" means "use the sealed file if it exists, otherwise run
		// unauthenticated and log a warning". This lets the systemd unit
		// shipped in the pancaked layer set --tpm-token=auto by default
		// — first boot has no enrollment so pancaked still starts (just
		// without auth); after `pancake enroll` and a daemon restart, it
		// picks up the sealed token and gates incoming RPCs.
		if _, err := os.Stat(orchsrv.DefaultSealedTokenPath); err == nil {
			*tpmToken = orchsrv.DefaultSealedTokenPath
		} else {
			fmt.Fprintf(os.Stderr,
				"pancaked: --tpm-token=auto but %s does not exist — "+
					"running UNAUTHENTICATED. Run `pancake enroll` and "+
					"restart pancaked to gate updates with a TPM-sealed token.\n",
				orchsrv.DefaultSealedTokenPath)
			*tpmToken = ""
		}
	}

	k, err := kit.Open(*kitDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pancaked: %v\n", err)
		os.Exit(1)
	}
	if err := orchsrv.Serve(orchsrv.Opts{
		Kit:          k,
		Listen:       *listen,
		PubKey:       *pubkey,
		TokenFile:    *tokenFile,
		TPMTokenFile: *tpmToken,
		Builder:      *builder,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "pancaked: %v\n", err)
		os.Exit(1)
	}
}
