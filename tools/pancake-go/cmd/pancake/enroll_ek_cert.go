// enroll_ek_cert.go: pull the manufacturer EK cert (if any) out of NV
// and write it to disk so pancaked can include it in AttestResponse
// for the fleet-server to validate against Google's vTPM root or a
// TPM manufacturer bundle.
//
// No-op on swtpm: SWTPMBackend.ReadEKCert returns (nil, nil, nil) so
// callers can fall through to the dev EK CA path without an error.

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sinkap/pancake/tools/pancake-go/internal/tpmbackend"
)

const (
	defaultEKCertPath  = "/etc/pancake/ek.crt"
	defaultEKChainPath = "/etc/pancake/ek-chain.pem"
)

// writeEKCert reads the manufacturer-provisioned EK cert (when present)
// and writes it as DER to certPath and the chain (DER concatenated as
// PEM, leaf-to-root order) to chainPath. Returns (false, nil) when no
// cert is in NV (the swtpm case) so the caller knows to fall back to
// the dev EK CA path without treating it as an error.
//
// Errors are returned only when:
//   - the backend reports a transport/parse failure reading NV,
//   - the disk writes themselves fail.
func writeEKCert(ctx context.Context, backend tpmbackend.Backend, certPath, chainPath string) (bool, error) {
	leaf, chain, err := backend.ReadEKCert(ctx)
	if err != nil {
		return false, fmt.Errorf("read EK cert from TPM: %w", err)
	}
	if leaf == nil {
		return false, nil
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return false, err
	}
	if err := os.WriteFile(certPath, leaf.Raw, 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", certPath, err)
	}

	// Build chain PEM (leaf first, then intermediates).
	var pemBuf []byte
	pemBuf = append(pemBuf, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: leaf.Raw,
	})...)
	for _, c := range chain {
		pemBuf = append(pemBuf, pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: c.Raw,
		})...)
	}
	if err := os.WriteFile(chainPath, pemBuf, 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", chainPath, err)
	}

	fmt.Fprintf(os.Stderr,
		"[enroll] EK cert (%s) + %d intermediate(s) written to %s, %s\n",
		leaf.Subject.String(), len(chain), certPath, chainPath)
	return true, nil
}

// readEKCertChainFromDisk loads the EK cert + intermediates back as
// DER blobs suitable for orchpb.AttestResponse. Returns (nil, nil)
// when the files don't exist so the Attest RPC handler can omit the
// optional fields.
func readEKCertChainFromDisk(certPath, chainPath string) (ekCertDER []byte, chainDERs [][]byte, err error) {
	b, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	ekCertDER = b

	// chainPath is PEM; first block is the leaf (already in ekCertDER),
	// the rest are intermediates.
	pemBytes, err := os.ReadFile(chainPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ekCertDER, nil, nil
		}
		return nil, nil, err
	}
	rest := pemBytes
	first := true
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			if first {
				first = false
			} else {
				chainDERs = append(chainDERs, block.Bytes)
			}
		}
		rest = r
	}
	return ekCertDER, chainDERs, nil
}

// unused — silences linters in builds where x509 isn't otherwise referenced.
var _ = x509.ParseCertificate
