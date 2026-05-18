// Signer abstracts away "where does the signing key live" so the
// build server can either sign in-process (LocalSigner: PEM key on
// disk; useful for dev / single-process compose stacks) or delegate
// to the pancake-sign service over gRPC (RemoteSigner: prod
// deployments where the signing key lives in a separate trust
// boundary, possibly KMS-backed).
//
// Two operations:
//
//   - SignUKI: input is the raw bytes of an unsigned UEFI PE binary
//     (the .efi produced by `ukify build` with no
//     --secureboot-private-key). Output is the same PE with a
//     Microsoft Authenticode signature appended via sbsign(1). UEFI
//     Secure Boot verifies the appended cert chain against `db`.
//
//   - SignManifest: input is the raw bytes of a generation manifest
//     (manifest.toml). Output is a detached RSA-PKCS1v15-SHA256
//     signature (the same shape `openssl dgst -sha256 -verify`
//     consumes; what initramfs `/init` already verifies).
//
//   - Cert: returns the PEM-encoded leaf cert. Operators bake the
//     SubjectPublicKeyInfo into the initramfs at
//     /etc/pancake/manifest.pubkey, and enroll the cert (or its
//     CA chain) in UEFI `db`.

package sign

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type Signer interface {
	SignUKI(ctx context.Context, unsigned []byte) ([]byte, error)
	SignManifest(ctx context.Context, manifest []byte) ([]byte, error)
	Cert(ctx context.Context) ([]byte, error)
}

// LocalSigner signs in-process using a PEM key + cert on the local
// filesystem. Suitable for dev (one-machine compose stack) and as
// a fallback when no remote sign-server is configured.
//
// SignUKI shells out to sbsign(1) — Go has no in-tree Authenticode
// implementation and reproducing the PE COFF + spcIndirectDataContent
// + signed CMS triple-nested ASN.1 by hand is the wrong investment.
type LocalSigner struct {
	KeyPath  string // PEM RSA private key
	CertPath string // PEM X.509 cert (for SignUKI's sbsign)
}

// SignUKI runs `sbsign --key <KeyPath> --cert <CertPath> <tmp>`
// against the input bytes and returns the signed PE.
func (s *LocalSigner) SignUKI(ctx context.Context, unsigned []byte) ([]byte, error) {
	if s.KeyPath == "" || s.CertPath == "" {
		return nil, fmt.Errorf("local signer: KeyPath + CertPath required for SignUKI")
	}
	tmp, err := os.MkdirTemp("", "pancake-uki-sign-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	in := filepath.Join(tmp, "in.efi")
	out := filepath.Join(tmp, "out.efi")
	if err := os.WriteFile(in, unsigned, 0o644); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "sbsign",
		"--key", s.KeyPath,
		"--cert", s.CertPath,
		"--output", out,
		in)
	if msg, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("sbsign: %w (%s)", err, string(msg))
	}
	return os.ReadFile(out)
}

// SignManifest produces an RSA-PKCS1v15-SHA256 detached signature.
// Same algorithm SignManifest in sign.go uses; this just routes
// through the Signer interface so the file-based sign.SignManifest
// API isn't a hard dependency for callers that want pluggable
// signing.
func (s *LocalSigner) SignManifest(ctx context.Context, manifest []byte) ([]byte, error) {
	if s.KeyPath == "" {
		return nil, fmt.Errorf("local signer: KeyPath required for SignManifest")
	}
	keyPEM, err := os.ReadFile(s.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("%s: not PEM", s.KeyPath)
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, fmt.Errorf("parse pkcs8: %w", e)
		}
		var ok bool
		key, ok = k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA key")
		}
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(manifest)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
}

// Cert returns the PEM-encoded leaf cert. Operators bake it (or its
// derived pubkey) into image artifacts.
func (s *LocalSigner) Cert(ctx context.Context) ([]byte, error) {
	if s.CertPath == "" {
		return nil, fmt.Errorf("local signer: CertPath required for Cert")
	}
	return os.ReadFile(s.CertPath)
}
