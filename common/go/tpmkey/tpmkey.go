// Package tpmkey is the small JSON marker format that `pancake
// enroll` writes after ACME-tpm enrollment and that `pancaked`
// reads at startup to load its TPM-resident TLS signing key.
//
// The marker is a one-of-two server-key shapes pancaked accepts:
//
//   /etc/pancake/server.key      — PKCS#8 PEM key (Slice 1, static CA)
//   /etc/pancake/server.tpmkey   — JSON marker, key lives in TPM (Slice 2)
//
// Marker format (mode 0600):
//
//   {
//     "storage_dir": "/var/lib/pancake/tpm",
//     "ak_name":     "<EK fingerprint hex>",
//     "key_name":    "pancake-tls-<pid>"
//   }
//
// LoadSigner opens the TPM (via go.step.sm/crypto/tpm), looks up
// the key by name, and returns a crypto.Signer pancaked wraps in a
// tls.Certificate.

package tpmkey

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"

	"go.step.sm/crypto/tpm"
	tpmstorage "go.step.sm/crypto/tpm/storage"
)

// EKHandleECC is the persistent NVRAM handle reserved for the
// ECC NIST P-256 EK (template L-2) by the TCG EK Credential
// Profile for TPM Family 2.0, §2.2.1.5. Vendors that follow the
// profile populate this slot at provisioning time; tpm2-tools
// defaults to it; go-attestation hardcodes it under the same name.
// We pin our EK there once at enroll-time (`tpm2_evictcontrol`)
// so subsequent reads are a single `tpm2_readpublic`. Same handle
// is also where `pancake attest` looks it up on the verifier side.
//
// Note: we don't *derive* this from a library because the upstream
// libraries (go-attestation et al.) carry it as a private constant.
// See discussion in pancake-go/docs (or the commit message that
// introduced this comment) for the "why hardcode" survey.
const EKHandleECC = "0x81010002"

// Marker is the on-disk JSON; produced by pancake enroll, consumed
// by pancaked.
type Marker struct {
	StorageDir string `json:"storage_dir"`
	AKName     string `json:"ak_name"`
	KeyName    string `json:"key_name"`
}

// Read parses the marker JSON at path.
func Read(path string) (*Marker, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var m Marker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m.StorageDir == "" || m.KeyName == "" {
		return nil, fmt.Errorf("marker %s: storage_dir and key_name required", path)
	}
	return &m, nil
}

// Write serializes the marker to disk (mode 0600).
func Write(path string, m Marker) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// LoadSigner opens the TPM, looks up the key named by the marker,
// and returns a crypto.Signer suitable for embedding in a
// tls.Certificate. The TPM stays open for the process lifetime —
// the signer holds a reference back to it for each Sign() call.
func LoadSigner(m *Marker) (crypto.Signer, error) {
	t, err := tpm.New(tpm.WithStore(tpmstorage.NewDirstore(m.StorageDir)))
	if err != nil {
		return nil, fmt.Errorf("tpm.New: %w", err)
	}
	ctx := tpm.NewContext(context.Background(), t)
	if err := t.Available(); err != nil {
		return nil, fmt.Errorf("tpm not available: %w", err)
	}
	key, err := t.GetKey(ctx, m.KeyName)
	if err != nil {
		return nil, fmt.Errorf("GetKey %q: %w", m.KeyName, err)
	}
	return key.Signer(ctx)
}
