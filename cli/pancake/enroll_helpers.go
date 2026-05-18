// enroll_helpers.go: small bits used by enroll_acme.go +
// enroll_attest.go — TPM EK/AK lookup, ACME account-key persistence,
// poll loops, path utilities.

package main

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/ca"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/tpm"
)

// preferredAKName returns the hex SHA-256 fingerprint of the
// preferred EK pubkey — same naming convention smallstep CLI uses
// (an AK is "owned" by an EK; one AK per EK).
func preferredAKName(ctx context.Context, t *tpm.TPM) (string, error) {
	eks, err := t.GetEKs(ctx)
	if err != nil {
		return "", fmt.Errorf("GetEKs: %w", err)
	}
	if len(eks) == 0 {
		return "", fmt.Errorf("no TPM EKs available")
	}
	// Prefer RSA EK (TCG default), fall back to whatever's first.
	ek := eks[0]
	for _, e := range eks {
		if _, isRSA := e.Public().(*rsa.PublicKey); isRSA {
			ek = e
			break
		}
	}
	fp, err := keyutil.EncodedFingerprint(ek.Public(), keyutil.HexFingerprint)
	if err != nil {
		return "", fmt.Errorf("ek fingerprint: %w", err)
	}
	// keyutil returns "sha256:<hex>" — strip the prefix.
	if i := strings.IndexByte(fp, ':'); i >= 0 {
		fp = fp[i+1:]
	}
	return fp, nil
}

// getOrCreateAK looks up an AK by name; creates it if missing.
func getOrCreateAK(ctx context.Context, t *tpm.TPM, name string) (*tpm.AK, error) {
	ak, err := t.GetAK(ctx, name)
	if err == nil {
		return ak, nil
	}
	if !errors.Is(err, tpm.ErrNotFound) {
		return nil, fmt.Errorf("GetAK: %w", err)
	}
	ak, err = t.CreateAK(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("CreateAK: %w", err)
	}
	return ak, nil
}

// keyAuthDigest = SHA256(keyAuthorization(token, accountKey))
// — the ACME-tpm spec uses this as TPM2_Certify externalData so the
// AK signature binds the attestation to the specific challenge.
func keyAuthDigest(jwk *jose.JSONWebKey, token string) ([]byte, error) {
	keyAuth, err := acme.KeyAuthorization(token, jwk)
	if err != nil {
		return nil, fmt.Errorf("acme.KeyAuthorization: %w", err)
	}
	sum := sha256.Sum256([]byte(keyAuth))
	return sum[:], nil
}

// loadOrCreateACMEAccountKey returns a JWK for the ACME account.
// First call writes a new ECDSA P-256 key; subsequent calls reload.
func loadOrCreateACMEAccountKey(path string) (*jose.JSONWebKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(b, &jwk); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		return &jwk, nil
	}
	priv, err := keyutil.GenerateDefaultKey()
	if err != nil {
		return nil, fmt.Errorf("genkey: %w", err)
	}
	jwk := &jose.JSONWebKey{
		Key:       priv,
		Algorithm: "ES256",
		Use:       "sig",
	}
	out, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return jwk, nil
}

// waitChallengeValid polls the ACME challenge URL until it reports
// `valid` or `invalid`. step-ca validates device-attest-01
// synchronously so a single fetch is usually enough; we retry for
// network jitter.
func waitChallengeValid(ac *ca.ACMEClient, url string) error {
	for attempt := 0; attempt < 10; attempt++ {
		ch, err := ac.GetChallenge(url)
		if err != nil {
			return fmt.Errorf("get challenge %s: %w", url, err)
		}
		if ch.Status == "valid" {
			return nil
		}
		if ch.Status == "invalid" {
			detail := ""
			if ch.Error != nil {
				detail = ch.Error.Detail
			}
			return fmt.Errorf("challenge %s invalid: %s", url, detail)
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("challenge %s did not reach valid in 20s", url)
}

// pollOrderForCert polls the order (by ID, then finalize URL as a
// fallback) until CertificateURL is populated.
func pollOrderForCert(ac *ca.ACMEClient, orderID, finalizeURL string) (*acme.Order, error) {
	for attempt := 0; attempt < 10; attempt++ {
		// Try the order ID URL first; some step-ca versions take a
		// beat to populate CertificateURL after FinalizeOrder.
		if ord, err := ac.GetOrder(orderID); err == nil &&
			ord.CertificateURL != "" {
			return ord, nil
		}
		// Fallback: hit the finalize URL itself.
		if ord, err := ac.GetOrder(finalizeURL); err == nil &&
			ord.CertificateURL != "" {
			return ord, nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil, fmt.Errorf("order %s never returned a certificate URL", orderID)
}

// dirOf is filepath.Dir but tolerates an empty input.
func dirOf(p string) string {
	if p == "" {
		return "."
	}
	return filepath.Dir(p)
}

// writeTPMKeyMarker persists the JSON marker pancaked reads at
// startup to know which TPM key to load.
func writeTPMKeyMarker(path, storeDir, akName, keyName string) error {
	mb, err := json.MarshalIndent(tpmKeyMarker{
		StorageDir: storeDir,
		AKName:     akName,
		KeyName:    keyName,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(mb, '\n'), 0o600)
}
