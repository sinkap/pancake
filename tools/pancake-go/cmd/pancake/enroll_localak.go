// enroll_localak.go: local AK cert issuance for dev environments.
//
// In production with hardware TPMs, AK certs would come from a separate
// attestation CA. For dev with swtpm, we sign AK certs locally using the
// same dev EK CA that signed the EK cert. This eliminates the need for
// a separate attest-ca service while maintaining the same TPM attestation
// flow.

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.step.sm/crypto/tpm"
)

// issueLocalAKCert creates an AK certificate signed by the dev EK CA.
// This replaces the HTTP call to attest-ca for local dev environments.
//
// The cert is valid for 90 days and contains the AK public key. step-ca's
// ACME-tpm provisioner will validate this cert against attestationRoots
// (which points to the dev EK CA root).
func issueLocalAKCert(
	ctx context.Context,
	t *tpm.TPM,
	ak *tpm.AK,
	ekCaDir string,
) error {
	// Load dev EK CA key and cert
	caCertPath := filepath.Join(ekCaDir, "ca.crt")
	caKeyPath := filepath.Join(ekCaDir, "ca.key")

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}

	// Parse EC key - handle both with and without EC PARAMETERS block
	var caKey *ecdsa.PrivateKey
	for len(caKeyPEM) > 0 {
		block, rest := pem.Decode(caKeyPEM)
		if block == nil {
			break
		}
		caKeyPEM = rest

		// Skip EC PARAMETERS block, we only want the private key
		if block.Type == "EC PARAMETERS" {
			continue
		}

		if block.Type == "EC PRIVATE KEY" {
			caKey, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("parse CA key: %w", err)
			}
			break
		}

		// Also try PKCS8 format
		if block.Type == "PRIVATE KEY" {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("parse CA key (PKCS8): %w", err)
			}
			var ok bool
			caKey, ok = key.(*ecdsa.PrivateKey)
			if !ok {
				return fmt.Errorf("CA key is not ECDSA")
			}
			break
		}
	}

	if caKey == nil {
		return fmt.Errorf("no EC private key found in %s", caKeyPath)
	}

	// Get AK public key
	akPub := ak.Public()

	// Create AK certificate
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	// TPM AIK certificate OID: 2.23.133.8.3 (tcg-kp-AIKCertificate)
	aikOID := asn1.ObjectIdentifier{2, 23, 133, 8, 3}

	// Build TPM device attributes SAN (DirectoryName).
	// TCG spec requires manufacturer/model/version in AK certs.
	// For swtpm: manufacturer=0x49424D00 (IBM), model=SW TPM, version=firmware.
	tpmManufacturerOID := asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	tpmModelOID := asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	tpmVersionOID := asn1.ObjectIdentifier{2, 23, 133, 2, 3}

	// Build RDN sequence for DirectoryName
	rdnSet := []pkix.AttributeTypeAndValue{
		{Type: tpmManufacturerOID, Value: "id:49424D00"}, // IBM
		{Type: tpmModelOID, Value: "SW TPM"},
		{Type: tpmVersionOID, Value: "id:00000001"}, // version 1
	}

	// Marshal as RDNSequence (SET of AttributeTypeAndValue)
	rdnSeq := pkix.RDNSequence{rdnSet}
	nameBytes, err := asn1.Marshal(rdnSeq)
	if err != nil {
		return fmt.Errorf("marshal RDN: %w", err)
	}

	// Wrap in DirectoryName (context tag [4])
	dirName := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      nameBytes,
	}
	dirNameBytes, err := asn1.Marshal(dirName)
	if err != nil {
		return fmt.Errorf("marshal DirectoryName: %w", err)
	}

	// Wrap in SEQUENCE for SAN extension value
	sanValue, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      dirNameBytes,
	})
	if err != nil {
		return fmt.Errorf("marshal SAN: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		// Subject must be empty per TPM attestation spec
		Subject:               pkix.Name{},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(0, 3, 0), // 90 days
		KeyUsage:              x509.KeyUsageDigitalSignature,
		// Must include AIK EKU
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{aikOID},
		BasicConstraintsValid: true,
		IsCA:                  false,
		// SAN with TPM device attributes (DirectoryName)
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 17}, // SAN OID
				Critical: false,
				Value:    sanValue,
			},
		},
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		caCert,
		akPub,
		caKey,
	)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	akCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse created cert: %w", err)
	}

	// Install cert chain on AK: [AK cert, CA cert]
	chain := []*x509.Certificate{akCert, caCert}
	if err := ak.SetCertificateChain(ctx, chain); err != nil {
		return fmt.Errorf("set AK certificate chain: %w", err)
	}

	fmt.Fprintf(os.Stderr,
		"[enroll] AK cert issued locally (signed by dev EK CA)\n")
	return nil
}

// tryIssueLocalAKCert attempts to issue an AK cert using the dev EK CA.
// Returns nil on success, error if dev EK CA is not available or signing fails.
//
// Searches for dev EK CA in these locations (in order):
//   1. $PANCAKE_DEV_EK_CA env var
//   2. /etc/pancake/orch/dev-ek-ca (baked into orch-config layer)
//   3. ./pancake-host-state/dev-ek-ca (operator local dir)
func tryIssueLocalAKCert(
	ctx context.Context,
	t *tpm.TPM,
	ak *tpm.AK,
) error {
	// Try to find dev EK CA in standard locations
	candidates := []string{
		os.Getenv("PANCAKE_DEV_EK_CA"),
		"/etc/pancake/orch/dev-ek-ca",
		"./pancake-host-state/dev-ek-ca",
		"../pancake-host-state/dev-ek-ca",
	}

	var errs []string
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		caCert := filepath.Join(dir, "ca.crt")
		caKey := filepath.Join(dir, "ca.key")
		if _, err := os.Stat(caCert); err == nil {
			if _, err := os.Stat(caKey); err == nil {
				return issueLocalAKCert(ctx, t, ak, dir)
			} else {
				errs = append(errs, fmt.Sprintf("%s: ca.key not found", dir))
			}
		}
	}

	return fmt.Errorf("dev EK CA not found or incomplete. Searched:\n  %s",
		strings.Join(append([]string{strings.Join(candidates, ", ")}, errs...), "\n  "))
}

// akPublicKey converts TPM AK public key to crypto.PublicKey.
// Helper for issueLocalAKCert.
func akPublicKey(ak crypto.PublicKey) (crypto.PublicKey, error) {
	switch pub := ak.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported AK public key type: %T", ak)
	}
}
