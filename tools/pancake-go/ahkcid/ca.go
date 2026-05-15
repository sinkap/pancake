// ca.go: AK-CA primitives for the attestation server.
// Self-signed root, ECDSA P-256, persisted as PEM.
//
// AK certs we mint are intentionally minimal: short TTL, ClientAuth
// EKU, EK URN as URI SAN. step-ca's ACME-tpm validator checks the
// chain (against `attestationRoots`) and looks for the EK URN in
// the URI SANs — that's the binding. Nothing else is required.

package ahkcid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	tpm2leg "github.com/google/go-tpm/legacy/tpm2"
)

// tcgKpAIKCertificate is the TCG-defined ExtKeyUsage OID
// (2.23.133.8.3) that step-ca's ACME-tpm validator requires on AK
// certs. From "TCG TPM 2.0 Keys for Device Identity and Attestation".
var tcgKpAIKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 3}

func loadOrMintCA(dir string) (*x509.Certificate, crypto.Signer, error) {
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if certBytes, err := os.ReadFile(certPath); err == nil {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", keyPath, err)
		}
		certBlock, _ := pem.Decode(certBytes)
		keyBlock, _ := pem.Decode(keyBytes)
		if certBlock == nil || keyBlock == nil {
			return nil, nil, fmt.Errorf("ca files: missing PEM blocks")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
		k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("ca.key is not ECDSA")
		}
		return cert, ec, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "pancake-ahkcid"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// issueAKCert decodes the AK pubArea (TPMT_PUBLIC), extracts the
// public key, and signs a leaf cert per the TCG TPM 2.0 Keys for
// Device Identity profile that step-ca's ACME-tpm validator enforces:
//   - empty Subject
//   - tcg-kp-AIKCertificate EKU (2.23.133.8.3)
//   - SAN extension with directoryName carrying TPM manufacturer/
//     model/version + URI carrying the EK URN
func (s *Server) issueAKCert(akPubArea []byte, ekURI string, td tpmDetails) (*x509.Certificate, error) {
	pub, err := tpm2leg.DecodePublic(akPubArea)
	if err != nil {
		return nil, fmt.Errorf("decode pubArea: %w", err)
	}
	pubKey, err := pub.Key()
	if err != nil {
		return nil, fmt.Errorf("AK pub key: %w", err)
	}
	sanExt, err := buildSANExtension(ekURI, td)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{},
		NotBefore:          now.Add(-time.Minute),
		NotAfter:           now.Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{tcgKpAIKCertificate},
		ExtraExtensions:    []pkix.Extension{sanExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, pubKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign AK cert: %w", err)
	}
	return x509.ParseCertificate(der)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	return os.WriteFile(path, b, mode)
}
