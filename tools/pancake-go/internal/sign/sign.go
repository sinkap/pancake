// Package sign covers two signing operations pancake-bootstrap performs
// when --sign-key + --sign-cert are passed:
//
//  1. UKI signing: handed off to systemd-ukify (which calls sbsign) so the
//     resulting Unified Kernel Image is a valid UEFI Secure Boot signed PE
//     binary. UEFI verifies the signature against `db` before loading.
//
//  2. Manifest signing: produces <kit>/generations/<N>/manifest.toml.sig,
//     a raw RSA-SHA256 signature over the bytes of manifest.toml. Verifiable
//     via `openssl dgst -sha256 -verify pubkey.pem -signature manifest.sig
//     manifest.toml`. The public key is extracted from the X.509 cert and
//     baked into the initramfs at /etc/pancake/manifest.pubkey so /init
//     can run that exact openssl command before reading lowers.
//
// We deliberately use the same key for both. UEFI's Secure Boot verification
// machinery wants an X.509 cert (sbsign chains key to cert to db); openssl
// dgst -verify only needs the public key, which we extract from the cert.
// One key, one cert, two derived artifacts in the initramfs (none for UKI;
// /etc/pancake/manifest.pubkey for the manifest).
package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// PubkeyFromCert reads an X.509 PEM cert and writes the SubjectPublicKeyInfo
// out as a PEM-encoded public key. That's the form `openssl dgst -verify`
// expects (it handles raw -----BEGIN PUBLIC KEY----- blocks fine).
//
// We do this in pure Go rather than shelling out to `openssl x509 -pubkey
// -noout` because the latter prints the cert too, requires extra parsing,
// and adds an external dep to the build path that we already have natively.
func PubkeyFromCert(certPath, outPubkeyPath string) error {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("%s: not a PEM file", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal pubkey: %w", err)
	}
	out, err := os.Create(outPubkeyPath)
	if err != nil {
		return err
	}
	defer out.Close()
	return pem.Encode(out, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}

// SignManifest produces manifestPath + ".sig" with a raw RSA-PKCS1-v1_5
// SHA-256 signature over the file bytes. Detached, no envelope — `openssl
// dgst -sha256 -verify pubkey.pem -signature manifestPath.sig manifestPath`
// verifies it.
//
// Pure Go (crypto/rsa) so the build path doesn't gain a runtime openssl
// dep on the host. The verification path inside the initramfs DOES use
// openssl (cheaper than dragging Go into the initramfs).
func SignManifest(manifestPath, keyPath string) (string, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return "", fmt.Errorf("%s: not a PEM file", keyPath)
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return "", fmt.Errorf("parse pkcs8: %w", e)
		}
		var ok bool
		key, ok = k.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("%s: not an RSA private key", keyPath)
		}
	default:
		return "", fmt.Errorf("%s: unsupported PEM type %q (need RSA "+
			"PRIVATE KEY or PRIVATE KEY for RSA)", keyPath, block.Type)
	}
	if err != nil {
		return "", err
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("read manifest: %w", err)
	}
	digest := sha256.Sum256(manifestBytes)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	sigPath := manifestPath + ".sig"
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		return "", err
	}
	return sigPath, nil
}

// EnsureKeyAndCert: if keyPath or certPath don't exist, generate a fresh
// RSA-2048 dev pair at those paths. Useful for `pancake bootstrap` when
// the user hasn't pre-provisioned signing material — we conjure a CA-less
// self-signed pair and tell them where it landed. Returns true if newly
// generated, false if files already existed.
//
// Production usage is supposed to provide real keys. The generated cert
// has CN="pancake-dev <hostname> <timestamp>" so it's easy to recognize.
func EnsureKeyAndCert(keyPath, certPath, hostname string) (bool, error) {
	_, errK := os.Stat(keyPath)
	_, errC := os.Stat(certPath)
	if errK == nil && errC == nil {
		return false, nil
	}
	if errK == nil || errC == nil {
		return false, fmt.Errorf("sign: one of %s, %s exists but not the "+
			"other; refusing to mix old + new", keyPath, certPath)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return false, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return false, err
	}
	keyOut, err := os.OpenFile(keyPath,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return false, err
	}
	if err := pem.Encode(keyOut, &pem.Block{
		Type: "PRIVATE KEY", Bytes: keyDER,
	}); err != nil {
		keyOut.Close()
		return false, err
	}
	keyOut.Close()

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("pancake-dev %s %s",
				hostname, time.Now().UTC().Format("2006-01-02")),
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return false, err
	}
	certOut, err := os.OpenFile(certPath,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return false, err
	}
	if err := pem.Encode(certOut, &pem.Block{
		Type: "CERTIFICATE", Bytes: der,
	}); err != nil {
		certOut.Close()
		return false, err
	}
	certOut.Close()
	return true, nil
}
