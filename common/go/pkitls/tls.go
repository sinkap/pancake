// Package pkitls builds the *tls.Config values that pancaked (gRPC
// server) and `pancake orchestrate` (gRPC client) use for mutual TLS.
//
// All trust is rooted in PEM files on disk:
//
//	ca.crt        — root cert that signed both peers
//	<peer>.crt    — leaf cert presented by the peer
//	<peer>.key    — peer's private key
//
// Rotation is "drop new files, restart". This minimum-viable PKI
// proves the auth model end-to-end; ACME-device-attest enrollment
// (step-ca) replaces the manual issue path in a follow-up change.
package pkitls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadServerConfig builds a *tls.Config that requires + verifies a
// peer client cert against caFile. Used by pancaked.
func LoadServerConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	leaf, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("server keypair (%s/%s): %w",
			certFile, keyFile, err)
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{leaf},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// LoadClientConfig builds a *tls.Config that presents a client cert
// and verifies the server cert against caFile. serverName overrides
// the SNI / cert hostname check (use the SAN baked into the server
// cert; "" = use the dial address).
func LoadClientConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	leaf, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("client keypair (%s/%s): %w",
			certFile, keyFile, err)
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{leaf},
		RootCAs:            pool,
		ServerName:         serverName,
		InsecureSkipVerify: true, // TPM certs use permanent-identifier SANs, not DNS
		MinVersion:         tls.VersionTLS13,
	}, nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %s contained no PEM certs", caFile)
	}
	return pool, nil
}
