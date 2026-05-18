// server_tpm.go: TPM-backed variant of LoadServerConfig. Builds a
// tls.Config whose presented cert is loaded from PEM but whose
// private key lives in the TPM (resolved via internal/tpmkey).

package pkitls

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/sinkap/pancake/common/go/tpmkey"
)

// LoadServerConfigTPM reads the cert chain from certFile (PEM) and
// the TPM key marker from markerFile, then returns a *tls.Config
// that requires + verifies a client cert against caFile. The
// private key is the TPM-resident signer named by the marker.
func LoadServerConfigTPM(certFile, markerFile, caFile string) (*tls.Config, error) {
	leaf, err := loadTPMCertificate(certFile, markerFile)
	if err != nil {
		return nil, err
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

func loadTPMCertificate(certFile, markerFile string) (tls.Certificate, error) {
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read cert %s: %w", certFile, err)
	}
	var chain [][]byte
	rest := pemBytes
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
		rest = r
	}
	if len(chain) == 0 {
		return tls.Certificate{}, fmt.Errorf("no CERTIFICATE PEM blocks in %s", certFile)
	}
	marker, err := tpmkey.Read(markerFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	signer, err := tpmkey.LoadSigner(marker)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tpm signer: %w", err)
	}
	return tls.Certificate{
		Certificate: chain,
		PrivateKey:  signer,
	}, nil
}
