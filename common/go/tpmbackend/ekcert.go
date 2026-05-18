package tpmbackend

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// readNVCertFromTPM shells out to tpm2_nvread for the given NV index,
// parses the result as DER, and returns the x509 cert. Returns
// (nil, nil) if the index isn't provisioned (tpm2_nvread exits with the
// TPM "handle not present" error). Any other error is fatal.
//
// Exported as a helper for backends — pass the TCG-standard NV index
// constants (NVIndexECCEKCert / NVIndexRSAEKCert).
func readNVCertFromTPM(ctx context.Context, nvIndex string) (*x509.Certificate, error) {
	tmp, err := os.CreateTemp("", "ekcert-*.der")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// tpm2_nvread -o <file> <index> — TPM2TOOLS_TCTI must be set by the
	// backend's SetupEnv() before this is called.
	out, err := exec.CommandContext(cctx,
		"tpm2_nvread", "-o", tmp.Name(), nvIndex).CombinedOutput()
	if err != nil {
		// tpm2_nvread returns an error message containing
		// "0x18b" or "Esys_NV_Read(0x18B)" when the NV index isn't
		// provisioned. Treat as "no cert here" rather than fatal so
		// callers can probe both ECC + RSA indices.
		if isHandleNotPresent(out, err) {
			return nil, nil
		}
		return nil, fmt.Errorf("tpm2_nvread %s: %w (output: %s)",
			nvIndex, err, string(out))
	}

	der, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", tmp.Name(), err)
	}
	if len(der) == 0 {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse EK cert from NV %s: %w", nvIndex, err)
	}
	return cert, nil
}

func isHandleNotPresent(out []byte, err error) bool {
	if err == nil {
		return false
	}
	s := string(out)
	// tpm2-tools surfaces TPM_RC_HANDLE in a few formats depending on version.
	return contains(s, "0x18b") || contains(s, "0x18B") ||
		contains(s, "TPM_RC_HANDLE") || contains(s, "handle does not exist")
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// fetchAIAChain walks the AuthorityInformationAccess "issuer" URLs on
// `leaf` to build the cert chain back toward the manufacturer root.
// Returns whatever intermediates it can fetch; on any failure returns
// the partial chain (caller still has the leaf, can verify against
// trust roots, partial chain is fine).
//
// Limits: max 5 hops, 5 second timeout per fetch, ignores anything
// not DER.
func fetchAIAChain(ctx context.Context, leaf *x509.Certificate) []*x509.Certificate {
	if leaf == nil {
		return nil
	}
	var chain []*x509.Certificate
	current := leaf
	cl := &http.Client{Timeout: 5 * time.Second}
	for hop := 0; hop < 5; hop++ {
		next, err := fetchIssuingCert(ctx, cl, current)
		if err != nil || next == nil {
			return chain
		}
		chain = append(chain, next)
		// Stop when we reach a self-signed cert (a root)
		if next.CheckSignatureFrom(next) == nil {
			return chain
		}
		current = next
	}
	return chain
}

func fetchIssuingCert(ctx context.Context, cl *http.Client, c *x509.Certificate) (*x509.Certificate, error) {
	if len(c.IssuingCertificateURL) == 0 {
		return nil, nil
	}
	for _, u := range c.IssuingCertificateURL {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}
		resp, err := cl.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if err != nil || len(body) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(body)
		if err != nil {
			// Some CAs serve PEM at AIA; not handling that here yet.
			continue
		}
		return cert, nil
	}
	return nil, errors.New("no usable AIA URL")
}
