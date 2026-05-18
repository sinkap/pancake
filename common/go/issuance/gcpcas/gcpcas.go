// Package gcpcas implements issuance.Issuer against Google Cloud
// Certificate Authority Service (CAS).
//
// Flow:
//  1. Open the TPM (go.step.sm/crypto/tpm) and CreateKey — a P-256
//     ECDSA key resident in the TPM, no AK attestation needed (CAS
//     doesn't speak ACME or device-attest-01).
//  2. Build a CSR signed by the TPM key.
//  3. Call privateca.CreateCertificate on the configured CA pool.
//     Authentication is via Application Default Credentials, which
//     on a GCE Shielded VM means the instance service account; the
//     pool must have granted that SA roles/privateca.certificateRequester.
//  4. Write the returned PEM chain to ServerCertPath.
//  5. Write a tpmkey.Marker so pancaked can re-open the TPM and find
//     the key by name on next boot.
//
// Cert lifetime defaults to 90 days. The poller's cert-expiry monitor
// will flag the VM for re-enroll well before expiry.
package gcpcas

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	privatecapb "cloud.google.com/go/security/privateca/apiv1/privatecapb"
	"go.step.sm/crypto/tpm"
	tpmstorage "go.step.sm/crypto/tpm/storage"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/sinkap/pancake/tools/pancake-go/internal/issuance"
	"github.com/sinkap/pancake/tools/pancake-go/internal/tpmkey"
)

// Issuer mints VM TLS certs from a Google CAS pool.
type Issuer struct {
	// Pool is the full CAS pool resource name:
	//   projects/<project>/locations/<region>/caPools/<pool>
	Pool string

	// Lifetime is how long issued certs should be valid. Defaults to 90 days.
	Lifetime time.Duration
}

// New constructs an Issuer. Pool is required; Lifetime defaults to 90 days.
func New(pool string) (*Issuer, error) {
	if pool == "" {
		return nil, fmt.Errorf("gcpcas: pool required (projects/X/locations/Y/caPools/Z)")
	}
	return &Issuer{Pool: pool, Lifetime: 90 * 24 * time.Hour}, nil
}

// Name implements issuance.Issuer.
func (i *Issuer) Name() string { return "gcp-cas" }

// Issue implements issuance.Issuer. See package comment for the full flow.
func (i *Issuer) Issue(ctx context.Context, in issuance.Input) error {
	if err := os.MkdirAll(in.TPMStoreDir, 0o700); err != nil {
		return fmt.Errorf("mkdir tpm store: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(in.ServerCertPath), 0o755); err != nil {
		return fmt.Errorf("mkdir cert dir: %w", err)
	}

	// 1. Open TPM
	t, err := tpm.New(tpm.WithStore(tpmstorage.NewDirstore(in.TPMStoreDir)))
	if err != nil {
		return fmt.Errorf("tpm.New: %w", err)
	}
	tpmCtx := tpm.NewContext(ctx, t)
	if err := t.Available(); err != nil {
		return fmt.Errorf("tpm not available: %w", err)
	}

	// 2. Create TPM-resident key. Use a fresh name per call so
	// re-enrollment doesn't collide. pancaked finds it via the marker.
	keyName := fmt.Sprintf("pancake-tls-cas-%d", time.Now().UnixNano())
	key, err := t.CreateKey(tpmCtx, keyName, tpm.CreateKeyConfig{
		Algorithm: "ECDSA",
		Size:      256,
	})
	if err != nil {
		return fmt.Errorf("tpm CreateKey: %w", err)
	}
	signer, err := key.Signer(tpmCtx)
	if err != nil {
		return fmt.Errorf("tpm signer: %w", err)
	}

	// 3. Build CSR signed by the TPM key
	ips := make([]net.IP, 0, len(in.IPs))
	for _, s := range in.IPs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	csrTmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: in.CommonName},
		DNSNames:    in.DNSNames,
		IPAddresses: ips,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, signer)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// 4. Submit to CAS. ADC handles auth (instance SA on GCE).
	client, err := privateca.NewCertificateAuthorityClient(ctx)
	if err != nil {
		return fmt.Errorf("privateca client (check ADC): %w", err)
	}
	defer client.Close()

	// CertificateId must be unique within the pool. Time-based is fine;
	// the underlying CAS audit trail is keyed by name+serial regardless.
	certID := fmt.Sprintf("%s-%d", sanitizeCertID(in.CommonName), time.Now().Unix())

	resp, err := client.CreateCertificate(ctx, &privatecapb.CreateCertificateRequest{
		Parent:        i.Pool,
		CertificateId: certID,
		Certificate: &privatecapb.Certificate{
			Lifetime: durationpb.New(i.Lifetime),
			CertificateConfig: &privatecapb.Certificate_PemCsr{
				PemCsr: string(csrPEM),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("CAS CreateCertificate (pool=%s id=%s): %w",
			i.Pool, certID, err)
	}

	// 5. Write the cert PEM. CAS returns the leaf + the chain
	// (each issuer + root) separately; concatenate so pancaked's
	// LoadServerConfigTPM sees a complete chain.
	var pemBuf []byte
	pemBuf = append(pemBuf, []byte(resp.PemCertificate)...)
	if len(pemBuf) > 0 && pemBuf[len(pemBuf)-1] != '\n' {
		pemBuf = append(pemBuf, '\n')
	}
	for _, c := range resp.PemCertificateChain {
		pemBuf = append(pemBuf, []byte(c)...)
		if len(pemBuf) > 0 && pemBuf[len(pemBuf)-1] != '\n' {
			pemBuf = append(pemBuf, '\n')
		}
	}
	if err := os.WriteFile(in.ServerCertPath, pemBuf, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", in.ServerCertPath, err)
	}

	// 6. Write the key marker. AKName is intentionally empty — no AK
	// is involved in the CAS path. tpmkey.LoadSigner doesn't need it.
	if err := tpmkey.Write(in.KeyMarkerPath, tpmkey.Marker{
		StorageDir: in.TPMStoreDir,
		AKName:     "",
		KeyName:    key.Name(),
	}); err != nil {
		return fmt.Errorf("write key marker: %w", err)
	}
	return nil
}

// sanitizeCertID maps CommonName to CAS's CertificateId rules:
// lowercase letters, digits, hyphens, max 63 chars.
func sanitizeCertID(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b = append(b, byte(r))
		case r >= 'A' && r <= 'Z':
			b = append(b, byte(r-'A'+'a'))
		case r == '-' || r == '_' || r == '.':
			b = append(b, '-')
		}
	}
	if len(b) > 50 {
		b = b[:50]
	}
	if len(b) == 0 {
		b = []byte("pancake-vm")
	}
	return string(b)
}
