// Package issuance abstracts the act of obtaining a TLS server cert
// for pancaked. The TPM-bound key always comes from the TPM; this
// interface just covers what CA actually signs it.
//
// Two impls exist:
//   - step-ca via ACME-tpm (adapter lives in cmd/pancake; wraps the
//     existing in-process acmeTPMEnroll function).
//   - Google CAS via privateca.CreateCertificate (internal/issuance/gcpcas).
//
// The interface lives here so cmd/pancake can switch on it without
// importing CAS deps when only step-ca is in use, and so the CAS
// package can satisfy it without pulling cmd/pancake's other code.
package issuance

import (
	"context"
)

// Issuer mints a TLS cert chain for the running VM. Implementations
// own how they authenticate to the CA (ACME for step-ca, GCE
// instance identity / ADC for CAS).
type Issuer interface {
	// Name identifies the backend in logs ("step-ca", "gcp-cas").
	Name() string

	// Issue performs the full enrollment: create/attest the TPM key,
	// build a CSR, talk to the CA, write `ServerCertPath` (PEM chain)
	// and `KeyMarkerPath` (JSON pointer to the TPM key) so pancaked
	// can load them at startup.
	Issue(ctx context.Context, in Input) error
}

// Input bundles the per-call parameters. CA-specific configuration
// (URLs, pool names, account keys) lives on the concrete Issuer
// struct, set at construction.
type Input struct {
	// CommonName is the CSR's CN. Usually the system hostname.
	CommonName string

	// DNSNames and IPs become SANs on the issued cert. The fleet
	// server's mTLS dial requires the VM hostname to be in SANs;
	// CN alone is insufficient under modern TLS clients.
	DNSNames []string
	IPs      []string // string form to avoid pulling net into this pkg

	// TPMStoreDir is the directory go.step.sm/crypto/tpm uses to
	// persist AK + key handles + names.
	TPMStoreDir string

	// ServerCertPath is where the PEM cert chain is written.
	ServerCertPath string

	// KeyMarkerPath is where the tiny JSON file pancaked reads to
	// find its TPM-resident key. Format defined by cmd/pancake's
	// writeTPMKeyMarker.
	KeyMarkerPath string
}
