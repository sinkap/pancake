// enroll_attest.go: build the WebAuthn-style "tpm" attestation
// statement that the ACME device-attest-01 challenge expects.
//
// Wire format (CBOR-encoded):
//
//	{
//	  "fmt":     "tpm",
//	  "attStmt": {
//	    "ver":      "2.0",
//	    "alg":      <COSE alg id, -7 ES256 / -257 RS256>,
//	    "x5c":      <CBOR array of AK cert chain DER bytes>,
//	    "sig":      <AK signature over certInfo (TPMT_SIGNATURE)>,
//	    "certInfo": <TPM2B_ATTEST blob from TPM2_Certify>,
//	    "pubArea":  <attested key's TPMT_PUBLIC>
//	  }
//	}
//
// Mirrors smallstep/cli's attestationStatement() — same key names
// and types so step-ca's verifier accepts what we produce.

package main

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	tpm2leg "github.com/google/go-tpm/legacy/tpm2"
	"go.step.sm/crypto/tpm"
)

type attestationObject struct {
	Format       string                 `cbor:"fmt"`
	AttStatement map[string]interface{} `cbor:"attStmt,omitempty"`
}

// buildTPMAttestationStatement assembles + CBOR-encodes the "tpm"
// attestation statement for the given attested key + AK chain.
func buildTPMAttestationStatement(
	ctx context.Context,
	key *tpm.Key,
	akChain []*x509.Certificate,
) ([]byte, error) {
	params, err := key.CertificationParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("CertificationParameters: %w", err)
	}

	akChainDER := make([][]byte, len(akChain))
	for i, c := range akChain {
		akChainDER[i] = c.Raw
	}

	pub, err := tpm2leg.DecodePublic(params.Public)
	if err != nil {
		return nil, fmt.Errorf("decode pubArea: %w", err)
	}
	var alg int64
	switch pub.Type {
	case tpm2leg.AlgRSA:
		alg = -257 // RS256
	case tpm2leg.AlgECC:
		alg = -7 // ES256
	default:
		return nil, fmt.Errorf("unsupported TPM key type 0x%x", pub.Type)
	}

	obj := attestationObject{
		Format: "tpm",
		AttStatement: map[string]interface{}{
			"ver":      "2.0",
			"alg":      alg,
			"x5c":      akChainDER,
			"sig":      params.CreateSignature,
			"certInfo": params.CreateAttestation,
			"pubArea":  params.Public,
		},
	}
	return cbor.Marshal(obj)
}
