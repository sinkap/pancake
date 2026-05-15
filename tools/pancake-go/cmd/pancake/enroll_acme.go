// enroll_acme.go: ACME device-attest-01 enrollment driver.
// Mirrors smallstep CLI's `step ca certificate --kms tpmkms:...`
// flow but in-process so we don't ship `step` CLI in the VM image.

package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/ca"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/tpm"
	tpmstorage "go.step.sm/crypto/tpm/storage"
)

// acmeTPMOpts is the bundle of settings that drives one enrollment.
type acmeTPMOpts struct {
	CAURL        string
	CARoot       string
	AttestCAURL  string
	AttestCARoot string
	CommonName   string
	DNSNames     []string
	IPs          []net.IP
	ServerCert   string
	TPMStoreDir  string
	KeyMarker    string
	AcctKeyFile  string
}

// acmeTPMEnroll runs the full ACME device-attest-01 flow.
func acmeTPMEnroll(o acmeTPMOpts) error {
	for _, d := range []string{
		o.TPMStoreDir,
		dirOf(o.AcctKeyFile),
		dirOf(o.ServerCert),
	} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	t, err := tpm.New(tpm.WithStore(tpmstorage.NewDirstore(o.TPMStoreDir)))
	if err != nil {
		return fmt.Errorf("tpm.New: %w", err)
	}
	ctx := tpm.NewContext(context.Background(), t)
	if err := t.Available(); err != nil {
		return fmt.Errorf("tpm not available: %w", err)
	}

	akName, err := preferredAKName(ctx, t)
	if err != nil {
		return err
	}
	ak, err := getOrCreateAK(ctx, t, akName)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[enroll] AK %q ready\n", ak.Name())

	// Enroll the AK with pancake-attest-ca (TPM Attestation CA) so we
	// have a cert chain to put in the ACME-tpm attestation
	// statement's `x5c`. step-ca's ACME-tpm provisioner verifies
	// this chain against `attestationRoots`.
	if o.AttestCAURL != "" {
		if err := enrollAKWithAttestCA(ctx, t, ak,
			o.AttestCAURL, o.AttestCARoot); err != nil {
			return fmt.Errorf("AK enrollment with attestation CA: %w", err)
		}
		fmt.Fprintf(os.Stderr,
			"[enroll] AK cert chain installed (issued by %s)\n",
			o.AttestCAURL)
	} else if len(ak.CertificateChain()) == 0 {
		return fmt.Errorf("AK has no cert chain and --attest-ca-url is unset; " +
			"step-ca's ACME-tpm validation will reject the empty x5c")
	}

	// NewACMEClient registers a fresh account using an internally-
	// generated ephemeral key and stores it in ac.Key. We DON'T
	// override ac.Key — doing so detaches subsequent signed
	// requests from the registered account (step-ca sees a JWS
	// signature that doesn't match the account on file → rejects
	// new-order as malformed). Persistent account-key reuse is a
	// follow-up; for now each enrollment registers a new account.
	caOpts := []ca.ClientOption{}
	if o.CARoot != "" {
		caOpts = append(caOpts, ca.WithRootFile(o.CARoot))
	}
	ac, err := ca.NewACMEClient(o.CAURL, []string{}, caOpts...)
	if err != nil {
		return fmt.Errorf("acme client: %w", err)
	}
	acctKey := ac.Key

	// ACME-tpm uses a single permanent-identifier order whose value
	// is the device's hardware ID (the CN, here). DNS/IP SANs land
	// in the issued cert via the CSR, not the order. step-ca matches
	// the order's permanent-identifier against the attested hardware
	// identifiers from the TPM AK cert during validation.
	order, err := newPermanentIDOrder(ac, o.CommonName)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[enroll] ACME order created (%d authz)\n",
		len(order.AuthorizationURLs))

	keyName := fmt.Sprintf("pancake-tls-%d", os.Getpid())
	attestedKey, err := solveChallenges(
		ctx, t, ak, ac, acctKey, order, keyName)
	if err != nil {
		return err
	}

	return finalizeAndWriteCert(ctx, ac, attestedKey, ak, o, order)
}

func newPermanentIDOrder(ac *ca.ACMEClient, deviceID string) (*acme.Order, error) {
	req := struct {
		Identifiers []acme.Identifier `json:"identifiers"`
	}{
		Identifiers: []acme.Identifier{{
			Type:  acme.PermanentIdentifier,
			Value: deviceID,
		}},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return ac.NewOrder(body)
}

// solveChallenges loops over the order's authzs, solving each
// device-attest-01 with a single TPM key (attested once).
func solveChallenges(
	ctx context.Context, t *tpm.TPM, ak *tpm.AK,
	ac *ca.ACMEClient, acctKey *jose.JSONWebKey,
	order *acme.Order, keyName string,
) (*tpm.Key, error) {
	var attestedKey *tpm.Key
	for _, authzURL := range order.AuthorizationURLs {
		authz, err := ac.GetAuthz(authzURL)
		if err != nil {
			return nil, fmt.Errorf("get authz %s: %w", authzURL, err)
		}
		var ch *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "device-attest-01" {
				ch = c
				break
			}
		}
		if ch == nil {
			return nil, fmt.Errorf(
				"authz %s has no device-attest-01 challenge", authzURL)
		}

		digest, err := keyAuthDigest(acctKey, ch.Token)
		if err != nil {
			return nil, err
		}
		if attestedKey == nil {
			attestedKey, err = t.AttestKey(ctx, ak.Name(), keyName,
				tpm.AttestKeyConfig{
					Algorithm:      "ECDSA",
					Size:           256,
					QualifyingData: digest,
				})
			if err != nil {
				return nil, fmt.Errorf("attest key: %w", err)
			}
		}

		attStmt, err := buildTPMAttestationStatement(
			ctx, attestedKey, ak.CertificateChain())
		if err != nil {
			return nil, fmt.Errorf("build attestation statement: %w", err)
		}
		bodyBytes, _ := json.Marshal(struct {
			AttObj string `json:"attObj"`
		}{
			AttObj: base64.RawURLEncoding.EncodeToString(attStmt),
		})
		if err := ac.ValidateWithPayload(ch.URL, bodyBytes); err != nil {
			return nil, fmt.Errorf("validate challenge %s: %w", ch.URL, err)
		}
		if err := waitChallengeValid(ac, ch.URL); err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "[enroll]   authz %s validated\n", authzURL)
	}
	return attestedKey, nil
}

// finalizeAndWriteCert builds the CSR signed by the TPM key,
// finalizes the order, fetches the issued cert chain, and writes
// it (PEM) plus the JSON marker that pancaked uses to find the key.
func finalizeAndWriteCert(
	ctx context.Context, ac *ca.ACMEClient, attestedKey *tpm.Key,
	ak *tpm.AK, o acmeTPMOpts, order *acme.Order,
) error {
	signer, err := attestedKey.Signer(ctx)
	if err != nil {
		return fmt.Errorf("tpm signer: %w", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: o.CommonName},
		DNSNames:    o.DNSNames,
		IPAddresses: o.IPs,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return err
	}

	if err := ac.FinalizeOrder(order.FinalizeURL, csr); err != nil {
		return fmt.Errorf("finalize order: %w", err)
	}
	finalOrder, err := pollOrderForCert(ac, order.ID, order.FinalizeURL)
	if err != nil {
		return err
	}
	leaf, chain, err := ac.GetCertificate(finalOrder.CertificateURL)
	if err != nil {
		return fmt.Errorf("get certificate: %w", err)
	}

	pemBuf := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: leaf.Raw})
	for _, c := range chain {
		pemBuf = append(pemBuf, pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := os.WriteFile(o.ServerCert, pemBuf, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", o.ServerCert, err)
	}
	return writeTPMKeyMarker(
		o.KeyMarker, o.TPMStoreDir, ak.Name(), attestedKey.Name())
}
