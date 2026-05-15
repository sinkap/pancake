// Package ahkcid implements a TPM 2.0 Attestation CA — the missing
// half of pancake's ACME-tpm enrollment flow. Same wire protocol as
// smallstep's go.step.sm/crypto/tpm/attestation client speaks, so
// the in-VM `pancake enroll` uses the upstream client unchanged.
//
// Protocol (TCG TPM 2.0 Attestation Activation):
//
//   POST /attest  {tpmInfo, ek, params}    → {credential, secret}  (encrypted to EK)
//   POST /secret  {secret}                  → {chain}              AK cert + CA root
//
// /attest verifies AK↔EK binding and emits an EncryptedCredential
// via attest.ActivationParameters.Generate(). Client decrypts via
// TPM2_ActivateCredential, POSTs the secret back; on match the
// server issues an AK cert with the EK URN as URI SAN — the binding
// step-ca's hasValidIdentity() looks for.

package ahkcid

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-attestation/attest"
)

type Server struct {
	caCert  *x509.Certificate
	caKey   crypto.Signer
	pending sync.Map // sha256(secret)|string -> *pendingChallenge
}

type pendingChallenge struct {
	akPub     []byte
	ekURI     string
	tpm       tpmDetails // hardware info for the AK cert SAN
	createdAt time.Time
}

// NewServer loads (or mints) an AK-CA at caDir/{ca.crt,ca.key}.
func NewServer(caDir string) (*Server, error) {
	cert, key, err := loadOrMintCA(caDir)
	if err != nil {
		return nil, err
	}
	return &Server{caCert: cert, caKey: key}, nil
}

// Routes returns a mux wired to /attest, /secret, /health, /root.crt.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/attest", s.handleAttest)
	mux.HandleFunc("/secret", s.handleSecret)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/root.crt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw})
	})
	return mux
}

type attestationParameters struct {
	Public                  []byte `json:"public,omitempty"`
	UseTCSDActivationFormat bool   `json:"useTCSDActivationFormat,omitempty"`
	CreateData              []byte `json:"createData,omitempty"`
	CreateAttestation       []byte `json:"createAttestation,omitempty"`
	CreateSignature         []byte `json:"createSignature,omitempty"`
}

type attestationRequest struct {
	TPMInfo struct {
		Version         attest.TPMVersion `json:"version,omitempty"`
		Manufacturer    string            `json:"manufacturer,omitempty"`
		Model           string            `json:"model,omitempty"`
		FirmwareVersion string            `json:"firmwareVersion,omitempty"`
	} `json:"tpmInfo"`
	EKPub        []byte                `json:"ek,omitempty"`
	EKCerts      [][]byte              `json:"ekCerts,omitempty"`
	AKCert       []byte                `json:"akCert,omitempty"`
	AttestParams attestationParameters `json:"params"`
}

type attestationResponse struct {
	Credential []byte `json:"credential"`
	Secret     []byte `json:"secret"`
}

type secretRequest struct {
	Secret []byte `json:"secret"`
}

type secretResponse struct {
	CertificateChain [][]byte `json:"chain"`
}

func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req attestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.EKPub) == 0 || len(req.AttestParams.Public) == 0 {
		http.Error(w, "ek and params.public required", http.StatusBadRequest)
		return
	}
	ekPub, err := x509.ParsePKIXPublicKey(req.EKPub)
	if err != nil {
		http.Error(w, "ek pkix parse: "+err.Error(), http.StatusBadRequest)
		return
	}

	ap := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ekPub,
		AK: attest.AttestationParameters{
			Public:                  req.AttestParams.Public,
			UseTCSDActivationFormat: req.AttestParams.UseTCSDActivationFormat,
			CreateData:              req.AttestParams.CreateData,
			CreateAttestation:       req.AttestParams.CreateAttestation,
			CreateSignature:         req.AttestParams.CreateSignature,
		},
	}
	secret, ec, err := ap.Generate()
	if err != nil {
		http.Error(w, "ActivationParameters.Generate: "+err.Error(),
			http.StatusBadRequest)
		return
	}

	// Default the TPM hardware details if the client didn't send
	// any — step-ca rejects empty manufacturer/model/version. For
	// swtpm and TPMs without a manufacturer-signed identity we
	// supply a synthetic but well-formed value.
	td := tpmDetails{
		Manufacturer: req.TPMInfo.Manufacturer,
		Model:        req.TPMInfo.Model,
		Version:      req.TPMInfo.FirmwareVersion,
	}
	if td.Manufacturer == "" {
		td.Manufacturer = "id:00000000"
	}
	if td.Model == "" {
		td.Model = "pancake-ahkcid"
	}
	if td.Version == "" {
		td.Version = "id:00000000"
	}

	hash := sha256.Sum256(secret)
	s.pending.Store(string(hash[:]), &pendingChallenge{
		akPub:     req.AttestParams.Public,
		ekURI:     ekURN(req.EKPub),
		tpm:       td,
		createdAt: time.Now(),
	})

	writeJSON(w, attestationResponse{
		Credential: ec.Credential,
		Secret:     ec.Secret,
	})
}

func (s *Server) handleSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req secretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	hash := sha256.Sum256(req.Secret)
	v, ok := s.pending.LoadAndDelete(string(hash[:]))
	if !ok {
		http.Error(w, "no pending challenge for this secret",
			http.StatusUnauthorized)
		return
	}
	pc := v.(*pendingChallenge)
	if time.Since(pc.createdAt) > 5*time.Minute {
		http.Error(w, "challenge expired", http.StatusUnauthorized)
		return
	}

	akCert, err := s.issueAKCert(pc.akPub, pc.ekURI, pc.tpm)
	if err != nil {
		http.Error(w, "issue: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	writeJSON(w, secretResponse{
		CertificateChain: [][]byte{akCert.Raw, s.caCert.Raw},
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ekURN is the smallstep-format EK URN. step-ca's ACME-tpm validator
// looks for this in the AK cert's URI SANs to bind the challenge
// identifier to the attested hardware identity.
func ekURN(ekPubPKIX []byte) string {
	sum := sha256.Sum256(ekPubPKIX)
	return "urn:ek:sha256:" + base64.StdEncoding.EncodeToString(sum[:])
}
