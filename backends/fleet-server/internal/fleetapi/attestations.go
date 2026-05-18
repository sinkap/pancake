package fleetapi

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sinkap/pancake/backends/fleet-server/internal/fleetdb"
)

type attestationJSON struct {
	ID                 int32           `json:"id"`
	VMID               int32           `json:"vm_id"`
	Timestamp          string          `json:"timestamp"`
	NonceHex           string          `json:"nonce_hex"`
	PCRs               json.RawMessage `json:"pcrs"`
	QuoteHex           string          `json:"quote_hex"`
	SignatureHex       string          `json:"signature_hex"`
	AKPubHex           string          `json:"ak_pub_hex,omitempty"`
	EKPubHex           string          `json:"ek_pub_hex,omitempty"`
	VerificationStatus string          `json:"verification_status"`
	VerificationError  string          `json:"verification_error,omitempty"`
	EventLogSize       int             `json:"event_log_size"` // size only; full log on demand
	AttestationMode    string          `json:"attestation_mode"`
	EKCertSerial       string          `json:"ek_cert_serial,omitempty"`
	EKChainVerified    *bool           `json:"ek_chain_verified,omitempty"`
}

func toAttestationJSON(a fleetdb.Attestation) attestationJSON {
	j := attestationJSON{
		ID:                 a.ID,
		VMID:               a.VMID,
		Timestamp:          a.Timestamp.UTC().Format(time.RFC3339),
		NonceHex:           hex.EncodeToString(a.Nonce),
		QuoteHex:           hex.EncodeToString(a.Quote),
		SignatureHex:       hex.EncodeToString(a.Signature),
		VerificationStatus: a.VerificationStatus,
		VerificationError:  a.VerificationError,
		EventLogSize:       len(a.EventLog),
		AttestationMode:    a.AttestationMode,
		EKCertSerial:       a.EKCertSerial,
		EKChainVerified:    a.EKChainVerified,
	}
	if len(a.AKPub) > 0 {
		j.AKPubHex = hex.EncodeToString(a.AKPub)
	}
	if len(a.EKPub) > 0 {
		j.EKPubHex = hex.EncodeToString(a.EKPub)
	}
	if a.PCRs != "" {
		j.PCRs = json.RawMessage(a.PCRs)
	}
	return j
}

// listLatestAttestations: one row per VM (its newest attestation).
// O(fleet) rows rather than O(fleet × polls), so the default /attestations
// view stays small even when the poller runs for weeks.
func (a *API) listLatestAttestations(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.ListLatestPerVM(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]attestationJSON, 0, len(rows))
	for _, x := range rows {
		out = append(out, toAttestationJSON(x))
	}
	writeJSON(w, http.StatusOK, map[string]any{"attestations": out})
}

func (a *API) listAttestations(w http.ResponseWriter, r *http.Request) {
	limit := int(queryInt(r, "limit", 100))
	rows, err := a.DB.ListAttestations(r.Context(), 0, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]attestationJSON, 0, len(rows))
	for _, x := range rows {
		out = append(out, toAttestationJSON(x))
	}
	writeJSON(w, http.StatusOK, map[string]any{"attestations": out})
}

func (a *API) listAttestationsForVM(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	limit := int(queryInt(r, "limit", 100))
	rows, err := a.DB.ListAttestations(r.Context(), id, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]attestationJSON, 0, len(rows))
	for _, x := range rows {
		out = append(out, toAttestationJSON(x))
	}
	writeJSON(w, http.StatusOK, map[string]any{"attestations": out})
}
