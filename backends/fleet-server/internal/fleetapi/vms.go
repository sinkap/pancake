package fleetapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sinkap/pancake/backends/fleet-server/internal/fleetdb"
)

// vmJSON is the wire format for VMs in the REST API.
// Differs from fleetdb.VM in that timestamps are RFC3339 strings, and
// metadata is a raw JSON object (not a string).
type vmJSON struct {
	ID                int32           `json:"id"`
	Name              string          `json:"name"`
	Platform          string          `json:"platform"`
	InternalIP        string          `json:"internal_ip,omitempty"`
	ExternalIP        string          `json:"external_ip,omitempty"`
	EnrolledAt        string          `json:"enrolled_at"`
	CertSerial        string          `json:"cert_serial,omitempty"`
	CertExpiresAt     string          `json:"cert_expires_at,omitempty"`
	LastHeartbeat     string          `json:"last_heartbeat,omitempty"`
	LastAttestation   string          `json:"last_attestation,omitempty"`
	AttestationStatus string          `json:"attestation_status"`
	CurrentGeneration int32           `json:"current_generation"`
	Metadata          json.RawMessage `json:"metadata,omitempty"`
}

func toVMJSON(v fleetdb.VM) vmJSON {
	j := vmJSON{
		ID:                v.ID,
		Name:              v.Name,
		Platform:          v.Platform,
		InternalIP:        v.InternalIP,
		ExternalIP:        v.ExternalIP,
		EnrolledAt:        v.EnrolledAt.UTC().Format(time.RFC3339),
		CertSerial:        v.CertSerial,
		AttestationStatus: v.AttestationStatus,
		CurrentGeneration: v.CurrentGeneration,
	}
	if v.CertExpiresAt != nil {
		j.CertExpiresAt = v.CertExpiresAt.UTC().Format(time.RFC3339)
	}
	if v.LastHeartbeat != nil {
		j.LastHeartbeat = v.LastHeartbeat.UTC().Format(time.RFC3339)
	}
	if v.LastAttestation != nil {
		j.LastAttestation = v.LastAttestation.UTC().Format(time.RFC3339)
	}
	if v.MetadataJSON != "" {
		j.Metadata = json.RawMessage(v.MetadataJSON)
	}
	return j
}

func (a *API) listVMs(w http.ResponseWriter, r *http.Request) {
	platform := r.URL.Query().Get("platform")
	statusFilter := r.URL.Query().Get("status")
	pageSize := queryInt(r, "page_size", 100)
	offset := queryInt(r, "offset", 0)

	vms, total, err := a.DB.ListVMs(r.Context(), platform, statusFilter, pageSize, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	out := make([]vmJSON, 0, len(vms))
	for _, v := range vms {
		out = append(out, toVMJSON(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vms":    out,
		"total":  total,
		"offset": offset,
	})
}

func (a *API) getVM(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	v, err := a.DB.GetVMByID(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "vm not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toVMJSON(*v))
}

// attestVM triggers an immediate attestation of the named VM via the
// poller. Returns 202 on dispatch (the result lands in attestation_log
// shortly); returns 503 if the poller wasn't enabled at server start.
func (a *API) attestVM(w http.ResponseWriter, r *http.Request) {
	if a.Poller == nil {
		writeError(w, http.StatusServiceUnavailable,
			"poller disabled — restart with mTLS materials to enable on-demand attest")
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	v, err := a.DB.GetVMByID(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "vm not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.Poller.AttestOne(r.Context(), *v); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "attestation completed; see /api/v1/vms/" + strconv.FormatInt(int64(id), 10) + "/attestations",
	})
}
