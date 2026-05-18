package fleetapi

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

type eventJSON struct {
	ID            int32           `json:"id"`
	EventType     string          `json:"event_type"`
	VMID          *int32          `json:"vm_id,omitempty"`
	Timestamp     string          `json:"timestamp"`
	Details       json.RawMessage `json:"details"`
	EventHash     string          `json:"event_hash"`
	PrevEventHash string          `json:"prev_event_hash"`
}

func (a *API) listEvents(w http.ResponseWriter, r *http.Request) {
	eventType := r.URL.Query().Get("type")
	limit := int(queryInt(r, "limit", 100))
	rows, err := a.DB.ListEvents(r.Context(), eventType, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]eventJSON, 0, len(rows))
	for _, e := range rows {
		out = append(out, eventJSON{
			ID:            e.ID,
			EventType:     e.EventType,
			VMID:          e.VMID,
			Timestamp:     e.Timestamp.UTC().Format(time.RFC3339),
			Details:       json.RawMessage(e.DetailsJSON),
			EventHash:     hex.EncodeToString(e.EventHash),
			PrevEventHash: hex.EncodeToString(e.PrevEventHash),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}
