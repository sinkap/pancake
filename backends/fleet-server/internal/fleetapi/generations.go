package fleetapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sinkap/pancake/tools/pancake-go/fleet-server/internal/fleetdb"
)

type generationJSON struct {
	Generation  int32             `json:"generation"`
	PCRs        map[string]string `json:"pcrs"`
	Description string            `json:"description,omitempty"`
	CreatedAt   string            `json:"created_at"`
}

func toGenerationJSON(g fleetdb.ExpectedPCRs) generationJSON {
	return generationJSON{
		Generation:  g.Generation,
		PCRs:        g.PCRs,
		Description: g.Description,
		CreatedAt:   g.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func (a *API) listGenerations(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.ListExpectedPCRs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]generationJSON, 0, len(rows))
	for _, g := range rows {
		out = append(out, toGenerationJSON(g))
	}
	writeJSON(w, http.StatusOK, map[string]any{"generations": out})
}

func (a *API) getGeneration(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid generation id")
		return
	}
	g, err := a.DB.GetExpectedPCRs(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "generation not registered")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toGenerationJSON(*g))
}

type putGenerationBody struct {
	PCRs        map[string]string `json:"pcrs"`
	Description string            `json:"description"`
}

func (a *API) putGeneration(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid generation id")
		return
	}
	var body putGenerationBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if len(body.PCRs) == 0 {
		writeError(w, http.StatusBadRequest, "pcrs must be non-empty")
		return
	}
	if err := a.DB.UpsertExpectedPCRs(r.Context(), id, body.PCRs, body.Description); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Log a transparency event for the policy change
	details, _ := json.Marshal(map[string]any{
		"generation":  id,
		"pcr_count":   len(body.PCRs),
		"description": body.Description,
	})
	_, _ = a.DB.InsertEvent(r.Context(), "policy_updated", nil, string(details))

	g, _ := a.DB.GetExpectedPCRs(r.Context(), id)
	writeJSON(w, http.StatusOK, toGenerationJSON(*g))
}
