// Package fleetapi provides the HTTP REST + SSE API consumed by the
// web UI and operator scripts.
package fleetapi

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sinkap/pancake/backends/fleet-server/internal/attestpoll"
	"github.com/sinkap/pancake/backends/fleet-server/internal/fleetdb"
)

// API holds shared dependencies for HTTP handlers.
type API struct {
	DB     *fleetdb.DB
	Poller *attestpoll.Poller // optional; when nil, on-demand attest returns 503
	WebUI  string             // optional; path to SvelteKit build/ dir to serve at /
}

// Routes wires REST endpoints onto a fresh ServeMux and returns it.
// Callers wrap it with logging/CORS/auth middleware as needed.
func (a *API) Routes() *http.ServeMux {
	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("GET /readyz", a.readyz)

	// VMs
	mux.HandleFunc("GET /api/v1/vms", a.listVMs)
	mux.HandleFunc("GET /api/v1/vms/{id}", a.getVM)
	mux.HandleFunc("GET /api/v1/vms/{id}/attestations", a.listAttestationsForVM)
	mux.HandleFunc("POST /api/v1/vms/{id}/attest", a.attestVM)

	// Attestations (fleet-wide)
	mux.HandleFunc("GET /api/v1/attestations", a.listAttestations)
	mux.HandleFunc("GET /api/v1/attestations/latest", a.listLatestAttestations)

	// Stats
	mux.HandleFunc("GET /api/v1/stats", a.stats)

	// Events / transparency log
	mux.HandleFunc("GET /api/v1/events", a.listEvents)

	// Generations (PCR policies)
	mux.HandleFunc("GET /api/v1/generations", a.listGenerations)
	mux.HandleFunc("GET /api/v1/generations/{id}", a.getGeneration)
	mux.HandleFunc("PUT /api/v1/generations/{id}", a.putGeneration)

	// SvelteKit SPA: serve from WebUI dir if configured. Fallback to
	// index.html for SPA routes (so /vms/42 served as index.html and
	// the client router takes over).
	if a.WebUI != "" {
		mux.HandleFunc("GET /", a.serveUI)
	}

	return mux
}

func (a *API) serveUI(w http.ResponseWriter, r *http.Request) {
	// Don't serve UI for API paths — let those 404 normally.
	if strings.HasPrefix(r.URL.Path, "/api/") ||
		strings.HasPrefix(r.URL.Path, "/healthz") ||
		strings.HasPrefix(r.URL.Path, "/readyz") {
		http.NotFound(w, r)
		return
	}
	// Try the requested file. If missing, fall back to index.html (SPA).
	clean := filepath.Clean(r.URL.Path)
	if clean == "/" {
		clean = "/index.html"
	}
	full := filepath.Join(a.WebUI, clean)
	st, err := os.Stat(full)
	if err == nil && !st.IsDir() {
		http.ServeFile(w, r, full)
		return
	}
	// SPA fallback
	http.ServeFile(w, r, filepath.Join(a.WebUI, "index.html"))
}

func (a *API) healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (a *API) readyz(w http.ResponseWriter, r *http.Request) {
	// Verify we can reach the DB
	if err := a.DB.Pool.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not ready", "error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// helpers

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(body); err != nil {
		// Already wrote the header; just log on the server side.
		// Production: hook into a structured logger.
		_ = err
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func queryInt(r *http.Request, key string, def int32) int32 {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return def
	}
	return int32(n)
}

func pathInt(r *http.Request, key string) (int32, bool) {
	v := r.PathValue(key)
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return 0, false
	}
	return int32(n), true
}
