// Package signsrv implements the pancake-sign HTTP service.
package signsrv

import (
	"fmt"
	"io"
	"net/http"

	"github.com/sinkap/pancake/tools/pancake-go/internal/sign"
)

// Server wraps a sign.Signer and exposes it over HTTP.
type Server struct {
	signer sign.Signer
	mux    *http.ServeMux
}

func New(signer sign.Signer) *Server {
	s := &Server{signer: signer, mux: http.NewServeMux()}
	s.mux.HandleFunc("POST /sign/uki", s.handleSignUKI)
	s.mux.HandleFunc("POST /sign/manifest", s.handleSignManifest)
	s.mux.HandleFunc("GET /signing-cert", s.handleGetCert)
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// POST /sign/uki — body is unsigned PE bytes; response is signed PE.
func (s *Server) handleSignUKI(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err),
			http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	signed, err := s.signer.SignUKI(r.Context(), body)
	if err != nil {
		http.Error(w, fmt.Sprintf("SignUKI: %v", err),
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(signed)
}

// POST /sign/manifest — body is raw bytes; response is detached signature.
func (s *Server) handleSignManifest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read body: %v", err),
			http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	sig, err := s.signer.SignManifest(r.Context(), body)
	if err != nil {
		http.Error(w, fmt.Sprintf("SignManifest: %v", err),
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(sig)
}

// GET /signing-cert — returns the leaf cert PEM.
func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request) {
	cert, err := s.signer.Cert(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("Cert: %v", err),
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(cert)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// signer.Cert is the cheapest "is everything wired up" probe.
	if _, err := s.signer.Cert(r.Context()); err != nil {
		http.Error(w, fmt.Sprintf("not ready: %v", err),
			http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}
