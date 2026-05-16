// Package hoststate resolves the operator host state directory and
// provides default paths for client certs, trust roots, and service
// URLs. Used by all CLI commands that talk to the orchestrator stack
// (attest, orchestrate, bootstrap, enroll) so they work out of the
// box after `docker compose up && pancake host-cert init && source
// pancake.env`.
package hoststate

import (
	"fmt"
	"os"
	"path/filepath"
)

// Paths holds resolved paths for operator host state: client certs,
// trust roots, and service URLs. All fields except Dir may be empty
// if the state directory doesn't contain the corresponding file.
type Paths struct {
	// Dir is the resolved state directory path
	Dir string

	// Client mTLS cert and key for talking to pancaked
	ClientCert string
	ClientKey  string

	// Trust roots for verifying step-ca and attest-ca
	TrustRoot    string // step-ca root cert
	AttestCARoot string // attest-ca root cert

	// Service URLs
	BuilderAddr   string // pancake-build-server gRPC address
	CAURL         string // step-ca HTTPS URL
	AttestCAURL   string // attest-ca HTTPS URL
}

// Resolve searches for the operator host state directory in this order:
//   1. $PANCAKE_HOST_STATE
//   2. ./pancake-host-state (current working directory)
//   3. $XDG_CONFIG_HOME/pancake (or ~/.config/pancake if XDG_CONFIG_HOME unset)
//
// Returns Paths with all known file paths resolved. Fields are empty
// if the state directory doesn't exist or doesn't contain the file.
// Returns an error only if the search fails entirely (no candidate
// directory exists).
func Resolve() (Paths, error) {
	var candidates []string

	// 1. $PANCAKE_HOST_STATE
	if env := os.Getenv("PANCAKE_HOST_STATE"); env != "" {
		candidates = append(candidates, env)
	}

	// 2. ./pancake-host-state
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "pancake-host-state"))
	}

	// 3. $XDG_CONFIG_HOME/pancake or ~/.config/pancake
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		if home, err := os.UserHomeDir(); err == nil {
			configHome = filepath.Join(home, ".config")
		}
	}
	if configHome != "" {
		candidates = append(candidates, filepath.Join(configHome, "pancake"))
	}

	// Find first existing directory
	var stateDir string
	for _, candidate := range candidates {
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			stateDir = candidate
			break
		}
	}

	if stateDir == "" {
		return Paths{}, fmt.Errorf("no pancake host state directory found; tried: %v", candidates)
	}

	p := Paths{Dir: stateDir}

	// Resolve individual files — don't error if missing, just leave empty
	p.ClientCert = fileIfExists(filepath.Join(stateDir, "client.crt"))
	p.ClientKey = fileIfExists(filepath.Join(stateDir, "client.key"))
	p.TrustRoot = fileIfExists(filepath.Join(stateDir, "step-root.crt"))
	p.AttestCARoot = fileIfExists(filepath.Join(stateDir, "attest-ca-root.crt"))

	// Read URL files
	p.CAURL = readStringFile(filepath.Join(stateDir, "ca-url"))
	p.AttestCAURL = readStringFile(filepath.Join(stateDir, "attest-ca-url"))
	p.BuilderAddr = readStringFile(filepath.Join(stateDir, "builder-addr"))

	return p, nil
}

// fileIfExists returns path if the file exists, empty string otherwise.
func fileIfExists(path string) string {
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		return path
	}
	return ""
}

// readStringFile reads a single-line string from a file, trimming whitespace.
// Returns empty string if the file doesn't exist or can't be read.
func readStringFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Trim trailing newline
	s := string(b)
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	return s
}
