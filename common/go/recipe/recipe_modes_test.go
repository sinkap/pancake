package recipe

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseModes verifies the recipe parses the new attestation.ek-trust,
// issuance.ca, issuance.step-ca.url, issuance.cas.pool fields without
// blowing up strict-mode "unknown field" detection.
func TestParseModes(t *testing.T) {
	cases := map[string]struct {
		body         string
		wantPlatform string
		wantEKTrust  string
		wantCA       string
		wantStepURL  string
		wantCASPool  string
	}{
		"dev defaults": {
			body: `output: ./kit
platform: dev
ca-url: https://127.0.0.1:8443/acme/tpm/directory
`,
			wantPlatform: "dev",
		},
		"gcp full": {
			body: `output: ./kit
platform: gcp
ca-url: https://unused.example.com/acme/tpm/directory
attestation:
  ek-trust: google-vtpm
issuance:
  ca: gcp-cas
  cas:
    pool: projects/my-proj/locations/us-central1/caPools/pancake
`,
			wantPlatform: "gcp",
			wantEKTrust:  "google-vtpm",
			wantCA:       "gcp-cas",
			wantCASPool:  "projects/my-proj/locations/us-central1/caPools/pancake",
		},
		"self-hosted hardware": {
			body: `output: ./kit
platform: self-hosted
ca-url: https://prod-ca.example.com:8443/acme/tpm/directory
attestation:
  ek-trust: manufacturer
issuance:
  ca: step-ca
  step-ca:
    url: https://prod-ca.example.com:8443/acme/tpm/directory
`,
			wantPlatform: "self-hosted",
			wantEKTrust:  "manufacturer",
			wantCA:       "step-ca",
			wantStepURL:  "https://prod-ca.example.com:8443/acme/tpm/directory",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recipe.yaml")
			if err := os.WriteFile(path, []byte(c.body), 0o644); err != nil {
				t.Fatal(err)
			}
			r, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if r.Platform != c.wantPlatform {
				t.Errorf("Platform = %q, want %q", r.Platform, c.wantPlatform)
			}
			if r.Attestation.EKTrust != c.wantEKTrust {
				t.Errorf("EKTrust = %q, want %q", r.Attestation.EKTrust, c.wantEKTrust)
			}
			if r.Issuance.CA != c.wantCA {
				t.Errorf("Issuance.CA = %q, want %q", r.Issuance.CA, c.wantCA)
			}
			if r.Issuance.StepCA.URL != c.wantStepURL {
				t.Errorf("StepCA.URL = %q, want %q", r.Issuance.StepCA.URL, c.wantStepURL)
			}
			if r.Issuance.CAS.Pool != c.wantCASPool {
				t.Errorf("CAS.Pool = %q, want %q", r.Issuance.CAS.Pool, c.wantCASPool)
			}
		})
	}
}
