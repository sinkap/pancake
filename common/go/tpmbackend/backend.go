// Package tpmbackend provides platform-specific TPM backend abstraction.
//
// Supports multiple TPM sources:
//   - swtpm: software TPM for development (self-hosted mode)
//   - GCE vTPM: Google Cloud virtual TPM 2.0 (gce mode)
//   - Hardware TPM: real TPM 2.0 devices (bare metal, future)
package tpmbackend

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
)

// TCG TPM 2.0 EK Credential Profile § 2.2.1 defines the NV indices for
// manufacturer-provisioned EK certificates. Pancake reads them in this
// order; the ECC index matches the EK pancake creates (`tpm2_createek -G ecc`).
const (
	NVIndexECCEKCert = "0x01c0000a" // ECC NIST P256 EK certificate
	NVIndexRSAEKCert = "0x01c00002" // RSA 2048 EK certificate
)

// Backend abstracts platform-specific TPM details.
type Backend interface {
	// Device returns the TPM device path or TCTI string.
	// Examples: "/dev/tpmrm0", "swtpm:path=/path/to/socket"
	Device() string

	// EKCertSource indicates where EK certificates come from.
	// - "self-signed": swtpm generates self-signed EK cert
	// - "manufacturer": hardware TPM or GCE vTPM with Google-signed EK
	// - "ca-issued": custom CA like dev EK CA
	EKCertSource() string

	// SetupEnv sets TPM2TOOLS_TCTI and other environment variables
	// needed for tpm2-tools commands to talk to this TPM.
	SetupEnv() error

	// Platform returns the platform name (self-hosted, gce, etc.)
	Platform() string

	// ReadEKCert returns the EK certificate the manufacturer provisioned
	// into NV storage, plus any AIA-fetched intermediates back toward
	// the root. Returns (nil, nil, nil) when no NV-stored cert exists
	// (the swtpm case), so callers can fall back to a dev EK CA.
	//
	// Implementations should try the ECC index (0x01c0000a) first since
	// pancake provisions an ECC EK, then RSA (0x01c00002) as a fallback.
	ReadEKCert(ctx context.Context) (leaf *x509.Certificate, chain []*x509.Certificate, err error)
}

// New creates a Backend for the given platform.
// Supported platforms: "self-hosted", "gce", "auto"
// "auto" detects the platform from environment.
func New(platform string) (Backend, error) {
	if platform == "" || platform == "auto" {
		platform = detectPlatform()
	}

	switch platform {
	case "self-hosted":
		return NewSWTPMBackend()
	case "gce":
		return NewGCEVTPMBackend()
	default:
		return nil, fmt.Errorf("unsupported platform: %s", platform)
	}
}

// detectPlatform auto-detects the current platform.
func detectPlatform() string {
	// Check for GCE metadata server
	if isGCE() {
		return "gce"
	}

	// Check for hardware TPM
	if fileExists("/dev/tpmrm0") {
		// Could be bare metal or other cloud, but default to self-hosted for now
		// TODO: add more cloud detection (AWS Nitro, Azure, etc.)
		return "self-hosted"
	}

	// Default to self-hosted (assumes swtpm)
	return "self-hosted"
}

// isGCE checks if running on Google Compute Engine by testing
// the metadata server.
func isGCE() bool {
	// GCE metadata server is at http://metadata.google.internal
	// or 169.254.169.254. Simple check: see if DMI product name is Google.
	if b, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		return string(b) == "Google\n" || string(b) == "Google Compute Engine\n"
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
