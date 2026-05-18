package tpmbackend

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
)

// GCEVTPMBackend is the Google Cloud virtual TPM 2.0 backend.
type GCEVTPMBackend struct {
	device string
}

// NewGCEVTPMBackend creates a backend for GCE vTPM.
// GCE exposes vTPM at /dev/tpmrm0 in Shielded VMs.
func NewGCEVTPMBackend() (*GCEVTPMBackend, error) {
	// GCE vTPM is always at /dev/tpmrm0
	device := "/dev/tpmrm0"
	if !fileExists(device) {
		return nil, fmt.Errorf("GCE vTPM not found at %s (is this a Shielded VM?)", device)
	}

	return &GCEVTPMBackend{device: device}, nil
}

func (b *GCEVTPMBackend) Device() string {
	return b.device
}

func (b *GCEVTPMBackend) EKCertSource() string {
	// GCE vTPM comes with Google-signed EK certificates
	return "manufacturer"
}

func (b *GCEVTPMBackend) SetupEnv() error {
	// GCE vTPM is a standard character device
	os.Setenv("TPM2TOOLS_TCTI", "device:"+b.device)
	return nil
}

func (b *GCEVTPMBackend) Platform() string {
	return "gce"
}

// ReadEKCert reads the Google-signed EK cert from NV. Tries the ECC
// index (0x01c0000a) first since pancake provisions an ECC EK, then
// RSA (0x01c00002) as a fallback. On a Shielded VM at least one is
// present; if neither is present we surface that as an error so the
// caller can fail loud rather than silently fall back to dev EK CA.
//
// After reading the leaf, walks its AuthorityInformationAccess URLs
// to build the chain back toward Google's vTPM root.
func (b *GCEVTPMBackend) ReadEKCert(ctx context.Context) (*x509.Certificate, []*x509.Certificate, error) {
	for _, idx := range []string{NVIndexECCEKCert, NVIndexRSAEKCert} {
		cert, err := readNVCertFromTPM(ctx, idx)
		if err != nil {
			return nil, nil, fmt.Errorf("read EK cert at NV %s: %w", idx, err)
		}
		if cert != nil {
			return cert, fetchAIAChain(ctx, cert), nil
		}
	}
	return nil, nil, fmt.Errorf("no manufacturer EK cert at NV %s or %s "+
		"(is this really a Shielded VM with Google vTPM?)",
		NVIndexECCEKCert, NVIndexRSAEKCert)
}
