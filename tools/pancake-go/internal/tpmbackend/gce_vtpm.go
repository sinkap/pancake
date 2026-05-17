package tpmbackend

import (
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
