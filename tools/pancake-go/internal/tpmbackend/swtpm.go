package tpmbackend

import (
	"fmt"
	"os"
)

// SWTPMBackend is the software TPM backend for self-hosted development.
type SWTPMBackend struct {
	socketPath string
}

// NewSWTPMBackend creates a backend for swtpm.
// Looks for TPM2TOOLS_TCTI in environment, or defaults to device /dev/tpmrm0
// if it exists (in case running inside a VM that has swtpm exposed as a device).
func NewSWTPMBackend() (*SWTPMBackend, error) {
	// Check if TPM2TOOLS_TCTI is already set (e.g., boot-vm.sh sets it)
	if tcti := os.Getenv("TPM2TOOLS_TCTI"); tcti != "" {
		// Parse socket path from "swtpm:path=/path/to/sock"
		// For now, just store the full TCTI string
		return &SWTPMBackend{socketPath: tcti}, nil
	}

	// Fall back to /dev/tpmrm0 if it exists (swtpm in VM mode)
	if fileExists("/dev/tpmrm0") {
		return &SWTPMBackend{socketPath: "/dev/tpmrm0"}, nil
	}

	// No TPM found - this is an error in self-hosted mode
	return nil, fmt.Errorf("no TPM device found (not /dev/tpmrm0, no TPM2TOOLS_TCTI)")
}

func (b *SWTPMBackend) Device() string {
	return b.socketPath
}

func (b *SWTPMBackend) EKCertSource() string {
	return "self-signed"
}

func (b *SWTPMBackend) SetupEnv() error {
	// If it's a device path, set TPM2TOOLS_TCTI to device
	if b.socketPath == "/dev/tpmrm0" || b.socketPath == "/dev/tpm0" {
		os.Setenv("TPM2TOOLS_TCTI", "device:"+b.socketPath)
	} else if b.socketPath != "" {
		// Already a full TCTI string (e.g., "swtpm:path=...")
		os.Setenv("TPM2TOOLS_TCTI", b.socketPath)
	}
	return nil
}

func (b *SWTPMBackend) Platform() string {
	return "self-hosted"
}
