package tpmbackend

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"

	"github.com/sinkap/pancake/tools/pancake-go/internal/platform/gce"
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

// ReadEKCert returns the Google-signed EK certificate for this VM.
//
// On hardware TPMs the EK cert lives at well-known NV indices
// (0x01C0000A ECC, 0x01C00002 RSA). Google's vTPM does NOT populate
// those — instead the EK cert is exposed via the Compute API endpoint
// instances.getShieldedInstanceIdentity, which returns separate
// PEM-encoded certs for the ECC P-256 EK and the RSA 2048 EK. We
// prefer the ECC entry since pancake provisions an ECC EK.
//
// Auth: Application Default Credentials. On a Shielded VM that's the
// instance service account; it needs roles/compute.viewer (or at
// least compute.instances.getShieldedInstanceIdentity) on the project.
//
// After reading the leaf, walks its AuthorityInformationAccess URLs
// to build the chain back toward Google's vTPM root.
func (b *GCEVTPMBackend) ReadEKCert(ctx context.Context) (*x509.Certificate, []*x509.Certificate, error) {
	project, err := gce.GetProjectID()
	if err != nil {
		return nil, nil, fmt.Errorf("read GCE project from metadata: %w", err)
	}
	zone, err := gce.GetZone()
	if err != nil {
		return nil, nil, fmt.Errorf("read GCE zone from metadata: %w", err)
	}
	instance, err := gce.GetInstanceName()
	if err != nil {
		return nil, nil, fmt.Errorf("read GCE instance name from metadata: %w", err)
	}

	client, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("compute client: %w", err)
	}
	defer client.Close()

	resp, err := client.GetShieldedInstanceIdentity(ctx,
		&computepb.GetShieldedInstanceIdentityInstanceRequest{
			Project:  project,
			Zone:     zone,
			Instance: instance,
		})
	if err != nil {
		return nil, nil, fmt.Errorf("GetShieldedInstanceIdentity(%s/%s/%s): %w",
			project, zone, instance, err)
	}

	// Prefer ECC P-256 (pancake's EK algorithm); fall back to RSA.
	var pemStr string
	switch {
	case resp.GetEccP256EncryptionKey() != nil && resp.GetEccP256EncryptionKey().GetEkCert() != "":
		pemStr = resp.GetEccP256EncryptionKey().GetEkCert()
	case resp.GetEncryptionKey() != nil && resp.GetEncryptionKey().GetEkCert() != "":
		pemStr = resp.GetEncryptionKey().GetEkCert()
	default:
		return nil, nil, fmt.Errorf(
			"GetShieldedInstanceIdentity returned no EK cert for %s/%s/%s "+
				"(is the VM really shielded with --shielded-vtpm?)",
			project, zone, instance)
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("Shielded VM EK cert is not a PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse Shielded VM EK cert: %w", err)
	}
	return cert, fetchAIAChain(ctx, cert), nil
}
