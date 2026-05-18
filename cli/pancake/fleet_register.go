// fleet_register.go: post-enroll hook that registers this VM with
// pancake-fleet-server. Called after `pancake enroll` has its TLS cert,
// so we can hand the fleet server a cert serial and expiry that match
// what pancaked is about to serve.

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/sinkap/pancake/common/gen/go/fleetpb"
	"github.com/sinkap/pancake/common/go/platform/gce"
	"github.com/sinkap/pancake/common/go/tpmbackend"
)

// defaultEKPubPath: where pancake enroll writes the TPM2B_PUBLIC blob.
// Kept here as a local constant rather than importing from enroll.go to
// avoid widening that file's exported surface.
const defaultEKPubPath = "/etc/pancake/ek.pub"

// registerWithFleet calls FleetManager.Enroll on the configured fleet server.
// Best-effort: errors are logged but don't fail the overall enroll flow,
// since the fleet server is observational and shouldn't block boot.
func registerWithFleet(fleetServer string, certPEMPath string, backend tpmbackend.Backend) {
	if fleetServer == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "[enroll] registering with fleet server %s\n", fleetServer)

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	platform := "self-hosted"
	if backend != nil {
		platform = backend.Platform()
	}

	// On GCE, prefer the canonical instance identity (name + IP) from the
	// metadata server over the host's view: hostname can be overridden,
	// network interfaces can be renamed, but project/zone/instance-name
	// are authoritative. Fail-soft: fall back to hostname + interface scan
	// if any lookup fails, so non-GCE platforms behave unchanged.
	internalIP := primaryInternalIP()
	metadataJSON := ""
	if platform == "gce" || platform == "gcp" {
		if name, err := gce.GetInstanceName(); err == nil && name != "" {
			hostname = name
		}
		if ip, err := gce.GetInternalIP(); err == nil && ip != "" {
			internalIP = ip
		}
		// Stash project/zone/instance-id as JSON in the fleet record so
		// the UI can deep-link to the GCE console and the orchestrator
		// can identify the VM beyond just its hostname.
		md := map[string]string{}
		if v, err := gce.GetProjectID(); err == nil {
			md["gce_project"] = v
		}
		if v, err := gce.GetZone(); err == nil {
			md["gce_zone"] = v
		}
		if v, err := gce.GetInstanceID(); err == nil {
			md["gce_instance_id"] = v
		}
		if v, err := gce.GetExternalIP(); err == nil && v != "" {
			md["gce_external_ip"] = v
		}
		if len(md) > 0 {
			if b, err := json.Marshal(md); err == nil {
				metadataJSON = string(b)
			}
		}
	}

	certSerial, certExpires := parseCertSerialAndExpiry(certPEMPath)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// gRPC: assume insecure for now. Production should use mTLS, but the
	// fleet server is typically inside the operator's trusted network
	// or behind an authenticated ingress.
	cc, err := grpc.NewClient(fleetServer, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[enroll] fleet register: dial %s: %v\n", fleetServer, err)
		return
	}
	defer cc.Close()
	cli := fleetpb.NewPancakeFleetServiceClient(cc)

	// Read the EK public area; fleet server uses it as the TOFU
	// trust anchor for later attestations. Best-effort: if /etc/pancake/
	// ek.pub is missing or unreadable (shouldn't be after exportEK
	// succeeded), skip the field rather than fail the enroll.
	ekPub, _ := os.ReadFile(defaultEKPubPath)

	req := &fleetpb.EnrollRequest{
		Name:              hostname,
		Platform:          platform,
		InternalIp:        internalIP,
		CertSerial:        certSerial,
		CurrentGeneration: 1,
		MetadataJson:      metadataJSON,
		EkPub:             ekPub,
	}
	if certExpires != nil {
		req.CertExpiresAt = timestamppb.New(*certExpires)
	}

	resp, err := cli.Enroll(ctx, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[enroll] fleet register: %v (continuing; fleet is non-blocking)\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "[enroll] fleet registered as vm id=%d (%s)\n",
		resp.GetId(), resp.GetMessage())
}

// primaryInternalIP returns the first non-loopback IPv4 address found
// on an up interface. Empty string if nothing usable.
func primaryInternalIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			return ip.String()
		}
	}
	return ""
}

// parseCertSerialAndExpiry pulls the serial number (uppercase hex) and
// notAfter out of the first PEM-encoded certificate in path. On error,
// returns empty strings — fleet enrollment proceeds without those hints.
func parseCertSerialAndExpiry(path string) (string, *time.Time) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil
	}
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				serial := strings.ToUpper(cert.SerialNumber.Text(16))
				notAfter := cert.NotAfter
				return serial, &notAfter
			}
		}
		b = rest
	}
	return "", nil
}
