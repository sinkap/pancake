// Package gce provides GCE-specific platform integration.
package gce

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	metadataHost = "metadata.google.internal"
	metadataBase = "http://" + metadataHost + "/computeMetadata/v1"
)

// metadataClient is a simple HTTP client for GCE metadata service.
var metadataClient = &http.Client{
	Timeout: 2 * time.Second,
}

// GetInstanceName returns the GCE instance name.
func GetInstanceName() (string, error) {
	return metadataGet("instance/name")
}

// GetInstanceID returns the GCE instance numeric ID.
func GetInstanceID() (string, error) {
	return metadataGet("instance/id")
}

// GetZone returns the GCE zone (e.g., "us-central1-a").
func GetZone() (string, error) {
	zone, err := metadataGet("instance/zone")
	if err != nil {
		return "", err
	}
	// Returned as "projects/12345/zones/us-central1-a", extract zone
	parts := strings.Split(zone, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1], nil
	}
	return zone, nil
}

// GetProjectID returns the GCE project ID.
func GetProjectID() (string, error) {
	return metadataGet("project/project-id")
}

// GetInternalIP returns the primary internal IP address.
func GetInternalIP() (string, error) {
	return metadataGet("instance/network-interfaces/0/ip")
}

// GetExternalIP returns the primary external IP address (if exists).
func GetExternalIP() (string, error) {
	return metadataGet("instance/network-interfaces/0/access-configs/0/external-ip")
}

// GetAttribute returns a custom instance metadata attribute.
func GetAttribute(name string) (string, error) {
	return metadataGet("instance/attributes/" + name)
}

// metadataGet fetches a metadata value from the GCE metadata service.
func metadataGet(path string) (string, error) {
	url := metadataBase + "/" + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := metadataClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("metadata server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}

// Note: a top-level "are we on GCE?" predicate intentionally lives in
// the tpmbackend package (DMI product name based, ties detection to
// the same probe that picks the TPM backend). This file is just the
// metadata-server client.
