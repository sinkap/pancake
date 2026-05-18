package sign

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RemoteSigner talks to a pancake-sign service over HTTP. It's the
// production shape: the build server holds no signing key; every
// signature crosses a process boundary so the key only ever lives
// in pancake-sign's process memory + its mounted volume.
//
// BaseURL example: "http://pancake-sign:7880" (compose-internal
// hostname). For production deployments add a Transport with mTLS
// and tighter timeouts; the v1 in-compose use is plain HTTP on a
// private docker network.
type RemoteSigner struct {
	BaseURL string
	Client  *http.Client // optional; defaults to a 60s timeout client
}

func (s *RemoteSigner) httpClient() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (s *RemoteSigner) post(
	ctx context.Context, path string, body []byte,
) ([]byte, error) {
	url := strings.TrimRight(s.BaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("pancake-sign POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pancake-sign POST %s: %s: %s",
			path, resp.Status, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

func (s *RemoteSigner) get(ctx context.Context, path string) ([]byte, error) {
	url := strings.TrimRight(s.BaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("pancake-sign GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pancake-sign GET %s: %s: %s",
			path, resp.Status, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

func (s *RemoteSigner) SignUKI(ctx context.Context, unsigned []byte) ([]byte, error) {
	return s.post(ctx, "/sign/uki", unsigned)
}

func (s *RemoteSigner) SignManifest(ctx context.Context, manifest []byte) ([]byte, error) {
	return s.post(ctx, "/sign/manifest", manifest)
}

func (s *RemoteSigner) Cert(ctx context.Context) ([]byte, error) {
	return s.get(ctx, "/signing-cert")
}
