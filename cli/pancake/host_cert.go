package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"

	"github.com/sinkap/pancake/tools/pancake-go/internal/hoststate"
	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
)

func cmdHostCert(_ *kit.Kit, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: pancake host-cert <init>")
		return 2
	}

	switch args[0] {
	case "init":
		return cmdHostCertInit(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "pancake host-cert: unknown subcommand %q\n", args[0])
		return 2
	}
}

func cmdHostCertInit(args []string) int {
	fs := flag.NewFlagSet("host-cert init", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "",
		"Path to pancake-host-state directory (default: auto-detect)")
	caURL := fs.String("ca-url", "",
		"step-ca URL (default: read from state-dir/ca-url)")
	sans := fs.String("san", "",
		"Additional SANs to include in cert, comma-separated (optional)")
	notAfter := fs.String("not-after", "24h",
		"Certificate validity duration (default: 24 hours)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx := context.Background()

	// Resolve state directory
	var stateDirPath string
	if *stateDir != "" {
		stateDirPath = *stateDir
	} else {
		paths, err := hoststate.Resolve()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[pancake] error resolving host state directory: %v\n", err)
			fmt.Fprintln(os.Stderr, "Hint: run 'docker compose up -d --wait' first to create pancake-host-state/")
			return 1
		}
		stateDirPath = paths.Dir
	}

	fmt.Fprintf(os.Stderr, "[pancake] using state directory: %s\n", stateDirPath)

	// Read JWK provisioner password
	pwFile := filepath.Join(stateDirPath, "host-cert.jwk.pwd")
	pwBytes, err := os.ReadFile(pwFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[pancake] error reading JWK password from %s: %v\n", pwFile, err)
		fmt.Fprintln(os.Stderr, "Hint: ensure 'docker compose up' has run and ca-server initialized")
		return 1
	}
	password := string(bytes.TrimSpace(pwBytes))

	// Read CA URL
	caURLStr := *caURL
	if caURLStr == "" {
		urlBytes, err := os.ReadFile(filepath.Join(stateDirPath, "ca-url"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[pancake] error reading ca-url: %v\n", err)
			return 1
		}
		caURLStr = string(bytes.TrimSpace(urlBytes))
	}
	fmt.Fprintf(os.Stderr, "[pancake] CA URL: %s\n", caURLStr)

	// Read step-ca root cert for TLS trust
	rootCertPath := filepath.Join(stateDirPath, "step-root.crt")
	rootPEM, err := os.ReadFile(rootCertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[pancake] error reading step-ca root cert from %s: %v\n", rootCertPath, err)
		return 1
	}

	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(rootPEM) {
		fmt.Fprintln(os.Stderr, "[pancake] error: failed to parse step-ca root cert")
		return 1
	}

	// Generate EC P-256 key
	fmt.Fprintln(os.Stderr, "[pancake] generating EC P-256 key...")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[pancake] error generating key: %v\n", err)
		return 1
	}

	// Build CSR with SANs
	// CN must be "pancake-host" to match step-ca provisioner template
	commonName := "pancake-host"

	// Parse SANs
	var dnsNames []string
	var ipAddrs []net.IP
	dnsNames = append(dnsNames, commonName)
	// Don't add IP addresses - step-ca provisioner doesn't allow them

	if *sans != "" {
		for _, san := range []string{*sans} {
			if ip := net.ParseIP(san); ip != nil {
				ipAddrs = append(ipAddrs, ip)
			} else {
				dnsNames = append(dnsNames, san)
			}
		}
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[pancake] error creating CSR: %v\n", err)
		return 1
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Read the JWK provisioner key
	jwkKey, err := readJWKProvisionerKey(stateDirPath, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[pancake] error reading JWK provisioner key: %v\n", err)
		return 1
	}

	// Parse validity duration
	notAfterDur, err := time.ParseDuration(*notAfter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[pancake] error parsing --not-after: %v\n", err)
		return 1
	}

	// Sign JWT and request cert from step-ca
	fmt.Fprintln(os.Stderr, "[pancake] requesting certificate from step-ca...")
	certPEM, err := requestCertFromStepCA(ctx, caURLStr, rootPool, jwkKey, csrPEM, notAfterDur)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[pancake] error requesting cert from step-ca: %v\n", err)
		return 1
	}

	// Write client cert
	clientCertPath := filepath.Join(stateDirPath, "client.crt")
	if err := os.WriteFile(clientCertPath, certPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[pancake] error writing client cert: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[pancake] wrote %s\n", clientCertPath)

	// Write client key (mode 0600)
	clientKeyPath := filepath.Join(stateDirPath, "client.key")
	keyPEM, err := pemutil.Serialize(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[pancake] error serializing key: %v\n", err)
		return 1
	}
	if err := os.WriteFile(clientKeyPath, pem.EncodeToMemory(keyPEM), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "[pancake] error writing client key: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[pancake] wrote %s (mode 0600)\n", clientKeyPath)

	// Render pancake.env
	envPath := filepath.Join(stateDirPath, "pancake.env")
	envContent := fmt.Sprintf(`# Source this file to configure pancake CLI for the orchestrator stack:
#   source %s
export PANCAKE_HOST_STATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PANCAKE_CLIENT_CERT="$PANCAKE_HOST_STATE/client.crt"
export PANCAKE_CLIENT_KEY="$PANCAKE_HOST_STATE/client.key"
export PANCAKE_TRUST_ROOT="$PANCAKE_HOST_STATE/step-root.crt"
export PANCAKE_ATTEST_CA_ROOT="$PANCAKE_HOST_STATE/attest-ca-root.crt"
export PANCAKE_BUILDER_ADDR="localhost:7879"
export PANCAKE_CA_URL="%s"
export PANCAKE_ATTEST_CA_URL="https://localhost:8444"
`, envPath, caURLStr)

	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "[pancake] error writing pancake.env: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[pancake] wrote %s\n", envPath)

	fmt.Fprintf(os.Stderr, "\n[pancake] Success! Next steps:\n")
	fmt.Fprintf(os.Stderr, "  source %s\n", envPath)
	fmt.Fprintf(os.Stderr, "  pancake bootstrap pancake-recipe.yaml\n")

	return 0
}

func readJWKProvisionerKey(stateDir, password string) (*jose.JSONWebKey, error) {
	jwkPath := filepath.Join(stateDir, "host-cert.jwk")
	jweBytes, err := os.ReadFile(jwkPath)
	if err != nil {
		return nil, fmt.Errorf("reading JWK from %s: %w\nThe JWK provisioner key must be published by ca-server to the state directory", jwkPath, err)
	}

	// The file contains a JWE (encrypted JWK) as a string
	jweString := string(bytes.TrimSpace(jweBytes))

	// Parse and decrypt the JWE using the password
	key, err := jose.ParseEncrypted(jweString)
	if err != nil {
		return nil, fmt.Errorf("parsing encrypted JWK: %w", err)
	}

	// Decrypt with password
	jwkBytes, err := key.Decrypt([]byte(password))
	if err != nil {
		return nil, fmt.Errorf("decrypting JWK: %w", err)
	}

	// Parse the decrypted JWK
	jwk := &jose.JSONWebKey{}
	if err := json.Unmarshal(jwkBytes, jwk); err != nil {
		return nil, fmt.Errorf("parsing decrypted JWK: %w", err)
	}

	return jwk, nil
}

func requestCertFromStepCA(ctx context.Context, caURL string, rootPool *x509.CertPool, jwk *jose.JSONWebKey, csrPEM []byte, notAfter time.Duration) ([]byte, error) {
	// Build JWT claims
	now := time.Now()
	claims := map[string]interface{}{
		"aud": caURL + "/1.0/sign",
		"iss": "host-cert", // provisioner name
		"sub": "pancake-host",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}

	// Sign JWT
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jwk},
		&jose.SignerOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("creating JWT signer: %w", err)
	}

	claimsBytes, _ := json.Marshal(claims)
	jws, err := signer.Sign(claimsBytes)
	if err != nil {
		return nil, fmt.Errorf("signing JWT: %w", err)
	}

	token, err := jws.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("serializing JWT: %w", err)
	}

	// Build sign request
	signReq := map[string]interface{}{
		"csr":      string(csrPEM),
		"ott":      token,
		"notAfter": now.Add(notAfter).Format(time.RFC3339),
	}

	reqBody, err := json.Marshal(signReq)
	if err != nil {
		return nil, fmt.Errorf("marshaling sign request: %w", err)
	}

	// POST to step-ca
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootPool,
			},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Post(
		caURL+"/1.0/sign",
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return nil, fmt.Errorf("POST /1.0/sign: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("step-ca returned %s: %v", resp.Status, errResp)
	}

	// Parse response
	var signResp struct {
		CRT       string `json:"crt"`
		CA        string `json:"ca"`
		CertChain []string `json:"certChain"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if signResp.CRT == "" {
		return nil, fmt.Errorf("step-ca returned empty certificate")
	}

	return []byte(signResp.CRT), nil
}
