// pancake-attest-ca: TPM 2.0 Attestation CA daemon. Issues short-lived
// AK certs containing the EK URN as URI SAN. Designed to run in
// Docker alongside pancake-ca-server; the in-VM `pancake enroll`
// hits this server first to obtain an AK cert chain, then runs
// the ACME-tpm flow against pancake-ca-server (which trusts this
// service via `attestationRoots`).
//
// Defaults:
//
//	--listen   :8444
//	--ca-dir   /home/attestca/ca   (mount as a volume to persist)
//	--cert     <auto> server cert for HTTPS  (self-signed if absent)
//	--key      <auto> server key
//
// HTTP API (unauthenticated; rely on TLS + network ACLs in prod):
//
//	POST /attest   {tpmInfo, ek, params}    → {credential, secret}
//	POST /secret   {secret}                  → {chain}
//	GET  /health                             → {"status":"ok"}
//	GET  /root.crt                           → CA cert (PEM)
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sinkap/pancake/tools/pancake-go/attest-ca"
)

func main() {
	listen := flag.String("listen", ":8444",
		"address:port for HTTPS listener")
	caDir := flag.String("ca-dir", "/home/attestca/ca",
		"directory holding ca.{crt,key} (created if missing)")
	certFile := flag.String("cert", "",
		"server cert for HTTPS (auto-self-signed if empty)")
	keyFile := flag.String("key", "",
		"server key for HTTPS (auto if empty)")
	flag.Parse()

	srv, err := attestca.NewServer(*caDir)
	if err != nil {
		die("attestca.NewServer: %v", err)
	}

	tlsCert, err := loadOrSelfSignServerCert(*certFile, *keyFile, *caDir)
	if err != nil {
		die("server cert: %v", err)
	}
	publishTrustRoot(tlsCert, *caDir)

	httpSrv := &http.Server{
		Addr:    *listen,
		Handler: srv.Routes(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Fprintf(os.Stderr,
		"[pancake-attest-ca] listening on %s (HTTPS, ca-dir=%s)\n",
		*listen, *caDir)
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil {
		die("ListenAndServeTLS: %v", err)
	}
}

// loadOrSelfSignServerCert returns a TLS keypair. If files are
// supplied it loads them; otherwise mints a fresh self-signed cert
// in caDir/{server.crt,server.key}. The CA hierarchy is independent
// of the AK-CA — the server cert just authenticates the listener.
func loadOrSelfSignServerCert(certFile, keyFile, caDir string) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	cp := filepath.Join(caDir, "server.crt")
	kp := filepath.Join(caDir, "server.key")
	if _, err := os.Stat(cp); err == nil {
		return tls.LoadX509KeyPair(cp, kp)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pancake-attest-ca"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "pancake-attest-ca", "pancake-attest-ca"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.2.2")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(cp, kp)
}

// publishTrustRoot writes the TLS server cert (in PEM form) to
// /pancake-trust/attest-ca-root.crt when that directory exists,
// so pancake-build-server (mounting the same docker volume RO)
// can bake it into orch-config layers without HTTP fetch / blob
// upload from the operator. No-op when the volume is not mounted.
//
// Retries on EACCES — compose-internal trust-init chmods the
// volume world-writable, but the mode change is racy at startup;
// give it a few seconds before giving up.
func publishOne(src, dst string) {
	b, err := os.ReadFile(src)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"[pancake-attest-ca] publishOne: read %s: %v\n", src, err)
		return
	}
	for attempt := 1; attempt <= 10; attempt++ {
		if err := os.WriteFile(dst, b, 0o644); err == nil {
			fmt.Fprintf(os.Stderr,
				"[pancake-attest-ca] published %s (attempt %d)\n", dst, attempt)
			return
		}
		time.Sleep(time.Second)
	}
	fmt.Fprintf(os.Stderr,
		"[pancake-attest-ca] publishOne: gave up on %s\n", dst)
}

func publishTrustRoot(_ tls.Certificate, caDir string) {
	const dst = "/pancake-trust/attest-ca-root.crt"
	if _, err := os.Stat("/pancake-trust"); err != nil {
		return
	}
	src := filepath.Join(caDir, "server.crt")
	ak := filepath.Join(caDir, "ca.crt")
	publishOne(ak, "/pancake-trust/attest-ca-ak-root.crt")
	b, err := os.ReadFile(src)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"[pancake-attest-ca] publishTrustRoot: read %s: %v\n",
			src, err)
		return
	}
	for attempt := 1; attempt <= 10; attempt++ {
		if err := os.WriteFile(dst, b, 0o644); err == nil {
			fmt.Fprintf(os.Stderr,
				"[pancake-attest-ca] published %s (attempt %d)\n",
				dst, attempt)
			break
		} else if attempt == 10 {
			fmt.Fprintf(os.Stderr,
				"[pancake-attest-ca] publishTrustRoot: write %s: %v (giving up)\n",
				dst, err)
		} else {
			time.Sleep(time.Second)
		}
	}

	// Also publish to bind-mount for operator host access
	hostState := os.Getenv("PANCAKE_HOST_STATE")
	if hostState == "" {
		hostState = "/var/lib/pancake-host-state"
	}
	if st, err := os.Stat(hostState); err == nil && st.IsDir() {
		publishOne(src, filepath.Join(hostState, "attest-ca-root.crt"))
		// Write attest-ca URL for client defaults
		os.WriteFile(filepath.Join(hostState, "attest-ca-url"),
			[]byte("https://localhost:8444\n"), 0644)
		fmt.Fprintf(os.Stderr,
			"[pancake-attest-ca] published attest-ca-root.crt and attest-ca-url to %s\n",
			hostState)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pancake-attest-ca: "+format+"\n", args...)
	os.Exit(1)
}
