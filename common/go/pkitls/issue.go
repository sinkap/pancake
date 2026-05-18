// issue.go: minimal x509 CA — self-signed root + leaf-cert issuance.
// All keys are P-256 ECDSA, leaves are PKCS#8-encoded. The on-disk
// layout is intentionally trivial:
//
//	<dir>/ca.crt   (PEM CERTIFICATE,  mode 0644)
//	<dir>/ca.key   (PEM PRIVATE KEY,  mode 0600)
//
// `pancake ca init` calls InitRoot; `pancake ca issue` calls
// LoadRoot then Issue. There's no CSR pipeline — the CLI generates
// the leaf key and signs in one step, which is what makes this
// "static manually-issued certs" rather than a real PKI.
package pkitls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Root is a self-signed CA loaded from disk.
type Root struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// InitRoot mints dir/{ca.crt,ca.key}. Refuses to overwrite an
// existing ca.crt — re-bootstrapping a CA breaks every leaf cert
// already in the field, which should be a deliberate `rm -rf`.
func InitRoot(dir, commonName string) (*Root, error) {
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if _, err := os.Stat(certPath); err == nil {
		return nil, fmt.Errorf("%s already exists; "+
			"`rm -rf %s` first if you really want to mint a new root",
			certPath, dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("genkey: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign: %w", err)
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Root{Cert: cert, Key: key}, nil
}

// LoadRoot reads dir/{ca.crt,ca.key}.
func LoadRoot(dir string) (*Root, error) {
	cert, err := readCert(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	key, err := readKey(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	return &Root{Cert: cert, Key: key}, nil
}

// IssueOpts is the leaf-cert request. Server=true sets the
// ServerAuth EKU, Server=false sets ClientAuth — pancaked needs
// the former, `pancake orchestrate` needs the latter.
type IssueOpts struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	Server     bool
	OutCert    string
	OutKey     string
	TTLDays    int
}

// Issue mints a new leaf cert + key under r.
func (r *Root) Issue(o IssueOpts) error {
	if o.CommonName == "" {
		return fmt.Errorf("issue: CommonName required")
	}
	if o.OutCert == "" || o.OutKey == "" {
		return fmt.Errorf("issue: OutCert and OutKey required")
	}
	if o.TTLDays == 0 {
		o.TTLDays = 365
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randSerial()
	if err != nil {
		return err
	}
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if o.Server {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: o.CommonName},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.AddDate(0, 0, o.TTLDays),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: eku,
		DNSNames:    o.DNSNames,
		IPAddresses: o.IPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, r.Cert,
		&key.PublicKey, r.Key)
	if err != nil {
		return err
	}
	if err := writePEM(o.OutCert, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(o.OutKey, "PRIVATE KEY", keyDER, 0o600)
}

// ParseSANs splits a comma-separated SAN list into DNS / IP buckets.
// Accepts "DNS:vm.example", "IP:10.0.0.5", or bare names (treated
// as IP if they parse as one, else DNS).
func ParseSANs(s string) ([]string, []net.IP) {
	var dns []string
	var ips []net.IP
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		switch {
		case strings.HasPrefix(raw, "DNS:"):
			dns = append(dns, raw[4:])
		case strings.HasPrefix(raw, "IP:"):
			if ip := net.ParseIP(raw[3:]); ip != nil {
				ips = append(ips, ip)
			}
		default:
			if ip := net.ParseIP(raw); ip != nil {
				ips = append(ips, ip)
			} else {
				dns = append(dns, raw)
			}
		}
	}
	return dns, ips
}

func randSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	return os.WriteFile(path, b, mode)
}

func readCert(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA key", path)
	}
	return ec, nil
}
