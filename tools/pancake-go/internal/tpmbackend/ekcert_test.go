package tpmbackend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestContains(t *testing.T) {
	cases := []struct {
		s, sub string
		want   bool
	}{
		{"hello world", "world", true},
		{"hello world", "xyz", false},
		{"", "x", false},
		{"abc", "", true},
		{"0x18b", "0x18b", true},
	}
	for _, c := range cases {
		if got := contains(c.s, c.sub); got != c.want {
			t.Errorf("contains(%q, %q) = %v, want %v", c.s, c.sub, got, c.want)
		}
	}
}

func TestIsHandleNotPresent(t *testing.T) {
	cases := []struct {
		out  string
		err  error
		want bool
	}{
		{"WARN: NV handle does not exist", errors.New("exit 1"), true},
		{"Esys_NV_Read(0x18B)", errors.New("exit 1"), true},
		{"some other error", errors.New("exit 1"), false},
		{"any output", nil, false}, // no err means success
	}
	for _, c := range cases {
		got := isHandleNotPresent([]byte(c.out), c.err)
		if got != c.want {
			t.Errorf("isHandleNotPresent(%q, %v) = %v, want %v",
				c.out, c.err, got, c.want)
		}
	}
}

func TestFetchAIAChain_NilCert(t *testing.T) {
	if chain := fetchAIAChain(context.Background(), nil); chain != nil {
		t.Errorf("fetchAIAChain(nil) = %v, want nil", chain)
	}
}

func TestFetchAIAChain_NoAIA(t *testing.T) {
	// A cert without AuthorityInformationAccess URLs yields an empty chain.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	if chain := fetchAIAChain(context.Background(), cert); len(chain) != 0 {
		t.Errorf("fetchAIAChain(no-AIA) = %v (len %d), want empty", chain, len(chain))
	}
}

func TestSWTPMBackend_ReadEKCert_NoCert(t *testing.T) {
	// swtpm has no manufacturer-provisioned cert; ReadEKCert must
	// return (nil, nil, nil) so callers fall back to dev EK CA.
	b := &SWTPMBackend{socketPath: "/dev/tpmrm0"}
	leaf, chain, err := b.ReadEKCert(context.Background())
	if err != nil || leaf != nil || chain != nil {
		t.Errorf("SWTPMBackend.ReadEKCert = (%v, %v, %v); want all-nil", leaf, chain, err)
	}
}

func TestBackendInterface_Compliance(t *testing.T) {
	// Compile-time check: both backends satisfy the Backend interface,
	// including the new ReadEKCert method.
	var _ Backend = (*SWTPMBackend)(nil)
	var _ Backend = (*GCEVTPMBackend)(nil)
}
