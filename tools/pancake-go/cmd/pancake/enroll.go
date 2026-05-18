// `pancake enroll`: bind this VM's identity to its TPM and obtain a
// pancaked TLS cert from pancake-ca-server via ACME-tpm.
//
// Two independent things happen here:
//
//   (a) EK export — the TPM endorsement key public area is read out
//       (or created if missing), promoted to the TCG-canonical ECC
//       persistent handle (tpmkey.EKHandleECC), and written to
//       /etc/pancake/ek.pub. This is what `pancake attest` uses to
//       identify the TPM remotely.
//
//   (b) ACME-tpm enrollment — mint an Attestation Key (AK) and a new
//       TPM-resident TLS signing key, attest the latter via the AK
//       (qualifying-data = SHA256 of the ACME key authorization), POST
//       a CBOR/WebAuthn-format "tpm" attestation statement to the
//       step-ca ACME challenge URL, finalize the order, and write
//       the resulting cert chain to /etc/pancake/server.crt. The
//       signing key never leaves the TPM; pancaked loads it via
//       go.step.sm/crypto/tpm at startup.
//
// Re-running enroll mints a fresh TPM-resident TLS key (the qualifying
// data binds the attestation to a specific ACME order, so each
// enrollment needs a distinct key) but reuses the AK and ACME account
// key.
//
// The bearer-token sealing path (the previous v1) is gone. Manifest
// signature is still the integrity floor on the wire; mTLS is the
// transport floor.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/sinkap/pancake/tools/pancake-go/internal/issuance"
	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"
	"github.com/sinkap/pancake/tools/pancake-go/internal/tpmbackend"
	"github.com/sinkap/pancake/tools/pancake-go/internal/tpmkey"
)

const (
	defaultEKOut        = "/etc/pancake/ek.pub"
	defaultServerCert   = "/etc/pancake/server.crt"
	defaultTPMStore     = "/var/lib/pancake/tpm"
	defaultTPMKeyMarker = "/etc/pancake/server.tpmkey"
	defaultACMEAcctKey  = "/var/lib/pancake/acme-account.jwk"

	// defaultOrchConfig: when present, pancake enroll reads its
	// orchestrator URLs + CA roots from this JSON file (baked into
	// the signed pancake-orch-config verity layer at bootstrap
	// time). Flags still override individual fields.
	defaultOrchConfig = "/etc/pancake/orch/config.json"
)

// orchConfig mirrors the JSON written by bakeOrchConfig server-side.
// All paths are absolute paths inside the running VM. The single
// TrustRoot anchors every TLS connection enroll makes (ACME +
// attest-ca both go through the same gateway).
type orchConfig struct {
	CAURL        string `json:"ca_url"`
	AttestCAURL  string `json:"attest_ca_url"`
	TrustRoot    string `json:"trust_root"`
	AttestCARoot string `json:"attest_ca_root"`
	ClientCARoot string `json:"client_ca_root"`
	FleetServer  string `json:"fleet_server"`

	// IssuanceCA picks the cert issuer: "step-ca" (default) or "gcp-cas".
	// Set at bake time from the recipe's issuance.ca field.
	IssuanceCA string `json:"issuance_ca,omitempty"`

	// CASPool is the Google CAS pool resource name when IssuanceCA is
	// "gcp-cas" (e.g. "projects/X/locations/Y/caPools/Z").
	CASPool string `json:"cas_pool,omitempty"`

	// EKTrust picks how EK certs are trusted: "dev-ek-ca" (default),
	// "manufacturer", or "google-vtpm". Drives whether enroll falls
	// back to the dev EK CA path.
	EKTrust string `json:"ek_trust,omitempty"`
}

// tpmKeyMarker is the small JSON file pancaked reads at startup to
// know how to load the TPM-resident TLS key.
type tpmKeyMarker struct {
	StorageDir string `json:"storage_dir"`
	AKName     string `json:"ak_name"`
	KeyName    string `json:"key_name"`
}

func fileExistsNonEmpty(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Size() > 0
}

func cmdEnroll(_ *kit.Kit, args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	platform := fs.String("platform", "",
		"platform mode: self-hosted, gce, auto (auto-detect)")
	ekOut := fs.String("ek-out", defaultEKOut,
		"path to write the TPM endorsement key public area (TPM2B_PUBLIC). "+
			"Used by `pancake attest` on the orchestrator to verify this "+
			"VM's TPM identity.")

	caURL := fs.String("ca-url", "",
		"step-ca ACME directory URL, e.g. "+
			"https://orchestrator:8443/acme/tpm/directory  (required unless --skip-acme)")
	caRoot := fs.String("ca-root", "",
		"PEM file containing the step-ca root cert, used to verify the "+
			"ACME server's TLS. Get it from the orchestrator with "+
			"`docker exec pancake-ca-server cat /home/step/certs/root_ca.crt`")
	attestCAURL := fs.String("attest-ca-url", "",
		"pancake-attest-ca base URL, e.g. https://orchestrator:8444 . "+
			"When set, the AK is enrolled with this Attestation CA "+
			"before the ACME flow so step-ca's x5c chain validation "+
			"succeeds. Required for TPMs without manufacturer-signed "+
			"AK certs (i.e., almost all of them).")
	attestCARoot := fs.String("attest-ca-root", "",
		"PEM file containing the attest-ca TLS root (--attest-ca-url's "+
			"server cert chain).")
	deviceID := fs.String("device-id", "",
		"the leaf cert's CN. Defaults to the system hostname.")
	sanList := fs.String("san", "",
		"comma-separated list of SANs for the TLS cert. Each entry is "+
			"either DNS:name or IP:addr (or a bare value, auto-classified). "+
			"At least one is required — orchestrator's mTLS hostname check "+
			"reads SAN, not CN.")

	serverCert := fs.String("server-cert", defaultServerCert,
		"where to write the issued TLS cert chain (PEM)")
	tpmStore := fs.String("tpm-store", defaultTPMStore,
		"directory for go.step.sm/crypto/tpm key persistence (AK + key handles)")
	keyMarker := fs.String("tpm-key-marker", defaultTPMKeyMarker,
		"small JSON file telling pancaked which TPM key to load")
	acctKeyFile := fs.String("acme-account-key", defaultACMEAcctKey,
		"path for the ACME account key (JWK). Created on first enroll, "+
			"reused thereafter.")
	skipACME := fs.Bool("skip-acme", false,
		"only do EK export, skip the ACME flow")
	orchConfigPath := fs.String("orch-config", defaultOrchConfig,
		"JSON file (baked into pancake-orch-config layer at bootstrap "+
			"time) supplying ca-url / attest-ca-url / ca-root / "+
			"attest-ca-root. Individual --flag values override the JSON.")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Set up TPM backend based on platform
	platformMode := *platform
	if platformMode == "" {
		platformMode = os.Getenv("PANCAKE_PLATFORM")
	}
	if platformMode == "" {
		platformMode = "auto" // Auto-detect
	}
	backend, err := tpmbackend.New(platformMode)
	if err != nil {
		return die(fmt.Errorf("setup TPM backend: %w", err))
	}
	if err := backend.SetupEnv(); err != nil {
		return die(fmt.Errorf("configure TPM environment: %w", err))
	}
	fmt.Fprintf(os.Stderr,
		"[enroll] platform: %s, TPM device: %s, EK source: %s\n",
		backend.Platform(), backend.Device(), backend.EKCertSource())

	// Layer-baked defaults. When the JSON exists, use it as the
	// fallback for the four orch fields; explicit flags still win.
	// CAURL + AttestCAURL are pre-expanded paths against the single
	// gateway URL; both anchor at TrustRoot.
	if cfg, err := loadOrchConfig(*orchConfigPath); err == nil {
		if *caURL == "" {
			*caURL = cfg.CAURL
		}
		if *caRoot == "" {
			*caRoot = cfg.TrustRoot
		}
		if *attestCAURL == "" {
			*attestCAURL = cfg.AttestCAURL
		}
		if *attestCARoot == "" {
			*attestCARoot = cfg.AttestCARoot
		}
		fmt.Fprintf(os.Stderr,
			"[enroll] orch config loaded from %s (ca=%s attest=%s)\n",
			*orchConfigPath, cfg.CAURL, cfg.AttestCAURL)
	}

	// (a) EK export — always runs.
	if err := exportEK(*ekOut); err != nil {
		return die(err)
	}

	if *skipACME {
		fmt.Fprintln(os.Stderr,
			"[enroll] --skip-acme set; done after EK export")
		return 0
	}

	// (b) ACME-tpm enrollment.
	if *caURL == "" {
		return die(fmt.Errorf("--ca-url required (unless --skip-acme); " +
			"either pass it explicitly or bake it into " + defaultOrchConfig))
	}
	if *sanList == "" {
		return die(fmt.Errorf("--san required (at least one DNS:/IP: entry)"))
	}
	cn := *deviceID
	if cn == "" {
		hn, err := os.Hostname()
		if err != nil {
			return die(fmt.Errorf("hostname: %w", err))
		}
		cn = hn
	}
	dns, ips := parseSANList(*sanList)
	if len(dns)+len(ips) == 0 {
		return die(fmt.Errorf("--san parsed to zero entries"))
	}

	cfgForIssuer, _ := loadOrchConfig(*orchConfigPath)
	issuer, err := pickIssuer(cfgForIssuer, *caURL, *caRoot, *attestCAURL, *attestCARoot, *acctKeyFile)
	if err != nil {
		return die(err)
	}
	fmt.Fprintf(os.Stderr, "[enroll] issuer: %s\n", issuer.Name())

	ipStrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}
	if err := issuer.Issue(context.Background(), issuance.Input{
		CommonName:     cn,
		DNSNames:       dns,
		IPs:            ipStrs,
		TPMStoreDir:    *tpmStore,
		ServerCertPath: *serverCert,
		KeyMarkerPath:  *keyMarker,
	}); err != nil {
		return die(err)
	}

	fmt.Fprintf(os.Stderr,
		"[enroll] enrollment complete.\n"+
			"[enroll]   cert:        %s\n"+
			"[enroll]   tpm marker:  %s (pancaked loads its key via this)\n"+
			"[enroll]   ek pubkey:   %s\n"+
			"[enroll] restart pancaked: systemctl restart pancaked\n",
		*serverCert, *keyMarker, *ekOut)

	// Best-effort: register with the fleet server if one was configured.
	// Read fleet-server from the same orch-config JSON (already loaded
	// above into cfg if it existed).
	if cfg, err := loadOrchConfig(*orchConfigPath); err == nil && cfg.FleetServer != "" {
		registerWithFleet(cfg.FleetServer, *serverCert, backend)
	}

	return 0
}

// exportEK reads (or creates and persists at the canonical handle)
// the TPM endorsement key and writes the public area to outPath.
// Shells out to tpm2_* — same convention `pancake attest` reads.
func exportEK(outPath string) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "pancake-ek-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	ekCtx := filepath.Join(tmp, "ek.ctx")

	if err := runner.RunOK(runner.Cmd{
		Argv: []string{"tpm2_readpublic", "-c", tpmkey.EKHandleECC, "-o", outPath},
		Sudo: true,
	}); err == nil && fileExistsNonEmpty(outPath) {
		fmt.Fprintf(os.Stderr,
			"[enroll] EK already at persistent handle %s; pubkey re-exported to %s\n",
			tpmkey.EKHandleECC, outPath)
		return nil
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"tpm2_createek", "-G", "ecc", "-u", outPath, "-c", ekCtx},
		Sudo: true,
	}); err != nil {
		return fmt.Errorf("tpm2_createek: %w", err)
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"tpm2_evictcontrol", "-C", "o", "-c", ekCtx, tpmkey.EKHandleECC},
		Sudo: true,
	}); err != nil {
		return fmt.Errorf("tpm2_evictcontrol → %s: %w", tpmkey.EKHandleECC, err)
	}
	fmt.Fprintf(os.Stderr,
		"[enroll] EK created, persisted at handle %s, pubkey written to %s\n",
		tpmkey.EKHandleECC, outPath)
	return nil
}

// loadOrchConfig reads + parses the JSON written by bootstrap's
// packOrchConfigLayer. Returns ErrNotExist when the layer wasn't
// installed (i.e. recipe omitted [orchestrator]) — caller treats
// that as "fall back to flags" without erroring.
func loadOrchConfig(path string) (*orchConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c orchConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// parseSANList splits "DNS:foo,IP:1.2.3.4,bare" into DNS + IP buckets.
func parseSANList(s string) ([]string, []net.IP) {
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
