// Package attestpoll runs a background loop that periodically polls
// every enrolled VM for a TPM attestation report, stores the result in
// the database, and (for "custom" mode) does basic verification.
//
// Full PCR policy verification (compare PCRs to expected_pcrs per
// generation) is a follow-up; this initial implementation just records
// raw quotes + flips vms.attestation_status to valid/failed based on
// transport success and non-empty quote bytes.
package attestpoll

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sinkap/pancake/backends/fleet-server/internal/fleetdb"
	"github.com/sinkap/pancake/common/gen/go/pancakepb"
	"github.com/sinkap/pancake/common/go/pkitls"
)

// Config controls poller behavior.
type Config struct {
	// Interval between full-fleet sweeps. 0 = default (60s).
	Interval time.Duration

	// PerVMTimeout is the deadline for one Attest RPC. 0 = default (15s).
	PerVMTimeout time.Duration

	// MaxConcurrent caps in-flight Attest calls. 0 = default (10).
	MaxConcurrent int

	// VMPort is the gRPC port pancaked listens on. 0 = default (7878).
	VMPort int

	// CAFile / CertFile / KeyFile are the mTLS materials used to talk
	// to pancaked. When all empty, falls back to insecure (dev only).
	CAFile, CertFile, KeyFile string

	// ServerNameOverride: if set, all VMs share this SNI/cert hostname.
	// Empty = derive from VM.Name (the hostname-shaped value the cert
	// SAN is signed for).
	ServerNameOverride string

	// TOFU: if true, the first valid attestation for a generation that
	// has no registered expected_pcrs auto-registers them. Subsequent
	// attestations for that generation must match. Off by default;
	// production should pre-register policies via the API.
	TOFU bool

	// EKTrustRoots is the trust pool the poller validates an
	// AttestResponse.EkCert chain against. Empty = skip chain
	// verification (still records ek_cert_serial when one is
	// present so the UI can display it).
	EKTrustRoots *x509.CertPool
}

func (c *Config) applyDefaults() {
	if c.Interval == 0 {
		c.Interval = 60 * time.Second
	}
	if c.PerVMTimeout == 0 {
		c.PerVMTimeout = 15 * time.Second
	}
	if c.MaxConcurrent == 0 {
		c.MaxConcurrent = 10
	}
	if c.VMPort == 0 {
		c.VMPort = 7878
	}
}

// Poller polls VMs for TPM attestations.
type Poller struct {
	DB     *fleetdb.DB
	Config Config

	dialOpts []grpc.DialOption // computed once at New
}

// New constructs a Poller, returning an error if mTLS materials can't load.
func New(db *fleetdb.DB, cfg Config) (*Poller, error) {
	cfg.applyDefaults()

	p := &Poller{DB: db, Config: cfg}

	switch {
	case cfg.CAFile != "" && cfg.CertFile != "" && cfg.KeyFile != "":
		// mTLS path. ServerName is set per-dial (depends on the VM).
		tlsCfg, err := pkitls.LoadClientConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile, "")
		if err != nil {
			return nil, fmt.Errorf("load mTLS materials: %w", err)
		}
		p.dialOpts = []grpc.DialOption{
			grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		}
	case cfg.CAFile == "" && cfg.CertFile == "" && cfg.KeyFile == "":
		// Insecure (dev only)
		log.Println("[attestpoll] WARNING: no mTLS materials — using insecure transport")
		p.dialOpts = []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}
	default:
		return nil, errors.New(
			"mTLS materials must be supplied together (CAFile, CertFile, KeyFile)")
	}
	return p, nil
}

// Run drives the poller until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	log.Printf("[attestpoll] starting (interval=%s, concurrency=%d)",
		p.Config.Interval, p.Config.MaxConcurrent)
	t := time.NewTicker(p.Config.Interval)
	defer t.Stop()

	// First sweep immediately so the operator gets feedback fast.
	p.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			log.Println("[attestpoll] stopping")
			return
		case <-t.C:
			p.sweep(ctx)
		}
	}
}

// sweep attests every VM once, in parallel up to MaxConcurrent.
func (p *Poller) sweep(ctx context.Context) {
	vms, _, err := p.DB.ListVMs(ctx, "", "", 1000, 0)
	if err != nil {
		log.Printf("[attestpoll] list vms: %v", err)
		return
	}
	if len(vms) == 0 {
		return
	}
	log.Printf("[attestpoll] sweeping %d VMs", len(vms))

	sem := make(chan struct{}, p.Config.MaxConcurrent)
	var wg sync.WaitGroup
	for _, vm := range vms {
		vm := vm
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := p.AttestOne(ctx, vm); err != nil {
				log.Printf("[attestpoll] vm=%s: %v", vm.Name, err)
			}
		}()
	}
	wg.Wait()
}

// AttestOne polls a single VM and writes the result to the DB. Exported
// so the REST API can trigger on-demand attestations.
func (p *Poller) AttestOne(ctx context.Context, vm fleetdb.VM) error {
	if vm.InternalIP == "" {
		return errors.New("vm has no internal_ip")
	}

	addr := net.JoinHostPort(vm.InternalIP, strconv.Itoa(p.Config.VMPort))
	dialCtx, cancel := context.WithTimeout(ctx, p.Config.PerVMTimeout)
	defer cancel()

	cc, err := grpc.NewClient(addr, p.dialOpts...)
	if err != nil {
		p.recordFailure(ctx, vm.ID, fmt.Sprintf("dial: %v", err))
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer cc.Close()
	cli := pancakepb.NewPancakeAgentServiceClient(cc)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	resp, err := cli.Attest(dialCtx, &pancakepb.AttestRequest{Nonce: nonce})
	if err != nil {
		p.recordFailure(ctx, vm.ID, fmt.Sprintf("attest rpc: %v", err))
		return fmt.Errorf("attest rpc: %w", err)
	}

	// Basic transport-level checks
	status := "valid"
	verifErr := ""
	if len(resp.Quote) == 0 || len(resp.Signature) == 0 || len(resp.AkPub) == 0 {
		status = "invalid"
		verifErr = "missing quote/signature/ak_pub"
	} else if len(resp.Pcr) == 0 {
		status = "invalid"
		verifErr = "no PCRs returned"
	}

	pcrMap := pcrsToMap(resp.Pcr)
	pcrJSON, _ := json.Marshal(pcrMap)

	// PCR policy check (only run if transport checks passed)
	if status == "valid" && vm.CurrentGeneration > 0 {
		if policyStatus, policyErr := p.checkPolicy(ctx, vm.CurrentGeneration, pcrMap); policyStatus != "" {
			status = policyStatus
			verifErr = policyErr
		}
	}

	// EK cert chain verification — records the leaf serial regardless,
	// and the verify result when an EKTrustRoots pool is configured.
	// Used by self-hosted / hardware TPM platforms where Google-style
	// API-anchored EK trust doesn't apply.
	ekSerial, ekVerified := p.verifyEKChain(resp.EkCert, resp.EkCertChain)
	if status == "valid" && ekVerified != nil && !*ekVerified {
		status = "invalid"
		verifErr = "EK cert chain failed to validate against trust roots"
	}

	// TOFU EK pubkey check. GCE (and any other platform where the EK
	// arrives without a manufacturer cert chain) anchors trust on the
	// ekPub recorded at first enrollment. A mismatch here means either
	// the VM's vTPM changed identity (legitimate but suspicious — disk
	// re-imaged, hypervisor moved?) or the VM is being impersonated.
	// vm.EKPub is empty when no first-enroll ekPub was ever recorded;
	// in that case we skip the check (no anchor → nothing to verify).
	if status == "valid" && len(vm.EKPub) > 0 {
		if !bytes.Equal(vm.EKPub, resp.EkPub) {
			status = "invalid"
			verifErr = fmt.Sprintf(
				"ekPub mismatch vs TOFU baseline: recorded %d bytes, got %d bytes — "+
					"vTPM identity changed, refusing attestation",
				len(vm.EKPub), len(resp.EkPub))
		}
	}

	_, err = p.DB.InsertAttestation(ctx, fleetdb.Attestation{
		VMID:               vm.ID,
		Nonce:              nonce,
		PCRs:               string(pcrJSON),
		Quote:              resp.Quote,
		Signature:          resp.Signature,
		AKPub:              resp.AkPub,
		EKPub:              resp.EkPub,
		VerificationStatus: status,
		VerificationError:  verifErr,
		EventLog:           resp.EventLog,
		AttestationMode:    "custom",
		EKCertSerial:       ekSerial,
		EKChainVerified:    ekVerified,
	})
	if err != nil {
		return fmt.Errorf("insert attestation: %w", err)
	}

	// Add a transparency-log event for observability.
	eventType := "attestation_success"
	if status != "valid" {
		eventType = "attestation_failure"
	}
	details, _ := json.Marshal(map[string]any{
		"status":  status,
		"vm_name": vm.Name,
		"err":     verifErr,
	})
	if _, err := p.DB.InsertEvent(ctx, eventType, &vm.ID, string(details)); err != nil {
		log.Printf("[attestpoll] event log write failed: %v", err)
	}
	return nil
}

// recordFailure stores a synthetic "transport failed" attestation row
// so the dashboard sees the failure without needing a wire response.
func (p *Poller) recordFailure(ctx context.Context, vmID int32, msg string) {
	_, err := p.DB.InsertAttestation(ctx, fleetdb.Attestation{
		VMID:               vmID,
		Nonce:              []byte{},
		PCRs:               "{}",
		Quote:              []byte{},
		Signature:          []byte{},
		VerificationStatus: "error",
		VerificationError:  msg,
		AttestationMode:    "custom",
	})
	if err != nil {
		log.Printf("[attestpoll] record failure: %v", err)
	}
	details, _ := json.Marshal(map[string]any{"err": msg})
	if _, err := p.DB.InsertEvent(ctx, "attestation_failure", &vmID, string(details)); err != nil {
		log.Printf("[attestpoll] event log write failed: %v", err)
	}
}

// verifyEKChain parses the EK cert + intermediate chain from the
// Attest response and (when EKTrustRoots is configured) walks the
// chain back to a trust root. Returns (serial, verified) where:
//   - serial:   hex-upper of the leaf serial, "" if no cert provided
//   - verified: nil if no chain to check; pointer to true/false otherwise.
func (p *Poller) verifyEKChain(ekCertDER []byte, chainDER [][]byte) (string, *bool) {
	if len(ekCertDER) == 0 {
		return "", nil
	}
	leaf, err := x509.ParseCertificate(ekCertDER)
	if err != nil {
		f := false
		return "", &f
	}
	serial := strings.ToUpper(leaf.SerialNumber.Text(16))

	if p.Config.EKTrustRoots == nil {
		// No trust pool configured: record the serial but don't claim
		// verified. The dashboard shows "no trust root configured" so
		// the operator can spot the gap.
		return serial, nil
	}

	intermediates := x509.NewCertPool()
	for _, der := range chainDER {
		if c, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(c)
		}
	}
	opts := x509.VerifyOptions{
		Roots:         p.Config.EKTrustRoots,
		Intermediates: intermediates,
		// EK certs aren't web certs — they use TPM-specific EKUs.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, verr := leaf.Verify(opts)
	verified := verr == nil
	if !verified {
		log.Printf("[attestpoll] EK chain verify failed serial=%s: %v", serial, verr)
	}
	return serial, &verified
}

// pcrsToMap turns the PCR array from Attest into {"<index>": "<hex digest>"}.
func pcrsToMap(pcrs []*pancakepb.AttestResponse_PcrDigest) map[string]string {
	out := make(map[string]string, len(pcrs))
	for _, p := range pcrs {
		out[strconv.Itoa(int(p.Index))] = hex.EncodeToString(p.Sha256)
	}
	return out
}

// checkPolicy compares observed PCRs against the registered expected
// PCRs for `gen`. Returns ("", "") when the policy passes (or when
// TOFU was enabled and just auto-registered the baseline). Returns
// ("invalid", details) on mismatch and ("", "") when no policy is
// registered and TOFU is off — the attestation stays "valid" since
// the operator hasn't asked us to enforce anything yet.
func (p *Poller) checkPolicy(ctx context.Context, gen int32, observed map[string]string) (string, string) {
	expected, err := p.DB.GetExpectedPCRs(ctx, gen)
	if errors.Is(err, pgx.ErrNoRows) {
		if p.Config.TOFU {
			if err := p.DB.UpsertExpectedPCRs(ctx, gen, observed,
				"auto-registered by attestpoll TOFU"); err != nil {
				log.Printf("[attestpoll] TOFU register gen=%d: %v", gen, err)
				return "invalid", "TOFU register failed: " + err.Error()
			}
			log.Printf("[attestpoll] TOFU registered baseline for generation %d (%d PCRs)",
				gen, len(observed))
			return "", ""
		}
		return "", "" // no policy registered, treat as valid
	}
	if err != nil {
		return "invalid", "policy lookup failed: " + err.Error()
	}

	// Compare every PCR that the policy mentions
	var mismatches []string
	for idx, want := range expected.PCRs {
		got, ok := observed[idx]
		if !ok {
			mismatches = append(mismatches, fmt.Sprintf("PCR[%s] missing in attestation", idx))
			continue
		}
		if !strings.EqualFold(got, want) {
			mismatches = append(mismatches, fmt.Sprintf("PCR[%s] got=%s want=%s", idx, got, want))
		}
	}
	if len(mismatches) > 0 {
		sort.Strings(mismatches)
		return "invalid", "policy mismatch for gen " + strconv.Itoa(int(gen)) + ": " + strings.Join(mismatches, "; ")
	}
	return "", ""
}
