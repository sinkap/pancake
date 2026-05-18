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
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sinkap/pancake/tools/pancake-go/fleet-server/internal/fleetdb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/orchpb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/pkitls"
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
	cli := orchpb.NewPancakeClient(cc)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	resp, err := cli.Attest(dialCtx, &orchpb.AttestRequest{Nonce: nonce})
	if err != nil {
		p.recordFailure(ctx, vm.ID, fmt.Sprintf("attest rpc: %v", err))
		return fmt.Errorf("attest rpc: %w", err)
	}

	// Basic verification: non-empty quote/sig/ak_pub + at least one PCR.
	status := "valid"
	verifErr := ""
	if len(resp.Quote) == 0 || len(resp.Signature) == 0 || len(resp.AkPub) == 0 {
		status = "invalid"
		verifErr = "missing quote/signature/ak_pub"
	} else if len(resp.Pcr) == 0 {
		status = "invalid"
		verifErr = "no PCRs returned"
	}

	pcrJSON, _ := json.Marshal(pcrsToMap(resp.Pcr))

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

// pcrsToMap turns the PCR array from Attest into {"<index>": "<hex digest>"}.
func pcrsToMap(pcrs []*orchpb.AttestResponse_PcrDigest) map[string]string {
	out := make(map[string]string, len(pcrs))
	for _, p := range pcrs {
		out[strconv.Itoa(int(p.Index))] = hex.EncodeToString(p.Sha256)
	}
	return out
}
