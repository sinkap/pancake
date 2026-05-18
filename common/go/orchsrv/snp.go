// snp.go: AMD SEV-SNP attestation report fetcher.
//
// /dev/sev-guest is the kernel interface (since Linux 5.19) that
// lets a confidential guest request a fresh attestation report
// signed by the platform's VCEK (Versioned Chip Endorsement Key).
// Each report carries a 64-byte REPORT_DATA field — we put the
// caller's nonce there so the verifier can prove freshness.
//
// We use github.com/google/go-sev-guest/client to talk to the
// device + (when supported) ask the host for the cert chain.
//
// Returns Unavailable when /dev/sev-guest is missing — pancake-os
// runs everywhere, attestation is best-effort.

package orchsrv

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/sinkap/pancake/common/gen/go/pancakepb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/go-sev-guest/client"
)

// AttestSEVSNP shells the request through to /dev/sev-guest, returns
// the raw 1184-byte SNP report. Verifier-side handles cert-chain
// validation + signature verification; server stays small.
func (s *server) AttestSEVSNP(
	ctx context.Context, req *pancakepb.AttestSEVSNPRequest,
) (*pancakepb.AttestSEVSNPResponse, error) {
	if _, err := os.Stat("/dev/sev-guest"); err != nil {
		return nil, status.Error(codes.Unavailable,
			"/dev/sev-guest absent — VM is not SEV-SNP")
	}
	if len(req.Nonce) > 64 {
		return nil, status.Error(codes.InvalidArgument,
			"nonce must be <= 64 bytes (REPORT_DATA field size)")
	}

	qp, err := client.GetQuoteProvider()
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"sev-guest QuoteProvider: %v", err)
	}

	var data [64]byte
	copy(data[:], req.Nonce)
	rawQuote, err := qp.GetRawQuote(data)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "GetRawQuote: %v", err)
	}

	// `GetRawQuote` returns the report optionally followed by an
	// extended-report cert chain. The full quote is what we ship —
	// verifier slices off the report (1184 bytes) and uses any
	// trailing bytes as the (host-provided) VCEK chain when
	// fetching from KDS isn't possible.
	const reportSize = 0x4A0 // 1184 bytes per SEV-SNP ABI § 8.7
	resp := &pancakepb.AttestSEVSNPResponse{Report: rawQuote}
	if len(rawQuote) > reportSize {
		resp.Report = rawQuote[:reportSize]
		resp.VcekCert = rawQuote[reportSize:]
	}

	fmt.Fprintf(os.Stderr,
		"[pancaked] SNP attestation: %d-byte report (%d-byte cert chain)\n",
		len(resp.Report), len(resp.VcekCert))
	return resp, nil
}

// errSNPUnavailable is the canonical "no SNP device" sentinel for
// callers that want to distinguish transport vs. capability failures.
var errSNPUnavailable = errors.New("sev-guest not available on this host")
