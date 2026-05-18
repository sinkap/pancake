// attest_snp.go: verifier-side SEV-SNP path for `pancake attest`.
//
// Pulls the AMD attestation report via the AttestSEVSNP RPC and
// runs three independent checks:
//
//   1. signature: report is signed by the chip-specific VCEK,
//      itself certified by the AMD ARK. We fetch the VCEK from
//      AMD KDS (https://kdsintf.amd.com) using CHIP_ID + TCB
//      from the report, validate the chain to the AMD root, and
//      verify the report signature.
//   2. nonce: REPORT_DATA[0:len(nonce)] must equal the random
//      nonce we sent — proves freshness, defeats replay.
//   3. measurement (optional): if --expect-measurement is set,
//      MEASUREMENT (the launch digest of the VM image) must
//      match. This is the cryptographic "this VM was launched
//      with the kernel/initrd I built" assertion.
//
// What's NOT yet checked: TCB version against a policy floor,
// ID_BLOCK / AUTHOR_KEY pinning, REPORTED_TCB freshness. These
// are easy to layer on top of go-sev-guest/verify.SnpAttestation
// once a fleet policy exists.

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/sinkap/pancake/tools/pancake-go/internal/orchpb"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
)

func attestSNPCheck(
	ctx context.Context,
	cli orchpb.PancakeClient,
	nonce []byte,
	expectMeasurementHex string,
) error {
	resp, err := cli.AttestSEVSNP(ctx,
		&orchpb.AttestSEVSNPRequest{Nonce: nonce})
	if err != nil {
		return fmt.Errorf("AttestSEVSNP: %w", err)
	}
	fmt.Printf("[attest-snp] response: report=%dB vcek_cert=%dB\n",
		len(resp.Report), len(resp.VcekCert))

	report, err := abi.ReportToProto(resp.Report)
	if err != nil {
		return fmt.Errorf("parse SNP report: %w", err)
	}
	// verify.SnpAttestation wants the report wrapped with a cert
	// chain (or empty CertificateChain — then it fetches VCEK from
	// AMD KDS using CHIP_ID + TCB from the report).
	attestation := &pb.Attestation{Report: report}
	if len(resp.VcekCert) > 0 {
		attestation.CertificateChain = &pb.CertificateChain{
			VcekCert: resp.VcekCert,
		}
	}

	// (1) signature: walk back to AMD ARK. Cert chain VCEK → ASK
	// → ARK; if not provided server-side, fetched via KDS.
	opts := verify.DefaultOptions()
	opts.Getter = trust.DefaultHTTPSGetter()
	if err := verify.SnpAttestation(attestation, opts); err != nil {
		return fmt.Errorf("verify SNP attestation: %w", err)
	}
	fmt.Println("[attest-snp] OK    report signature valid (chain → AMD ARK)")

	// (2) nonce binding: the SNP hardware copies REPORT_DATA verbatim
	// from our request. Must match our fresh nonce.
	if !bytes.HasPrefix(report.ReportData, nonce) {
		return fmt.Errorf("nonce mismatch: report_data[:%d]=%x… want=%x…",
			len(nonce), report.ReportData[:8], nonce[:8])
	}
	fmt.Printf("[attest-snp] OK    nonce in REPORT_DATA matches request (%x…)\n",
		nonce[:8])

	// Convenience: print which chip we're talking to and what TCB
	// it's running.
	tcb := kds.DecomposeTCBVersion(kds.TCBVersion(report.ReportedTcb))
	fmt.Printf("[attest-snp] INFO  chip_id=%x… reported_tcb=bl%d/tee%d/snp%d/ucode%d measurement=%x…\n",
		report.ChipId[:8],
		tcb.BlSpl, tcb.TeeSpl, tcb.SnpSpl, tcb.UcodeSpl,
		report.Measurement[:8])

	// (3) MEASUREMENT against expected (optional). The build server
	// can compute this from the UKI bytes it produced; skip if the
	// caller hasn't pinned a value.
	if expectMeasurementHex == "" {
		fmt.Println("[attest-snp] SKIP  --expect-measurement not set; not checking launch digest")
	} else {
		want, err := hex.DecodeString(expectMeasurementHex)
		if err != nil {
			return fmt.Errorf("--expect-measurement: invalid hex: %w", err)
		}
		if !bytes.Equal(want, report.Measurement) {
			return fmt.Errorf("MEASUREMENT mismatch: want=%x got=%x",
				want[:8], report.Measurement[:8])
		}
		fmt.Printf("[attest-snp] OK    MEASUREMENT matches expected (%x…)\n",
			want[:8])
	}
	return nil
}
