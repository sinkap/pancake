package orchsrv

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sinkap/pancake/tools/pancake-go/internal/orchpb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// defaultPCRs are quoted when the caller doesn't specify a PCR
// selection. Covers boot chain (7, 11, 12), manifest (13), and
// layer set (14) — enough for "is this VM running gen N?".
var defaultPCRs = []int32{7, 11, 12, 13, 14}

// attestState holds the per-boot TPM2 attestation context. Created
// once at pancaked startup; lives in /run (tmpfs) so it disappears
// on reboot, matching the per-boot AK lifecycle the verifier
// expects.
type attestState struct {
	dir    string // /run/pancake/attest
	ekCtx  string // .../ek.ctx — primary EK context blob
	ekPub  []byte // contents of .../ek.pub — TPM2B_PUBLIC, exported via Attest
	akCtx  string // .../ak.ctx — AK context blob (used by tpm2_quote)
	akPub  []byte // contents of .../ak.pub — TPM2B_PUBLIC
	akName []byte // contents of .../ak.name — name digest
}

// setupAttest provisions the per-boot AK if a TPM is present.
// Soft-fail: returns (nil, nil) on no-TPM systems so pancaked still
// serves Update / GetCurrentManifest; Attest RPC will return
// Unavailable.
//
// Steps mirror the standard tpm2-tools attestation flow:
//
//	tpm2_createek -G ecc -u ek.pub -c ek.ctx
//	tpm2_createak -C ek.ctx -G ecc -g sha256 -s ecdsa \
//	              -u ak.pub -n ak.name -c ak.ctx
//
// EK is anchored to the TPM endorsement seed (EH); AK is a child
// signing key. Both contexts are loaded into the TPM's transient
// hierarchy and saved to disk so subsequent quotes can resume them.
func setupAttest() (*attestState, error) {
	if _, err := os.Stat("/dev/tpmrm0"); err != nil {
		if _, err := os.Stat("/dev/tpm0"); err != nil {
			fmt.Fprintln(os.Stderr,
				"[pancaked] no TPM device — Attest RPC will return Unavailable")
			return nil, nil
		}
	}

	dir := "/run/pancake/attest"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("attest: mkdir %s: %w", dir, err)
	}
	st := &attestState{
		dir:   dir,
		ekCtx: filepath.Join(dir, "ek.ctx"),
		akCtx: filepath.Join(dir, "ak.ctx"),
	}
	ekPubPath := filepath.Join(dir, "ek.pub")
	akPubPath := filepath.Join(dir, "ak.pub")
	akNamePath := filepath.Join(dir, "ak.name")

	if err := runner.Run(runner.Cmd{
		Argv: []string{"tpm2_createek",
			"-G", "ecc",
			"-u", ekPubPath,
			"-c", st.ekCtx},
	}); err != nil {
		return nil, fmt.Errorf("attest: tpm2_createek: %w", err)
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"tpm2_createak",
			"-C", st.ekCtx,
			"-G", "ecc",
			"-g", "sha256",
			"-s", "ecdsa",
			"-u", akPubPath,
			"-n", akNamePath,
			"-c", st.akCtx},
	}); err != nil {
		return nil, fmt.Errorf("attest: tpm2_createak: %w", err)
	}

	var err error
	if st.ekPub, err = os.ReadFile(ekPubPath); err != nil {
		return nil, fmt.Errorf("attest: read ek.pub: %w", err)
	}
	if st.akPub, err = os.ReadFile(akPubPath); err != nil {
		return nil, fmt.Errorf("attest: read ak.pub: %w", err)
	}
	if st.akName, err = os.ReadFile(akNamePath); err != nil {
		return nil, fmt.Errorf("attest: read ak.name: %w", err)
	}

	fmt.Fprintf(os.Stderr,
		"[pancaked] attestation ready: AK provisioned (per-boot, in %s)\n", dir)
	return st, nil
}

// Attest implements orchpb.PancakeServer.Attest. Shells out to
// tpm2_quote against the in-memory AK ctx, returns the quote
// bytes + sig + AK/EK pubs + event log.
func (s *server) Attest(
	ctx context.Context, req *orchpb.AttestRequest,
) (*orchpb.AttestResponse, error) {
	if s.attest == nil {
		return nil, status.Error(codes.Unavailable,
			"no TPM on this host; attestation disabled")
	}
	if len(req.Nonce) < 8 {
		return nil, status.Error(codes.InvalidArgument,
			"nonce must be >= 8 bytes")
	}

	pcrs := req.Pcrs
	if len(pcrs) == 0 {
		pcrs = defaultPCRs
	}
	pcrList := pcrSelectionString(pcrs)

	// Quote produces three files: the attestation msg (-m), the sig
	// (-s), and a parsed PCR digest list (-o). Easier to read sigs/quote
	// directly than to parse stdout YAML.
	tmp, err := os.MkdirTemp(s.attest.dir, "quote-")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "tmpdir: %v", err)
	}
	defer os.RemoveAll(tmp)
	quotePath := filepath.Join(tmp, "quote.bin")
	sigPath := filepath.Join(tmp, "sig.bin")
	pcrsPath := filepath.Join(tmp, "pcrs.bin")

	// tpm2_quote accepts the qualification (nonce) as a hex string
	// directly via -q. Format defaults to the AK's signing scheme
	// (ECDSA-SHA256 for our AK), which tpm2_checkquote then parses.
	if err := runner.Run(runner.Cmd{
		Argv: []string{"tpm2_quote",
			"-c", s.attest.akCtx,
			"-l", pcrList,
			"-q", hex.EncodeToString(req.Nonce),
			"-m", quotePath,
			"-s", sigPath,
			"-o", pcrsPath},
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "tpm2_quote: %v", err)
	}

	quote, err := os.ReadFile(quotePath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read quote: %v", err)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read sig: %v", err)
	}
	pcrsBin, err := os.ReadFile(pcrsPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read pcrs.bin: %v", err)
	}

	// Per-PCR digests via tpm2_pcrread (separate call so we don't
	// have to parse tpm2_quote -o output, which is bank-prefixed).
	pcrDigests, err := readPCRs(pcrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "tpm2_pcrread: %v", err)
	}

	// Event log is best-effort; absent on systems where securityfs
	// isn't exposed in the running rootfs (it usually is via systemd).
	var eventLog []byte
	if b, err := os.ReadFile(
		"/sys/kernel/security/tpm0/binary_bios_measurements"); err == nil {
		eventLog = b
	}

	return &orchpb.AttestResponse{
		Quote:     quote,
		Signature: sig,
		AkPub:     s.attest.akPub,
		EkPub:     s.attest.ekPub,
		AkName:    s.attest.akName,
		Pcr:       pcrDigests,
		EventLog:  eventLog,
		PcrsBin:   pcrsBin,
	}, nil
}

// ActivateCredential runs the EK-policy-bound activation that proves
// the AK lives in the same TPM as the EK. The dance is necessary
// because TPM2 ECC EKs use a policy session requiring endorsement
// hierarchy auth — we set that up here and tear it down on every
// call (no persistent session state).
func (s *server) ActivateCredential(
	ctx context.Context, req *orchpb.ActivateCredentialRequest,
) (*orchpb.ActivateCredentialResponse, error) {
	if s.attest == nil {
		return nil, status.Error(codes.Unavailable, "no TPM on this host")
	}
	if len(req.Blob) == 0 {
		return nil, status.Error(codes.InvalidArgument, "blob is empty")
	}

	tmp, err := os.MkdirTemp(s.attest.dir, "ac-")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "tmpdir: %v", err)
	}
	defer os.RemoveAll(tmp)

	blobPath := filepath.Join(tmp, "blob.bin")
	secretPath := filepath.Join(tmp, "secret.bin")
	sessionPath := filepath.Join(tmp, "session.dat")
	if err := os.WriteFile(blobPath, req.Blob, 0o600); err != nil {
		return nil, status.Errorf(codes.Internal, "write blob: %v", err)
	}

	// Set up an endorsement-hierarchy policy session. ECC EKs require
	// it; default `tpm2_policysecret -c e` provides empty endorsement
	// auth (which is the swtpm + most physical-TPM default).
	if err := runner.Run(runner.Cmd{
		Argv: []string{"tpm2_startauthsession",
			"--policy-session", "-S", sessionPath},
	}); err != nil {
		return nil, status.Errorf(codes.Internal,
			"tpm2_startauthsession: %v", err)
	}
	defer runner.RunOK(runner.Cmd{
		Argv: []string{"tpm2_flushcontext", sessionPath},
	})
	if err := runner.Run(runner.Cmd{
		Argv: []string{"tpm2_policysecret",
			"-S", sessionPath, "-c", "e"},
	}); err != nil {
		return nil, status.Errorf(codes.Internal,
			"tpm2_policysecret: %v", err)
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"tpm2_activatecredential",
			"-c", s.attest.akCtx,
			"-C", s.attest.ekCtx,
			"-i", blobPath,
			"-o", secretPath,
			"-P", "session:" + sessionPath},
	}); err != nil {
		return nil, status.Errorf(codes.Internal,
			"tpm2_activatecredential: %v", err)
	}

	secret, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read secret: %v", err)
	}
	return &orchpb.ActivateCredentialResponse{Secret: secret}, nil
}

func pcrSelectionString(pcrs []int32) string {
	parts := make([]string, len(pcrs))
	for i, p := range pcrs {
		parts[i] = strconv.Itoa(int(p))
	}
	return "sha256:" + strings.Join(parts, ",")
}

// readPCRs returns per-PCR sha256 digests in the same order as
// requested. Calls tpm2_pcrread once and parses its output.
func readPCRs(pcrs []int32) ([]*orchpb.AttestResponse_PcrDigest, error) {
	if len(pcrs) == 0 {
		return nil, nil
	}
	out, err := runner.Capture(runner.Cmd{
		Argv: []string{"tpm2_pcrread", pcrSelectionString(pcrs)},
	})
	if err != nil {
		return nil, fmt.Errorf("tpm2_pcrread: %w", err)
	}
	// Output looks like:
	//   sha256:
	//     7  : 0x000102...
	//     11 : 0xABCDEF...
	digestByIdx := map[int32][]byte{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ":") || !strings.HasPrefix(line, strings.TrimSpace(line)) {
			continue
		}
		// expect "<num> : 0x<hex>"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		idxStr := strings.TrimSpace(parts[0])
		hexStr := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(parts[1]), "0x"))
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			continue
		}
		b, err := hex.DecodeString(hexStr)
		if err != nil {
			continue
		}
		digestByIdx[int32(idx)] = b
	}
	out2 := make([]*orchpb.AttestResponse_PcrDigest, 0, len(pcrs))
	for _, p := range pcrs {
		out2 = append(out2, &orchpb.AttestResponse_PcrDigest{
			Index:  p,
			Sha256: digestByIdx[p],
		})
	}
	return out2, nil
}
