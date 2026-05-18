// `pancake attest`: operator-side verifier for pancaked.Attest.
//
//   - Connects to a pancaked over gRPC.
//   - Sends a fresh nonce via Attest, gets back a TPM2 quote +
//     signature + AK pubkey + EK pubkey + per-PCR digests + event log.
//   - Validates, in order:
//       (a) EK pubkey matches the file produced by `pancake enroll
//           --ek-out=<path>` (exact byte match).
//       (b) Quote signature: tpm2_checkquote against AK pubkey + nonce
//           + the per-PCR digests the daemon returned (proves the TPM
//           generated the quote for THIS request).
//       (c) PCR 13 = sha256-extend(0…0, sha256(generation manifest))
//       (d) PCR 14 = sha256-extend(0…0, sha256(lowers TSV))
//       (e) PCR 11 (UKI) — TODO: skipped in v1; reading it correctly
//           requires re-running systemd-stub's per-section measurement
//           algorithm, which we'll piggyback on the event log later.
//
// Out of scope (v1): credential activation (cryptographically binds
// AK to EK via tpm2_makecredential / tpm2_activatecredential). Today
// we lean on the bearer-token-authenticated channel + EK byte
// comparison for "this is the same TPM we enrolled."

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sinkap/pancake/common/go/hoststate"
	"github.com/sinkap/pancake/common/go/kit"
	"github.com/sinkap/pancake/common/gen/go/pancakepb"
	"github.com/sinkap/pancake/common/go/runner"
	"github.com/sinkap/pancake/common/go/pkitls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func cmdAttest(_ *kit.Kit, args []string) int {
	// Resolve hoststate defaults (ignore error; flags can override)
	var caFileDefault, certFileDefault, keyFileDefault string
	if paths, err := hoststate.Resolve(); err == nil {
		caFileDefault = paths.TrustRoot
		certFileDefault = paths.ClientCert
		keyFileDefault = paths.ClientKey
	}

	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	target := fs.String("target", "",
		"address of pancaked, e.g. localhost:7878 (required)")
	ekPub := fs.String("ek-pub", "",
		"path to the EK pubkey file produced by `pancake enroll --ek-out`. "+
			"When set, the response's ek_pub MUST match these bytes "+
			"exactly. Skipped if empty.")
	tokenFile := fs.String("token-file", "",
		"bearer token file used by Attest's auth interceptor")
	caFile := fs.String("ca-file", caFileDefault,
		"PEM root CA for verifying pancaked's server cert (mTLS)")
	certFile := fs.String("cert-file", certFileDefault,
		"PEM client cert (mTLS)")
	keyFile := fs.String("key-file", keyFileDefault,
		"PKCS#8 PEM private key for --cert-file (mTLS)")
	serverName := fs.String("server-name", "",
		"override SNI / hostname verification (mTLS)")
	insecureSkipVerify := fs.Bool("insecure-skip-verify", false,
		"skip server hostname verification (dev only)")
	expectKit := fs.String("kit", "",
		"path to the kit dir whose generations/<gen>/ holds the "+
			"manifest.toml + lowers we expect this VM to be running. "+
			"Used to compute expected PCR 13 + 14. Skipped if empty.")
	expectGen := fs.Int("gen", 1,
		"generation id under --kit to compute expected PCR values from")
	mode := fs.String("mode", "tpm",
		"attestation mode: 'tpm' (default; per-VM TPM quote + PCRs), "+
			"'snp' (AMD SEV-SNP hardware report from /dev/sev-guest), "+
			"or 'both' (run both, all checks must pass)")
	expectMeasurement := fs.String("expect-measurement", "",
		"expected SEV-SNP MEASUREMENT (hex; 96 chars / 48 bytes). "+
			"When set in --mode=snp/both, the report's MEASUREMENT must "+
			"match — proves the launched UKI is the one we built.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *target == "" {
		return die(fmt.Errorf("--target is required"))
	}
	if *mode != "tpm" && *mode != "snp" && *mode != "both" {
		return die(fmt.Errorf("--mode must be tpm, snp, or both"))
	}

	// Fresh 32-byte nonce so the quote can't be replayed.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return die(err)
	}

	var creds credentials.TransportCredentials
	if *caFile != "" || *certFile != "" || *keyFile != "" {
		if *caFile == "" || *certFile == "" || *keyFile == "" {
			return die(fmt.Errorf("--ca-file, --cert-file, --key-file must be set together"))
		}
		cfg, err := pkitls.LoadClientConfig(*certFile, *keyFile, *caFile, *serverName)
		if err != nil {
			return die(fmt.Errorf("mTLS: %w", err))
		}
		if *insecureSkipVerify {
			cfg.InsecureSkipVerify = true
		}
		creds = credentials.NewTLS(cfg)
	} else {
		creds = insecure.NewCredentials()
	}
	cc, err := grpc.NewClient(*target, grpc.WithTransportCredentials(creds))
	if err != nil {
		return die(fmt.Errorf("dial %s: %w", *target, err))
	}
	defer cc.Close()
	cli := pancakepb.NewPancakeAgentServiceClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return die(fmt.Errorf("read token-file: %w", err))
		}
		ctx = metadata.AppendToOutgoingContext(ctx,
			"authorization", "Bearer "+trimSpace(string(b)))
	}

	pass := true

	// SEV-SNP path. In `--mode=both`, fail-on-error from the SNP
	// branch is independent of the TPM branch — both must succeed
	// for OVERALL PASS.
	if *mode == "snp" || *mode == "both" {
		if err := attestSNPCheck(ctx, cli, nonce, *expectMeasurement); err != nil {
			fmt.Printf("[attest-snp] FAIL  %v\n", err)
			pass = false
		}
		if *mode == "snp" {
			if !pass {
				fmt.Fprintln(os.Stderr, "\n[attest] OVERALL FAIL")
				return 1
			}
			fmt.Fprintln(os.Stderr, "\n[attest] OVERALL PASS")
			return 0
		}
		fmt.Println()
	}

	// TPM path (default).
	resp, err := cli.Attest(ctx, &pancakepb.AttestRequest{Nonce: nonce})
	if err != nil {
		return die(fmt.Errorf("Attest: %w", err))
	}

	fmt.Printf("[attest] response from %s: quote=%dB sig=%dB ak_pub=%dB ek_pub=%dB pcrs=%d event_log=%dB\n",
		*target, len(resp.Quote), len(resp.Signature),
		len(resp.AkPub), len(resp.EkPub), len(resp.Pcr), len(resp.EventLog))

	// (a) EK byte match.
	if *ekPub != "" {
		want, err := os.ReadFile(*ekPub)
		if err != nil {
			return die(fmt.Errorf("read --ek-pub: %w", err))
		}
		if !bytesEqual(want, resp.EkPub) {
			fmt.Printf("[attest] FAIL  EK pubkey mismatch (enrolled %s vs response): %d vs %d bytes, sha256(want)=%s sha256(got)=%s\n",
				*ekPub, len(want), len(resp.EkPub),
				sha256Hex(want), sha256Hex(resp.EkPub))
			pass = false
		} else {
			fmt.Printf("[attest] OK    EK pubkey matches enrolled (%s, sha256=%s)\n",
				*ekPub, sha256Hex(want)[:16]+"…")
		}

		// (a2) Credential activation: cryptographic AK ↔ EK binding.
		// Generate a random secret, encrypt it to AK-name under EK
		// via tpm2_makecredential -T none, ask the VM to activate,
		// compare returned bytes.
		if err := credentialActivationCheck(ctx, cli, resp); err != nil {
			fmt.Printf("[attest] FAIL  credential activation: %v\n", err)
			pass = false
		} else {
			fmt.Println("[attest] OK    credential activation (AK is in same TPM as enrolled EK)")
		}
	} else {
		fmt.Println("[attest] SKIP  --ek-pub not set; not checking EK identity / credential activation")
	}

	// (b) Quote signature via tpm2_checkquote. Marshal the per-PCR
	// digests into a "pcrs.bin" of the form tpm2_quote -o produces:
	// a TPMS_PCR_SELECTION header + digest sequence. tpm2_checkquote
	// is happy to accept the bin produced from `tpm2_pcrread … -o`,
	// which is the same shape — easier to reuse here.
	tmp, err := os.MkdirTemp("", "pancake-attest-")
	if err != nil {
		return die(err)
	}
	defer os.RemoveAll(tmp)
	akPubFile := filepath.Join(tmp, "ak.pub")
	quoteFile := filepath.Join(tmp, "quote.bin")
	sigFile := filepath.Join(tmp, "sig.bin")
	pcrsFile := filepath.Join(tmp, "pcrs.bin")
	if err := writeAll(akPubFile, resp.AkPub); err != nil {
		return die(err)
	}
	if err := writeAll(quoteFile, resp.Quote); err != nil {
		return die(err)
	}
	if err := writeAll(sigFile, resp.Signature); err != nil {
		return die(err)
	}
	// pcrs.bin is the same tpm2-tools-format file tpm2_quote -o
	// emitted server-side; we ship it verbatim so the verifier
	// doesn't have to reconstruct the selection-bitmap header.
	if err := writeAll(pcrsFile, resp.PcrsBin); err != nil {
		return die(err)
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"tpm2_checkquote",
			"-u", akPubFile,
			"-m", quoteFile,
			"-s", sigFile,
			"-f", pcrsFile,
			"-q", hex.EncodeToString(nonce),
			"-g", "sha256"},
	}); err != nil {
		fmt.Printf("[attest] FAIL  quote signature verification: %v\n", err)
		pass = false
	} else {
		fmt.Println("[attest] OK    quote signature valid (AK signed nonce + PCRs)")
	}

	// (c) + (d): PCR 13 = sha256(0…0 || sha256(manifest.toml))
	//            PCR 14 = sha256(0…0 || sha256(lowers TSV))
	if *expectKit != "" {
		genDir := filepath.Join(*expectKit, "generations",
			fmt.Sprintf("%d", *expectGen))
		mt, err := os.ReadFile(filepath.Join(genDir, "manifest.toml"))
		if err != nil {
			return die(fmt.Errorf("read manifest.toml: %w", err))
		}
		lw, err := os.ReadFile(filepath.Join(genDir, "lowers"))
		if err != nil {
			return die(fmt.Errorf("read lowers: %w", err))
		}
		expectPCR13 := pcrExtend(zero32(), sha256Sum(mt))
		expectPCR14 := pcrExtend(zero32(), sha256Sum(lw))

		got := map[int32][]byte{}
		for _, p := range resp.Pcr {
			got[p.Index] = p.Sha256
		}
		check := func(idx int32, want []byte, label string) {
			if g := got[idx]; g == nil {
				fmt.Printf("[attest] SKIP  PCR %d not in response (%s)\n", idx, label)
				return
			} else if !bytesEqual(g, want) {
				fmt.Printf("[attest] FAIL  PCR %d %s: want=%x  got=%x\n",
					idx, label, want[:8], g[:8])
				pass = false
			} else {
				fmt.Printf("[attest] OK    PCR %d %s: %x…\n",
					idx, label, want[:8])
			}
		}
		check(13, expectPCR13, "= extend(sha256(manifest.toml))")
		check(14, expectPCR14, "= extend(sha256(lowers))")
	} else {
		fmt.Println("[attest] SKIP  --kit not set; not checking PCR 13/14")
	}

	// PCR 11 (UKI) — systemd-stub measures each UKI section
	// (.linux, .initrd, .cmdline, .osrel, .uname) into PCR 11
	// during firmware/UKI handoff. The kernel exposes those
	// measurements at /sys/kernel/security/tpm0/binary_bios_measurements
	// (which pancaked ships in resp.event_log).
	//
	// Caveat: systemd-pcrextend ALSO extends PCR 11 from userspace
	// after boot ("sysinit", "ready", etc.), and those extensions
	// are NOT in the firmware log. So the firmware-only replay
	// won't equal the live PCR on a fully-booted system. We:
	//   - replay the firmware log → "firmwarePCR11" (proves the
	//     exact UKI that was loaded)
	//   - if live == firmwarePCR11 → strict OK (no userspace
	//     extensions: rare but possible with masked services)
	//   - else INFO with both values and the entry list, so the
	//     operator can verify the UKI sections by hand
	if len(resp.EventLog) > 0 {
		entries, err := parseEventLog(resp.EventLog)
		if err != nil {
			fmt.Printf("[attest] WARN  event log parse failed: %v\n", err)
		} else {
			for _, p := range resp.Pcr {
				if p.Index != 11 {
					continue
				}
				if isAllZero(p.Sha256) {
					fmt.Println("[attest] INFO  PCR 11 unset (no UKI; direct -kernel boot)")
					continue
				}
				firmwarePCR11 := replayPCR(entries, 11)
				count := len(filterPCR(entries, 11))
				if bytesEqual(firmwarePCR11, p.Sha256) {
					fmt.Printf("[attest] OK    PCR 11 firmware-event-log replay matches live (%d entries):\n",
						count)
				} else {
					fmt.Printf("[attest] INFO  PCR 11 firmware-event-log replay (%d firmware entries):\n",
						count)
					fmt.Printf("              firmware-replay: %x…\n", firmwarePCR11[:8])
					fmt.Printf("              live:            %x… (extended by userspace, e.g. systemd-pcrextend)\n",
						p.Sha256[:8])
				}
				for _, line := range summarizeEntries(entries, 11) {
					fmt.Println(line)
				}
			}
		}
	} else {
		fmt.Println("[attest] SKIP  no event_log in response (kernel didn't expose securityfs)")
	}

	if !pass {
		fmt.Fprintln(os.Stderr, "\n[attest] OVERALL FAIL")
		return 1
	}
	fmt.Fprintln(os.Stderr, "\n[attest] OVERALL PASS")
	return 0
}

// credentialActivationCheck does the verifier half of the standard
// TPM2 credential-activation dance:
//
//   1. Generate a random secret S (16 bytes).
//   2. tpm2_makecredential -T none -G sha256 -e ek.pub -n ak.name
//      -s S -o blob          (offline; -T none = no TPM needed here)
//   3. ActivateCredential(blob) → S' from the VM's TPM.
//   4. S == S' ⇒ AK is in the same TPM as the enrolled EK.
//
// Returns error if any step fails or the secret round-trip mismatches.
func credentialActivationCheck(
	ctx context.Context,
	cli pancakepb.PancakeAgentServiceClient,
	resp *pancakepb.AttestResponse,
) error {
	if len(resp.AkName) == 0 || len(resp.EkPub) == 0 {
		return fmt.Errorf("response missing ak_name or ek_pub")
	}

	tmp, err := os.MkdirTemp("", "pancake-credact-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	ekPubFile := filepath.Join(tmp, "ek.pub")
	akNameFile := filepath.Join(tmp, "ak.name")
	secretFile := filepath.Join(tmp, "secret.bin")
	blobFile := filepath.Join(tmp, "cred.blob")
	if err := writeAll(ekPubFile, resp.EkPub); err != nil {
		return err
	}
	if err := writeAll(akNameFile, resp.AkName); err != nil {
		return err
	}
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	if err := writeAll(secretFile, secret); err != nil {
		return err
	}
	// -T none = offline (no TPM access). DON'T pass -G: that
	// switches the tool into PEM-pubkey mode and rejects our
	// TPM2B_PUBLIC bytes. Algorithm is auto-derived from the EK
	// public area's nameAlg (ECC + sha256 for our setup).
	if err := runner.Run(runner.Cmd{
		Argv: []string{"tpm2_makecredential",
			"-T", "none",
			"-e", ekPubFile,
			"-n", hex.EncodeToString(resp.AkName),
			"-s", secretFile,
			"-o", blobFile},
	}); err != nil {
		return fmt.Errorf("tpm2_makecredential: %w", err)
	}
	blob, err := os.ReadFile(blobFile)
	if err != nil {
		return err
	}

	got, err := cli.ActivateCredential(ctx, &pancakepb.ActivateCredentialRequest{
		Blob: blob,
	})
	if err != nil {
		return fmt.Errorf("ActivateCredential RPC: %w", err)
	}
	if !bytesEqual(secret, got.Secret) {
		return fmt.Errorf("secret round-trip mismatch (want %x got %x)",
			secret[:8], got.Secret[:8])
	}
	return nil
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func sha256Hex(b []byte) string {
	return hex.EncodeToString(sha256Sum(b))
}

func zero32() []byte { return make([]byte, 32) }

// pcrExtend returns sha256(prev || measurement) — the standard PCR
// extension function for the SHA-256 bank.
func pcrExtend(prev, measurement []byte) []byte {
	buf := make([]byte, 0, len(prev)+len(measurement))
	buf = append(buf, prev...)
	buf = append(buf, measurement...)
	return sha256Sum(buf)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func filterPCR(entries []eventLogEntry, pcr uint32) []eventLogEntry {
	var out []eventLogEntry
	for _, e := range entries {
		if e.PCR == pcr {
			out = append(out, e)
		}
	}
	return out
}

func writeAll(path string, b []byte) error {
	return os.WriteFile(path, b, 0o600)
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' ||
		s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}
