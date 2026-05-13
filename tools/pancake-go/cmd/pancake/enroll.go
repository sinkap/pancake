// `pancake enroll`: bind the orchestrator-update auth token to this VM's
// boot chain via TPM PCR sealing.
//
// Generates a 256-bit random bearer token, encrypts it via systemd-creds
// against PCR 7 (UEFI Secure Boot policy) + PCR 11 (UKI sections — kernel
// + initrd + cmdline), writes the sealed blob to
// /etc/pancake/orch-token.creds, and prints the plaintext for the
// operator to copy to their orchestrator config.
//
// Subsequent `pancake serve` invocations decrypt the blob at startup. If
// the kernel/initrd/cmdline gets swapped, PCR 11 differs from what was
// sealed against → systemd-creds decrypt fails → serve refuses to start
// → no updates can land. That's the whole point: tamper detection
// gating remote control.
//
// Re-enroll is required after any boot-chain change (e.g., a `pancake
// swap` that brings up a new kernel/initrd). For real fleets this is a
// one-time setup; in development, expect to re-enroll occasionally.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"
)

const defaultSealedTokenPath = "/etc/pancake/orch-token.creds"

func cmdEnroll(_ *kit.Kit, args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	pcrs := fs.String("pcrs", "7+11",
		"TPM PCRs to seal the token against (passed to systemd-creds "+
			"--tpm2-pcrs). Default 7+11 binds to Secure Boot policy + UKI "+
			"sections; tampering with either causes unseal to fail.")
	out := fs.String("out", defaultSealedTokenPath,
		"path to write the sealed token blob")
	tokenLen := fs.Int("bits", 256,
		"random token entropy in bits")
	ekOut := fs.String("ek-out", "/etc/pancake/ek.pub",
		"path to write the TPM endorsement key public area (TPM2B_PUBLIC). "+
			"This file identifies the host's TPM to the orchestrator and "+
			"is what `pancake attest` compares against during verification. "+
			"Ship this file to your orchestrator/attestation registry.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tokenLen < 64 || *tokenLen%8 != 0 {
		return die(fmt.Errorf("--bits must be a multiple of 8 and >= 64"))
	}

	// Two independent things happen here: (a) bearer-token sealing
	// via systemd-creds (PCR 7+11), (b) EK pubkey export via
	// tpm2_createek. Both want the TPM, but they fail differently:
	//   - systemd-creds is strict — it requires firmware-side
	//     measurement (only happens via UEFI/UKI boot). On a
	//     direct -kernel boot it reports `partial -firmware`.
	//   - tpm2_createek only needs the TPM device itself.
	// So we attempt them independently and let either succeed.
	tokenSealed := false
	if _, err := runner.Capture(runner.Cmd{
		Argv: []string{"systemd-creds", "has-tpm2"},
	}); err != nil {
		fmt.Fprintln(os.Stderr,
			"[enroll] systemd-creds reports no usable TPM2 (need UEFI/UKI boot for "+
				"firmware measurement) — skipping bearer-token sealing")
	} else {
		tokenSealed = true
	}

	// (a) Bearer-token sealing — only when systemd-creds is happy.
	var token string
	if tokenSealed {
		raw := make([]byte, *tokenLen/8)
		if _, err := rand.Read(raw); err != nil {
			return die(err)
		}
		token = hex.EncodeToString(raw)

		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			return die(err)
		}
		tmpPlain, err := os.CreateTemp("", "pancake-enroll-")
		if err != nil {
			return die(err)
		}
		tmpPlainPath := tmpPlain.Name()
		if _, err := tmpPlain.WriteString(token); err != nil {
			tmpPlain.Close()
			os.Remove(tmpPlainPath)
			return die(err)
		}
		tmpPlain.Close()
		defer os.Remove(tmpPlainPath)

		if err := runner.Run(runner.Cmd{
			Argv: []string{"systemd-creds", "encrypt",
				"--name=pancake-orch-token",
				"--tpm2-pcrs=" + *pcrs,
				tmpPlainPath, *out},
			Sudo: true,
		}); err != nil {
			return die(fmt.Errorf("systemd-creds encrypt: %w", err))
		}

		fmt.Fprintf(os.Stderr,
			"\n[enroll] sealed token written to %s\n"+
				"[enroll] sealed against PCRs %s — re-enroll if the boot chain changes\n",
			*out, *pcrs)
	}

	// EK export. Same operator action also dumps the endorsement key
	// public area so the orchestrator's attestation registry can
	// recognize this host. EK is durable across reboots (anchored to
	// the TPM endorsement seed); export-once, ship-once, valid until
	// the TPM is reset.
	if err := os.MkdirAll(filepath.Dir(*ekOut), 0o755); err != nil {
		return die(err)
	}
	tmpDir, err := os.MkdirTemp("", "pancake-ek-")
	if err != nil {
		return die(err)
	}
	defer os.RemoveAll(tmpDir)
	ekCtx := filepath.Join(tmpDir, "ek.ctx")
	if err := runner.Run(runner.Cmd{
		Argv: []string{"tpm2_createek",
			"-G", "ecc",
			"-u", *ekOut,
			"-c", ekCtx},
		Sudo: true,
	}); err != nil {
		return die(fmt.Errorf("tpm2_createek: %w", err))
	}
	fmt.Fprintf(os.Stderr,
		"[enroll] EK public area written to %s\n"+
			"[enroll] copy this file to the orchestrator side (it's the\n"+
			"[enroll] identity verifier for `pancake attest --target=%s`)\n\n",
		*ekOut, "<vm>:<port>")

	if tokenSealed {
		fmt.Println(token)
		fmt.Fprintln(os.Stderr,
			"\n^ this is the bearer token. Save it to a file (mode 600) and pass it to:\n"+
				"    pancake orchestrate push --token-file <file> --target <vm>:<port> ...\n"+
				"  After this terminal goes away, only the TPM (and a matching\n"+
				"  boot chain) can recover the value from the sealed blob.")
	} else {
		fmt.Fprintln(os.Stderr,
			"[enroll] (token-sealing skipped; EK was still exported above)")
	}
	return 0
}

// (loadSealedToken moved to internal/orchsrv.LoadSealedToken — only
// pancaked needs to decrypt; enroll.go just produces the encrypted blob.)
