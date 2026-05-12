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

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/runner"
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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tokenLen < 64 || *tokenLen%8 != 0 {
		return die(fmt.Errorf("--bits must be a multiple of 8 and >= 64"))
	}
	if _, err := runner.Capture(runner.Cmd{
		Argv: []string{"systemd-creds", "has-tpm2"},
	}); err != nil {
		fmt.Fprintln(os.Stderr,
			"pancake enroll: systemd-creds reports no usable TPM2 — is /dev/tpmrm0 present?")
		return 1
	}

	// Random token, hex-encoded for ergonomic copy/paste.
	raw := make([]byte, *tokenLen/8)
	if _, err := rand.Read(raw); err != nil {
		return die(err)
	}
	token := hex.EncodeToString(raw)

	// Write plaintext to a tmpfile, then systemd-creds encrypt → out.
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

	// systemd-creds encrypt --name=pancake-orch-token --tpm2-pcrs=7+11 - <tmp> <out>
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
			"[enroll] sealed against PCRs %s — re-enroll if the boot chain changes\n"+
			"\n",
		*out, *pcrs)
	fmt.Println(token)
	fmt.Fprintln(os.Stderr,
		"\n^ this is the bearer token. Save it to a file (mode 600) and pass it to:\n"+
			"    pancake orchestrate push --token-file <file> --target <vm>:<port> ...\n"+
			"  After this terminal goes away, only the TPM (and a matching\n"+
			"  boot chain) can recover the value from the sealed blob.")
	return 0
}

// (loadSealedToken moved to internal/orchsrv.LoadSealedToken — only
// pancaked needs to decrypt; enroll.go just produces the encrypted blob.)
