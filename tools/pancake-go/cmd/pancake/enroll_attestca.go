// enroll_attestca.go: thin wrapper around the smallstep
// go.step.sm/crypto/tpm/attestation client. Asks pancake-attest-ca to
// issue a cert chain for our AK; installs it on the AK so the
// next ACME flow's x5c is non-empty.

package main

import (
	"context"
	"fmt"

	"go.step.sm/crypto/tpm"
	tpmattest "go.step.sm/crypto/tpm/attestation"
)

func enrollAKWithAttestCA(
	ctx context.Context, t *tpm.TPM, ak *tpm.AK,
	caURL, caRootFile string,
) error {
	opts := []tpmattest.Option{}
	if caRootFile != "" {
		opts = append(opts, tpmattest.WithRootsFile(caRootFile))
	} else {
		// Demo / dev path. pancake-attest-ca uses a self-signed listener cert
		// when no externally-issued one is provided.
		opts = append(opts, tpmattest.WithInsecure())
	}
	cli, err := tpmattest.NewClient(caURL, opts...)
	if err != nil {
		return fmt.Errorf("attestation client: %w", err)
	}

	eks, err := t.GetEKs(ctx)
	if err != nil {
		return fmt.Errorf("GetEKs: %w", err)
	}
	if len(eks) == 0 {
		return fmt.Errorf("no EK on this TPM")
	}
	ek := eks[0] // smallstep client picks the EK we pass in

	chain, err := cli.Attest(ctx, t, ek, ak)
	if err != nil {
		return err
	}
	if len(chain) == 0 {
		return fmt.Errorf("attestation CA returned empty chain")
	}
	if err := ak.SetCertificateChain(ctx, chain); err != nil {
		return fmt.Errorf("ak.SetCertificateChain: %w", err)
	}
	return nil
}
