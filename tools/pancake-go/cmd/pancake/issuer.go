// issuer.go: glue between cmd/pancake's enroll command and the
// pluggable issuance.Issuer interface.
//
// Today only the step-ca adapter lives here; the CAS issuer arrives
// in a follow-up commit and lives in internal/issuance/gcpcas to
// keep its GCP deps out of cmd/pancake.

package main

import (
	"context"
	"fmt"
	"net"

	"github.com/sinkap/pancake/tools/pancake-go/internal/issuance"
	"github.com/sinkap/pancake/tools/pancake-go/internal/issuance/gcpcas"
)

// pickIssuer returns the Issuer the enroll command should use based on
// the loaded orch config. Falls back to step-ca for backward compat
// when issuance.ca isn't set.
func pickIssuer(cfg *orchConfig, caURL, caRoot, attestCAURL, attestCARoot, acctKeyFile string) (issuance.Issuer, error) {
	mode := ""
	if cfg != nil {
		mode = cfg.IssuanceCA
	}
	switch mode {
	case "", "step-ca":
		return &stepCAIssuer{
			caURL:        caURL,
			caRoot:       caRoot,
			attestCAURL:  attestCAURL,
			attestCARoot: attestCARoot,
			acctKeyFile:  acctKeyFile,
		}, nil
	case "gcp-cas":
		if cfg == nil || cfg.CASPool == "" {
			return nil, fmt.Errorf("issuance.ca=gcp-cas selected but cas_pool is empty " +
				"in /etc/pancake/orch/config.json (recipe needs issuance.cas.pool)")
		}
		return gcpcas.New(cfg.CASPool)
	default:
		return nil, fmt.Errorf("unknown issuance.ca: %q (want step-ca or gcp-cas)", mode)
	}
}

// stepCAIssuer wraps the existing acmeTPMEnroll function in the
// Issuer interface. No behavior change — same code path as before.
type stepCAIssuer struct {
	caURL, caRoot             string
	attestCAURL, attestCARoot string
	acctKeyFile               string
}

func (s *stepCAIssuer) Name() string { return "step-ca" }

func (s *stepCAIssuer) Issue(_ context.Context, in issuance.Input) error {
	ips := make([]net.IP, 0, len(in.IPs))
	for _, v := range in.IPs {
		if ip := net.ParseIP(v); ip != nil {
			ips = append(ips, ip)
		}
	}
	return acmeTPMEnroll(acmeTPMOpts{
		CAURL:        s.caURL,
		CARoot:       s.caRoot,
		AttestCAURL:  s.attestCAURL,
		AttestCARoot: s.attestCARoot,
		CommonName:   in.CommonName,
		DNSNames:     in.DNSNames,
		IPs:          ips,
		ServerCert:   in.ServerCertPath,
		TPMStoreDir:  in.TPMStoreDir,
		KeyMarker:    in.KeyMarkerPath,
		AcctKeyFile:  s.acctKeyFile,
	})
}
