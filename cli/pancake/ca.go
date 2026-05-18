// `pancake ca`: minimum-viable certificate authority for the
// orchestrator's mTLS auth. Two subcommands:
//
//	init   create a self-signed root CA in a directory
//	issue  sign a leaf cert (server- or client-auth EKU)
//
// All keys are P-256 ECDSA; leaves are PKCS#8-encoded. The point of
// this CLI is to make the mTLS path testable without dragging in
// step-ca (yet) — the same on-wire/on-disk artifacts that
// step-ca/ACME-device-attest will produce later.
//
// Usage shape:
//
//	pancake ca init  --dir /etc/pancake/ca [--cn pancake-ca]
//	pancake ca issue --ca-dir /etc/pancake/ca \
//	                 --cn pancake-vm-1 \
//	                 --san DNS:localhost,IP:127.0.0.1 \
//	                 --server \
//	                 --out-cert /etc/pancake/server.crt \
//	                 --out-key  /etc/pancake/server.key
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/pkitls"
)

func cmdCA(_ *kit.Kit, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr,
			"usage: pancake ca <subcommand>\n"+
				"  init   --dir DIR [--cn NAME]\n"+
				"         create a self-signed root in DIR/{ca.crt,ca.key}\n"+
				"  issue  --ca-dir DIR --cn NAME [--san LIST] [--server]\n"+
				"         [--days N] --out-cert PATH --out-key PATH\n"+
				"         sign a leaf cert under DIR/{ca.crt,ca.key}")
		return 2
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "init":
		return cmdCAInit(args)
	case "issue":
		return cmdCAIssue(args)
	default:
		fmt.Fprintf(os.Stderr, "pancake ca: unknown subcommand %q\n", sub)
		return 2
	}
}

func cmdCAInit(args []string) int {
	fs := flag.NewFlagSet("ca init", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory for ca.crt + ca.key (required)")
	cn := fs.String("cn", "pancake-ca", "common name for the root cert")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "pancake ca init: --dir required")
		return 2
	}
	if _, err := pkitls.InitRoot(*dir, *cn); err != nil {
		return die(err)
	}
	fmt.Fprintf(os.Stderr,
		"[ca] root cert: %s/ca.crt\n"+
			"[ca] root key : %s/ca.key (mode 0600 — keep on the orchestrator only)\n",
		*dir, *dir)
	return 0
}

func cmdCAIssue(args []string) int {
	fs := flag.NewFlagSet("ca issue", flag.ContinueOnError)
	caDir := fs.String("ca-dir", "",
		"directory holding ca.crt + ca.key (required)")
	cn := fs.String("cn", "", "common name for the leaf (required)")
	san := fs.String("san", "",
		"comma-separated SAN list, e.g. 'DNS:localhost,IP:127.0.0.1' "+
			"or bare 'localhost,127.0.0.1' (auto-classified). "+
			"REQUIRED for server certs — TLS hostname verification "+
			"reads the SAN, not the CN.")
	server := fs.Bool("server", false,
		"issue a server-auth cert (default: client-auth)")
	days := fs.Int("days", 365, "validity in days")
	outCert := fs.String("out-cert", "",
		"path to write the leaf cert (PEM)")
	outKey := fs.String("out-key", "",
		"path to write the leaf key (PKCS#8 PEM, mode 0600)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *caDir == "" || *cn == "" || *outCert == "" || *outKey == "" {
		fmt.Fprintln(os.Stderr,
			"pancake ca issue: --ca-dir, --cn, --out-cert, --out-key all required")
		return 2
	}
	root, err := pkitls.LoadRoot(*caDir)
	if err != nil {
		return die(err)
	}
	dns, ips := pkitls.ParseSANs(*san)
	if *server && len(dns)+len(ips) == 0 {
		fmt.Fprintln(os.Stderr,
			"pancake ca issue: --server requires at least one --san entry "+
				"(TLS clients verify hostnames against SAN, not CN)")
		return 2
	}
	if err := root.Issue(pkitls.IssueOpts{
		CommonName: *cn,
		DNSNames:   dns,
		IPs:        ips,
		Server:     *server,
		OutCert:    *outCert,
		OutKey:     *outKey,
		TTLDays:    *days,
	}); err != nil {
		return die(err)
	}
	role := "client-auth"
	if *server {
		role = "server-auth"
	}
	fmt.Fprintf(os.Stderr,
		"[ca] issued %s leaf  cn=%s san=%q ttl=%dd\n"+
			"[ca]   cert: %s\n"+
			"[ca]   key : %s (mode 0600)\n",
		role, *cn, *san, *days, *outCert, *outKey)
	return 0
}
