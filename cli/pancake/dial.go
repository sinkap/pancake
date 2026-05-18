// Shared dial helpers for the admin-side gRPC subcommands
// (`pancake push`, `pancake get-current`).
//
// mTLS only — bearer-token plumbing is gone. Supplying any of
// --ca-file / --cert-file / --key-file without the others is a
// config error (no graceful "half mTLS" fallback worth having).
package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/sinkap/pancake/common/gen/go/pancakepb"
	"github.com/sinkap/pancake/common/go/pkitls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type dialOpts struct {
	target     string
	caFile     string
	certFile   string
	keyFile    string
	serverName string
}

func registerDialFlags(fs *flag.FlagSet, o *dialOpts) {
	fs.StringVar(&o.target, "target", "",
		"VM gRPC address, e.g. localhost:7878 (required)")
	fs.StringVar(&o.caFile, "ca-file", "",
		"PEM root CA that signed the server's cert (mTLS).")
	fs.StringVar(&o.certFile, "cert-file", "",
		"PEM client-auth leaf cert presented to pancaked (mTLS).")
	fs.StringVar(&o.keyFile, "key-file", "",
		"PKCS#8 PEM private key for --cert-file (mTLS).")
	fs.StringVar(&o.serverName, "server-name", "",
		"override SNI / server cert hostname check. Default: dial host.")
}

func dialTarget(o dialOpts) (pancakepb.PancakeAgentServiceClient, *grpc.ClientConn, context.Context, error) {
	target := strings.TrimPrefix(o.target, "grpc://")
	target = strings.TrimRight(target, "/")

	var dialOpt grpc.DialOption
	mtlsAny := o.caFile != "" || o.certFile != "" || o.keyFile != ""
	mtlsAll := o.caFile != "" && o.certFile != "" && o.keyFile != ""
	switch {
	case mtlsAll:
		serverName := o.serverName
		if serverName == "" {
			serverName = target
			if i := strings.LastIndex(serverName, ":"); i >= 0 {
				serverName = serverName[:i]
			}
		}
		cfg, err := pkitls.LoadClientConfig(
			o.certFile, o.keyFile, o.caFile, serverName)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("mTLS config: %w", err)
		}
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(cfg))
	case mtlsAny:
		return nil, nil, nil, fmt.Errorf(
			"--ca-file, --cert-file, --key-file must be set together")
	default:
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	conn, err := grpc.NewClient(target, dialOpt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial %s: %w", target, err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	return pancakepb.NewPancakeAgentServiceClient(conn), conn, ctx, nil
}
