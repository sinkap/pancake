// pancake-build-server: gRPC build daemon for pancake-os verity layers.
// See internal/buildpb/build.proto for the wire schema.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
	"github.com/sinkap/pancake/tools/pancake-go/server"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("listen", ":7879", "gRPC listen address")
	cacheDir := flag.String("cache", "/var/lib/pancake-build-server",
		"cache directory root (created if missing)")
	flag.Parse()

	if err := os.MkdirAll(*cacheDir, 0o755); err != nil {
		log.Fatalf("mkdir cache: %v", err)
	}
	srv, err := server.New(server.Opts{CacheDir: *cacheDir})
	if err != nil {
		log.Fatalf("server.New: %v", err)
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	g := grpc.NewServer()
	buildpb.RegisterPancakeBuilderServer(g, srv)

	fmt.Fprintf(os.Stderr,
		"[pancake-build-server] listening on %s, cache=%s\n", *addr, *cacheDir)
	if err := g.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
