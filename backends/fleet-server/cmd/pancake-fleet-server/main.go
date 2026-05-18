// pancake-fleet-server: orchestrator-side fleet manager.
//
// Listens on two ports:
//   -http-addr   HTTP REST API + (later) embedded SvelteKit UI
//   -grpc-addr   gRPC FleetManager service (Enroll, Heartbeat, ListVMs)
//
// Backed by PostgreSQL. Schema migrations applied automatically on startup.
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	fleetserver "github.com/sinkap/pancake/tools/pancake-go/fleet-server"
	"github.com/sinkap/pancake/tools/pancake-go/fleet-server/internal/attestpoll"
	"github.com/sinkap/pancake/tools/pancake-go/fleet-server/internal/fleetapi"
	"github.com/sinkap/pancake/tools/pancake-go/fleet-server/internal/fleetdb"
	"github.com/sinkap/pancake/tools/pancake-go/fleet-server/internal/fleetgrpc"
	"github.com/sinkap/pancake/tools/pancake-go/internal/fleetpb"
)

func main() {
	httpAddr := flag.String("http-addr", ":8080", "HTTP listen address (REST + UI)")
	grpcAddr := flag.String("grpc-addr", ":8081", "gRPC listen address (FleetManager)")
	dsn := flag.String("dsn", "",
		"PostgreSQL DSN, e.g. postgres://pancake:secret@db/pancake_fleet?sslmode=disable. "+
			"Falls back to $DATABASE_URL.")
	skipMigrate := flag.Bool("skip-migrate", false, "skip migrations on startup")

	// Attestation poller flags
	pollInterval := flag.Duration("attest-interval", time.Hour,
		"how often to attest every VM (0 = disable polling)")
	pollConcurrency := flag.Int("attest-concurrency", 10,
		"max parallel Attest RPCs per sweep")
	pollVMPort := flag.Int("attest-vm-port", 7878,
		"gRPC port pancaked listens on inside each VM")
	pollCA := flag.String("attest-ca-file", "",
		"CA bundle for mTLS to pancaked (step-ca root)")
	pollCert := flag.String("attest-cert-file", "",
		"client cert PEM for mTLS to pancaked")
	pollKey := flag.String("attest-key-file", "",
		"client key PEM for mTLS to pancaked")
	pollServerName := flag.String("attest-server-name", "",
		"override SNI/cert hostname when dialing pancaked (default: VM name)")

	webUI := flag.String("web-ui", "",
		"path to the SvelteKit build/ directory; if set, served at / "+
			"(typically web-ui/build after `npm run build`)")

	tofu := flag.Bool("attest-tofu", false,
		"trust-on-first-use: auto-register expected PCRs from the first "+
			"valid attestation for each new generation")

	ekTrustBundle := flag.String("ek-trust-bundle", "",
		"PEM file containing trust roots for EK cert chain verification "+
			"(typically Google's vTPM root CA bundle or TPM manufacturer "+
			"roots). When empty, the poller still records the leaf "+
			"serial but doesn't validate the chain.")

	flag.Parse()

	if *dsn == "" {
		*dsn = os.Getenv("DATABASE_URL")
	}
	if *dsn == "" {
		log.Fatal("DSN required (--dsn or $DATABASE_URL)")
	}

	if !*skipMigrate {
		log.Println("[fleet-server] applying schema migrations")
		if err := fleetdb.Migrate(*dsn, fleetserver.MigrationsFS, "migrations"); err != nil {
			log.Fatalf("migrate: %v", err)
		}
		log.Println("[fleet-server] migrations applied")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := fleetdb.Open(ctx, *dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Pool.Close()

	// Load EK trust bundle if provided
	var ekTrustRoots *x509.CertPool
	if *ekTrustBundle != "" {
		b, err := os.ReadFile(*ekTrustBundle)
		if err != nil {
			log.Fatalf("read ek-trust-bundle %s: %v", *ekTrustBundle, err)
		}
		ekTrustRoots = x509.NewCertPool()
		if !ekTrustRoots.AppendCertsFromPEM(b) {
			log.Fatalf("ek-trust-bundle %s: no usable certs", *ekTrustBundle)
		}
		log.Printf("[fleet-server] loaded EK trust bundle from %s", *ekTrustBundle)
	}

	// Attestation poller — optional. Disabled when --attest-interval=0.
	var poller *attestpoll.Poller
	if *pollInterval > 0 {
		var err error
		poller, err = attestpoll.New(db, attestpoll.Config{
			Interval:           *pollInterval,
			MaxConcurrent:      *pollConcurrency,
			VMPort:             *pollVMPort,
			CAFile:             *pollCA,
			CertFile:           *pollCert,
			KeyFile:            *pollKey,
			ServerNameOverride: *pollServerName,
			TOFU:               *tofu,
			EKTrustRoots:       ekTrustRoots,
		})
		if err != nil {
			log.Fatalf("init attest poller: %v", err)
		}
		go poller.Run(ctx)
	} else {
		log.Println("[fleet-server] attestation poller disabled (--attest-interval=0)")
	}

	// HTTP server (API can trigger on-demand attestation via poller)
	api := &fleetapi.API{DB: db, Poller: poller, WebUI: *webUI}
	if *webUI != "" {
		log.Printf("[fleet-server] serving web UI from %s", *webUI)
	}
	httpSrv := &http.Server{
		Addr:              *httpAddr,
		Handler:           api.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// gRPC server
	grpcSrv := grpc.NewServer()
	fleetpb.RegisterFleetManagerServer(grpcSrv, fleetgrpc.New(db))

	// Listen
	grpcLn, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		log.Fatalf("grpc listen: %v", err)
	}

	// Start both servers in goroutines
	errCh := make(chan error, 2)
	go func() {
		log.Printf("[fleet-server] HTTP listening on %s", *httpAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("http: %w", err)
		}
	}()
	go func() {
		log.Printf("[fleet-server] gRPC listening on %s", *grpcAddr)
		if err := grpcSrv.Serve(grpcLn); err != nil {
			errCh <- fmt.Errorf("grpc: %w", err)
		}
	}()

	// Graceful shutdown on SIGINT/SIGTERM, or fast exit on server error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		log.Printf("[fleet-server] received %s, shutting down", sig)
	case err := <-errCh:
		log.Printf("[fleet-server] server error: %v", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	grpcSrv.GracefulStop()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[fleet-server] http shutdown: %v", err)
	}
	log.Println("[fleet-server] done")
}
