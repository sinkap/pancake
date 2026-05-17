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

	// HTTP server
	api := &fleetapi.API{DB: db}
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
