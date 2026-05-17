// fleet-test-client: tiny grpc client for smoke-testing the fleet server.
//
// Usage:
//   go run ./fleet-server/cmd/fleet-test-client \
//     -addr localhost:8081 \
//     -op enroll -name test-vm-1 -platform gce
//   go run ./fleet-server/cmd/fleet-test-client -addr localhost:8081 -op list
//   go run ./fleet-server/cmd/fleet-test-client -addr localhost:8081 -op heartbeat -name test-vm-1
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sinkap/pancake/tools/pancake-go/internal/fleetpb"
)

func main() {
	addr := flag.String("addr", "localhost:8081", "fleet server gRPC address")
	op := flag.String("op", "list", "enroll | heartbeat | list | get")
	name := flag.String("name", "test-vm-1", "VM name")
	platform := flag.String("platform", "self-hosted", "VM platform")
	ip := flag.String("ip", "10.0.0.42", "internal IP")
	flag.Parse()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	cli := fleetpb.NewFleetManagerClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch *op {
	case "enroll":
		resp, err := cli.Enroll(ctx, &fleetpb.EnrollRequest{
			Name:              *name,
			Platform:          *platform,
			InternalIp:        *ip,
			CertSerial:        "deadbeef",
			CurrentGeneration: 1,
			MetadataJson:      `{"source":"test"}`,
		})
		if err != nil {
			log.Fatalf("enroll: %v", err)
		}
		fmt.Printf("enrolled id=%d msg=%q\n", resp.GetId(), resp.GetMessage())

	case "heartbeat":
		if _, err := cli.Heartbeat(ctx, &fleetpb.HeartbeatRequest{
			Name: *name, CurrentGeneration: 2,
		}); err != nil {
			log.Fatalf("heartbeat: %v", err)
		}
		fmt.Println("heartbeat ok")

	case "list":
		resp, err := cli.ListVMs(ctx, &fleetpb.ListVMsRequest{PageSize: 100})
		if err != nil {
			log.Fatalf("list: %v", err)
		}
		fmt.Printf("total=%d vms:\n", resp.GetTotal())
		for _, v := range resp.GetVms() {
			fmt.Printf("  id=%d name=%s platform=%s ip=%s status=%s gen=%d enrolled=%s\n",
				v.GetId(), v.GetName(), v.GetPlatform(), v.GetInternalIp(),
				v.GetAttestationStatus(), v.GetCurrentGeneration(),
				v.GetEnrolledAt().AsTime().Format(time.RFC3339))
		}

	case "get":
		v, err := cli.GetVM(ctx, &fleetpb.GetVMRequest{
			Id: &fleetpb.GetVMRequest_Name{Name: *name},
		})
		if err != nil {
			log.Fatalf("get: %v", err)
		}
		fmt.Printf("id=%d name=%s platform=%s status=%s metadata=%s\n",
			v.GetId(), v.GetName(), v.GetPlatform(),
			v.GetAttestationStatus(), v.GetMetadataJson())

	default:
		fmt.Fprintf(os.Stderr, "unknown op %q (enroll|heartbeat|list|get)\n", *op)
		os.Exit(2)
	}
}
