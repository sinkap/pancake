// Package fleetgrpc implements the FleetManager gRPC service.
package fleetgrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/sinkap/pancake/tools/pancake-go/fleet-server/internal/fleetdb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/fleetpb"
)

// Server implements fleetpb.FleetManagerServer.
type Server struct {
	fleetpb.UnimplementedFleetManagerServer
	DB *fleetdb.DB
}

// New returns a FleetManager service backed by the given database.
func New(db *fleetdb.DB) *Server {
	return &Server{DB: db}
}

// Enroll registers (or updates) a VM. Idempotent.
func (s *Server) Enroll(ctx context.Context, req *fleetpb.EnrollRequest) (*fleetpb.EnrollResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.GetPlatform() == "" {
		return nil, status.Error(codes.InvalidArgument, "platform is required")
	}

	// Validate metadata_json parses if non-empty
	md := req.GetMetadataJson()
	if md != "" {
		var tmp any
		if err := json.Unmarshal([]byte(md), &tmp); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "metadata_json: %v", err)
		}
	}

	vm := fleetdb.VM{
		Name:              req.GetName(),
		Platform:          req.GetPlatform(),
		InternalIP:        req.GetInternalIp(),
		ExternalIP:        req.GetExternalIp(),
		CertSerial:        req.GetCertSerial(),
		CurrentGeneration: req.GetCurrentGeneration(),
		MetadataJSON:      md,
	}
	if t := req.GetCertExpiresAt(); t != nil {
		expiry := t.AsTime()
		vm.CertExpiresAt = &expiry
	}

	id, err := s.DB.UpsertVM(ctx, vm)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "upsert vm: %v", err)
	}

	// Log the enrollment event for the transparency log.
	details := fmt.Sprintf(`{"platform":%q,"internal_ip":%q}`, req.GetPlatform(), req.GetInternalIp())
	if _, err := s.DB.InsertEvent(ctx, "enrollment", &id, details); err != nil {
		// Don't fail the enrollment if the log write fails; just note it.
		// Production should alert on this.
		_ = err
	}

	return &fleetpb.EnrollResponse{
		Id:      id,
		Message: "enrolled",
	}, nil
}

// Heartbeat updates last_heartbeat for the named VM.
func (s *Server) Heartbeat(ctx context.Context, req *fleetpb.HeartbeatRequest) (*fleetpb.HeartbeatResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	n, err := s.DB.UpdateHeartbeat(ctx, req.GetName(), req.GetCurrentGeneration())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "update heartbeat: %v", err)
	}
	if n == 0 {
		return nil, status.Errorf(codes.NotFound, "vm %q not enrolled", req.GetName())
	}
	return &fleetpb.HeartbeatResponse{}, nil
}

// ListVMs returns a paginated list of VMs.
func (s *Server) ListVMs(ctx context.Context, req *fleetpb.ListVMsRequest) (*fleetpb.ListVMsResponse, error) {
	vms, total, err := s.DB.ListVMs(ctx, req.GetPlatform(), req.GetAttestationStatus(),
		req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list vms: %v", err)
	}

	pageSize := req.GetPageSize()
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = 100
	}
	var next int32
	if int32(len(vms)) == pageSize {
		next = req.GetPageToken() + pageSize
	}

	resp := &fleetpb.ListVMsResponse{
		NextPageToken: next,
		Total:         total,
	}
	for _, v := range vms {
		resp.Vms = append(resp.Vms, vmToProto(v))
	}
	return resp, nil
}

// GetVM fetches one VM by name or id.
func (s *Server) GetVM(ctx context.Context, req *fleetpb.GetVMRequest) (*fleetpb.VM, error) {
	var v *fleetdb.VM
	var err error
	switch id := req.GetId().(type) {
	case *fleetpb.GetVMRequest_Name:
		v, err = s.DB.GetVMByName(ctx, id.Name)
	case *fleetpb.GetVMRequest_VmId:
		v, err = s.DB.GetVMByID(ctx, id.VmId)
	default:
		return nil, status.Error(codes.InvalidArgument, "must provide name or vm_id")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "vm not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get vm: %v", err)
	}
	return vmToProto(*v), nil
}

// vmToProto converts a DB VM to its protobuf representation.
func vmToProto(v fleetdb.VM) *fleetpb.VM {
	pv := &fleetpb.VM{
		Id:                v.ID,
		Name:              v.Name,
		Platform:          v.Platform,
		InternalIp:        v.InternalIP,
		ExternalIp:        v.ExternalIP,
		EnrolledAt:        timestamppb.New(v.EnrolledAt),
		CertSerial:        v.CertSerial,
		AttestationStatus: v.AttestationStatus,
		CurrentGeneration: v.CurrentGeneration,
		MetadataJson:      v.MetadataJSON,
	}
	if v.CertExpiresAt != nil {
		pv.CertExpiresAt = timestamppb.New(*v.CertExpiresAt)
	}
	if v.LastHeartbeat != nil {
		pv.LastHeartbeat = timestamppb.New(*v.LastHeartbeat)
	}
	if v.LastAttestation != nil {
		pv.LastAttestation = timestamppb.New(*v.LastAttestation)
	}
	return pv
}
