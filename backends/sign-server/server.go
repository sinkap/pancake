// Package signsrv implements the PancakeSignerService gRPC server.
package signsrv

import (
	"context"

	"github.com/sinkap/pancake/common/gen/go/signpb"
	"github.com/sinkap/pancake/common/go/sign"
)

// Server wraps a sign.Signer and exposes it as PancakeSignerService.
type Server struct {
	signpb.UnimplementedPancakeSignerServiceServer
	signer sign.Signer
}

func New(signer sign.Signer) *Server {
	return &Server{signer: signer}
}

func (s *Server) SignUKI(ctx context.Context, req *signpb.SignUKIRequest) (*signpb.SignUKIResponse, error) {
	signed, err := s.signer.SignUKI(ctx, req.GetUnsignedPe())
	if err != nil {
		return nil, err
	}
	return &signpb.SignUKIResponse{SignedPe: signed}, nil
}

func (s *Server) SignManifest(ctx context.Context, req *signpb.SignManifestRequest) (*signpb.SignManifestResponse, error) {
	sig, err := s.signer.SignManifest(ctx, req.GetManifest())
	if err != nil {
		return nil, err
	}
	return &signpb.SignManifestResponse{Signature: sig}, nil
}

func (s *Server) GetSigningCert(ctx context.Context, _ *signpb.GetSigningCertRequest) (*signpb.GetSigningCertResponse, error) {
	cert, err := s.signer.Cert(ctx)
	if err != nil {
		return nil, err
	}
	return &signpb.GetSigningCertResponse{CertPem: cert}, nil
}
