package sign

import (
	"context"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sinkap/pancake/common/gen/go/signpb"
)

// RemoteSigner talks to a pancake-sign service over gRPC. The build
// server holds no signing key; every signature crosses a process
// boundary so the key only ever lives in pancake-sign's process
// memory + its mounted volume.
//
// Target example: "pancake-sign:7880" (compose-internal hostname).
// Production deployments should add transport credentials; the v1
// in-compose use is plaintext on a private docker network.
//
// UKIs hit ~20-50MB, so the client raises grpc max-recv to 128MB —
// enough headroom for a few revisions without revisiting.
type RemoteSigner struct {
	// Target is the gRPC dial target (host:port). Accepts a legacy
	// "http://host:port" URL too — the scheme is stripped.
	Target string

	once   sync.Once
	conn   *grpc.ClientConn
	client signpb.PancakeSignerServiceClient
	dialErr error
}

const maxSignMsgBytes = 128 * 1024 * 1024 // 128MB; covers all current UKIs.

func (s *RemoteSigner) dial() (signpb.PancakeSignerServiceClient, error) {
	s.once.Do(func() {
		target := s.Target
		// Legacy compat: accept "http://host:port" and strip the
		// scheme. Build server flag was --signer-url=http://... for
		// a long time; this saves operators a config edit.
		for _, prefix := range []string{"http://", "https://", "grpc://"} {
			if len(target) > len(prefix) && target[:len(prefix)] == prefix {
				target = target[len(prefix):]
				break
			}
		}
		if target == "" {
			s.dialErr = fmt.Errorf("RemoteSigner: Target is empty")
			return
		}
		conn, err := grpc.NewClient(target,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallSendMsgSize(maxSignMsgBytes),
				grpc.MaxCallRecvMsgSize(maxSignMsgBytes),
			),
		)
		if err != nil {
			s.dialErr = fmt.Errorf("dial pancake-sign %s: %w", target, err)
			return
		}
		s.conn = conn
		s.client = signpb.NewPancakeSignerServiceClient(conn)
	})
	return s.client, s.dialErr
}

func (s *RemoteSigner) SignUKI(ctx context.Context, unsigned []byte) ([]byte, error) {
	cli, err := s.dial()
	if err != nil {
		return nil, err
	}
	resp, err := cli.SignUKI(ctx, &signpb.SignUKIRequest{UnsignedPe: unsigned})
	if err != nil {
		return nil, fmt.Errorf("SignUKI: %w", err)
	}
	return resp.SignedPe, nil
}

func (s *RemoteSigner) SignManifest(ctx context.Context, manifest []byte) ([]byte, error) {
	cli, err := s.dial()
	if err != nil {
		return nil, err
	}
	resp, err := cli.SignManifest(ctx, &signpb.SignManifestRequest{Manifest: manifest})
	if err != nil {
		return nil, fmt.Errorf("SignManifest: %w", err)
	}
	return resp.Signature, nil
}

func (s *RemoteSigner) Cert(ctx context.Context) ([]byte, error) {
	cli, err := s.dial()
	if err != nil {
		return nil, err
	}
	resp, err := cli.GetSigningCert(ctx, &signpb.GetSigningCertRequest{})
	if err != nil {
		return nil, fmt.Errorf("GetSigningCert: %w", err)
	}
	return resp.CertPem, nil
}
