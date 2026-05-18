#!/usr/bin/env bash
# Regenerate Go gRPC stubs for every service proto.
#
# Run from the repo root. Generated files land in common/gen/go/<pkg>/.
# The `--go_opt=module=...` flag strips the module prefix from each
# proto's go_package, so the file lands at the path relative to the
# repo root.
#
# Requires protoc + protoc-gen-go + protoc-gen-go-grpc.
#
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
#   apt install protobuf-compiler

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

protoc -I common/protos \
  --go_out=. --go_opt=module=github.com/sinkap/pancake \
  --go-grpc_out=. --go-grpc_opt=module=github.com/sinkap/pancake \
  common/protos/pancake.proto \
  common/protos/build.proto \
  common/protos/fleet.proto \
  common/protos/sign.proto

echo "regenerated: common/gen/go/{pancakepb,buildpb,fleetpb,signpb}/"
