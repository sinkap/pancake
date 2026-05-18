# Hacking on the pancake Go tools

## Layout

```
tools/pancake-go/
  cmd/pancake/             # the CLI
  daemon/pancaked/         # in-VM gRPC daemon
  server/                  # pancake-build-server (gRPC)
    cmd/                   # entrypoint
    *.go                   # service impls
    Dockerfile
  attest-ca/                  # TPM AK Attestation CA service
  ca-server/               # step-ca wrapper (Dockerfile + init.sh only)
  sign-server/             # pancake-sign service (Phase 5)
  internal/
    buildpb/               # build server gRPC proto + generated bindings
    orchpb/                # orchestrator gRPC proto + generated bindings
    sign/                  # signing primitives + Signer interface
    efi/, initramfs/, pack/, kit/, layer/, deb/, runner/, ...
```

## Building

Single binary the operator runs:

```
go install ./cmd/pancake
```

Everything else (build server, attest-ca, sign service, ca-server) ships
as containers via `compose.yaml`:

```
docker compose up -d --build
```

## Local-dev regression test (run before bootstrap-touching commits)

The fast-feedback unit test for `bootstrap_builder`'s request shaping
runs in CI:

```
go test ./cmd/pancake/...
```

The full end-to-end smoke test wraps the local docker compose stack
+ a real `pancake bootstrap` run + artifact assertions. It needs
sudo on the host (for mksquashfs / veritysetup) and a kernel tree
referenced by `pancake-recipe.yaml`. Operator-driven; not in CI:

```
./scripts/smoketest-local.sh
```

Pass it before any commit that touches:
- `cmd/pancake/`
- `server/{build_image,buildimage_handler,gcs_upload}.go`
- `internal/layer/`, `internal/initramfs/`, `initramfs/init`
- `internal/buildpb/build.proto` (regen + smoke)

If you bumped layer format (e.g. switched compression), wipe the
cache first so the assertion checks against fresh layers:

```
docker volume rm pancake-go_pancake-build-cache
```

## Regenerating protobuf bindings

The committed `*.pb.go` and `*_grpc.pb.go` files under
`internal/buildpb/` and `internal/orchpb/` are generated artifacts.
After editing `*.proto` you need to regenerate them.

Prerequisites (one-time):

```
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
# protoc itself: apt install protobuf-compiler  (Ubuntu/Debian)
```

Regenerate from the repo root:

```
protoc -I tools/pancake-go/internal/buildpb \
       --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       tools/pancake-go/internal/buildpb/build.proto

protoc -I tools/pancake-go/internal/orchpb \
       --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       tools/pancake-go/internal/orchpb/pancake.proto
```

After regen, `go build ./...` should pass.

### When a regen is required

Phases that touch the `*.proto` files (and therefore require regen
before the rest of the change set compiles):

- **Phase 4** — `build.proto` gained the `BuildImage` RPC plus
  `BuildImageRequest` and `BuildImageChunk` messages. The Go-side
  helper `Server.AssembleImage` (`server/build_image.go`) is
  reachable today as a Server method; the gRPC handler that wraps
  it is one stub away after regen:

  ```go
  func (s *Server) BuildImage(
      req *buildpb.BuildImageRequest,
      stream buildpb.PancakeBuilder_BuildImageServer,
  ) error {
      // Translate proto → Go request, call AssembleImage,
      // stream BuildImageChunk{} per artifact field.
  }
  ```

  Phase 6's thin client also depends on `BuildImage` existing on
  the wire.

## Running the build server locally

```
cd tools/pancake-go
docker compose up -d --build pancake-build-server
```

The server bundles `pancake`, `pancaked`, `mount-overlay`,
`pivot-root`, and `initramfs/init` into
`/usr/local/share/pancake-bundled/` so recipes that don't get
operator-uploaded override blobs can use those.

Cache lives in the named volume `pancake-build-cache`. Wipe with
`docker compose down -v`.
