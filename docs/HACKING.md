# Hacking on the pancake codebase

## Layout

```
.
├── cli/pancake/            # the CLI binary
├── backends/
│   ├── build-server/       # pancake-build-server (gRPC, port 7879)
│   ├── fleet-server/       # pancake-fleet-server (gRPC :8081 + HTTP :8082)
│   ├── sign-server/        # pancake-sign (HTTP today; gRPC after Phase 9)
│   └── pancaked/           # in-VM gRPC daemon
├── common/
│   ├── protos/             # source-of-truth .proto files
│   ├── gen/go/             # generated Go gRPC stubs (committed)
│   │   └── {pancakepb,buildpb,fleetpb}/
│   └── go/                 # shared Go libraries (was internal/)
├── frontend/               # SvelteKit web UI (read-only fleet dashboard)
├── tools/                  # low-level helpers (not Go services)
│   ├── initramfs/{init,mount-overlay.c}
│   └── pivot-root/pivot-root.c
├── deployment/
│   ├── docker/             # all Dockerfiles + compose files
│   ├── terraform/          # GCP/GKE infra
│   └── k8s/                # K8s manifests
├── docs/                   # this directory
├── scripts/                # build/dev helpers (smoketest, proto-gen, ops scripts)
└── examples/               # sample recipes
```

Single Go module at the repo root: `github.com/sinkap/pancake`.

## Building

Single binary the operator runs:

```
go install ./cli/pancake
```

Everything else (build server, sign service, ca-server, fleet server)
ships as containers via `compose.yaml`:

```
docker compose up -d --build       # uses repo-root shim that includes
                                   # deployment/docker/compose.yaml
```

## Local-dev regression test (run before bootstrap-touching commits)

The fast-feedback unit test for `bootstrap_builder`'s request shaping
runs in CI:

```
go test ./cli/pancake/...
```

The full end-to-end smoke test wraps the local docker compose stack
+ a real `pancake bootstrap` run + artifact assertions. It needs
sudo on the host (for mksquashfs / veritysetup) and a kernel tree
referenced by `pancake-recipe.yaml`. Operator-driven; not in CI:

```
./scripts/smoketest-local.sh
```

Pass it before any commit that touches:
- `cli/pancake/`
- `backends/build-server/{build_image,buildimage_handler,gcs_upload}.go`
- `common/go/layer/`, `common/go/initramfs/`, `tools/initramfs/init`
- `common/protos/build.proto` (regen + smoke)

If you bumped layer format (e.g. switched compression), wipe the
cache first so the assertion checks against fresh layers:

```
docker volume rm docker_pancake-build-cache   # or whatever compose names it
```

## Regenerating protobuf bindings

The committed `*.pb.go` and `*_grpc.pb.go` files under
`common/gen/go/{pancakepb,buildpb,fleetpb}/` are generated artifacts.
After editing `common/protos/*.proto`, regenerate them.

Prerequisites (one-time):

```
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
# protoc itself: apt install protobuf-compiler  (Ubuntu/Debian)
```

Regenerate from the repo root:

```
./scripts/proto-gen.sh
```

After regen, `go build ./...` should pass.

## Service-name conventions

All gRPC services use the symmetric `Pancake<Role>Service` naming
pattern (`PancakeAgentService` on each VM, `PancakeBuilderService`
on the build server, `PancakeFleetService` on the fleet server,
`PancakeSignerService` on the sign server). Generated clients are
`pancakepb.NewPancakeAgentServiceClient(conn)`, etc.

## Running the build server locally

```
docker compose up -d --build pancake-build-server
```

The server bundles `pancake`, `pancaked`, `mount-overlay`,
`pivot-root`, and `tools/initramfs/init` into
`/usr/local/share/pancake-bundled/` so recipes that don't get
operator-uploaded override blobs can use those.

Cache lives in the named volume `pancake-build-cache`. Wipe with
`docker compose down -v`.
