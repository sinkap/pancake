# pancake-fleet-server: HTTP + gRPC fleet orchestrator with PostgreSQL backend.
#
# Multi-stage build:
#   1. builder: compile static Go binary
#   2. runtime: distroless base for tiny image

FROM golang:1.25-bookworm AS builder

WORKDIR /src

# Copy module manifest first so dependency download is cached
COPY tools/pancake-go/go.mod tools/pancake-go/go.sum ./tools/pancake-go/
WORKDIR /src/tools/pancake-go
RUN go mod download

# Now copy source
WORKDIR /src
COPY tools/pancake-go ./tools/pancake-go

# Build statically; CGO not needed (pgx is pure Go)
WORKDIR /src/tools/pancake-go
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" \
    -o /out/pancake-fleet-server \
    ./fleet-server/cmd/pancake-fleet-server

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/pancake-fleet-server /usr/local/bin/pancake-fleet-server

USER nonroot:nonroot

EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/pancake-fleet-server"]
