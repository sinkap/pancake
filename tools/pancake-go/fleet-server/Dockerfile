# pancake-fleet-server: HTTP + gRPC fleet orchestrator + bundled SvelteKit UI.
#
# Multi-stage build:
#   1. ui-builder:  compile the SvelteKit project to static assets
#   2. go-builder:  compile static Go binary
#   3. runtime:     distroless base; ships binary + pre-built UI
#
# The runtime image places the UI bundle at /var/lib/pancake-fleet-ui.
# Compose / k8s should pass -web-ui /var/lib/pancake-fleet-ui to serve it.

FROM node:22-alpine AS ui-builder

WORKDIR /ui

# Cache dependencies separately from source
COPY tools/pancake-go/web-ui/package.json tools/pancake-go/web-ui/package-lock.json ./
RUN npm ci

COPY tools/pancake-go/web-ui ./
RUN npm run build

# -----------------------------------------------------------------------------
FROM golang:1.25-bookworm AS go-builder

WORKDIR /src

COPY tools/pancake-go/go.mod tools/pancake-go/go.sum ./tools/pancake-go/
WORKDIR /src/tools/pancake-go
RUN go mod download

WORKDIR /src
COPY tools/pancake-go ./tools/pancake-go

WORKDIR /src/tools/pancake-go
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" \
    -o /out/pancake-fleet-server \
    ./fleet-server/cmd/pancake-fleet-server

# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=go-builder /out/pancake-fleet-server /usr/local/bin/pancake-fleet-server
COPY --from=ui-builder /ui/build /var/lib/pancake-fleet-ui

USER nonroot:nonroot

EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/pancake-fleet-server"]
