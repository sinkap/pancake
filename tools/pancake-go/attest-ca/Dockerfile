# pancake-attest-ca: TPM 2.0 Attestation CA daemon, in a container.
#
# Build (context = tools/pancake-go/):
#   docker build -f attest-ca/Dockerfile -t pancake-attest-ca tools/pancake-go/
#
# Run with named volume (so the AK-CA root key persists):
#   docker volume create pancake-attest-ca-state
#   docker run -d --name pancake-attest-ca \
#       -p 8444:8444 \
#       -v pancake-attest-ca-state:/home/attestca \
#       pancake-attest-ca
#
# Endpoints:
#   :8444/attest    POST  TPM AK enrollment kickoff
#   :8444/secret    POST  TPM AK enrollment finalize  → AK cert chain
#   :8444/health    GET   liveness
#   :8444/root.crt  GET   AK-CA root cert (the bytes step-ca trusts
#                         in its ACME-tpm provisioner's attestationRoots)

# Build the Go binary in a multi-stage build to keep the final image
# small. Pancake-go's go.mod lives at the build context root.
FROM golang:1.25-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags='-s -w' \
    -o /out/pancake-attest-ca ./attest-ca/cmd

FROM alpine:3.21
RUN addgroup -g 65532 attestca && adduser -D -u 65532 -G attestca attestca && \
    mkdir -p /home/attestca && chown attestca:attestca /home/attestca
COPY --from=builder /out/pancake-attest-ca /usr/local/bin/pancake-attest-ca
USER attestca
WORKDIR /home/attestca

EXPOSE 8444
VOLUME /home/attestca

ENTRYPOINT ["/usr/local/bin/pancake-attest-ca"]
