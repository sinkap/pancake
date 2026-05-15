# pancake-ahkcid: TPM 2.0 Attestation CA daemon, in a container.
#
# Build (context = tools/pancake-go/):
#   docker build -f ahkcid/Dockerfile -t pancake-ahkcid tools/pancake-go/
#
# Run with named volume (so the AK-CA root key persists):
#   docker volume create pancake-ahkcid-state
#   docker run -d --name pancake-ahkcid \
#       -p 8444:8444 \
#       -v pancake-ahkcid-state:/home/ahkcid \
#       pancake-ahkcid
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
    -o /out/pancake-ahkcid ./ahkcid/cmd

FROM alpine:3.21
RUN addgroup -g 65532 ahkcid && adduser -D -u 65532 -G ahkcid ahkcid && \
    mkdir -p /home/ahkcid && chown ahkcid:ahkcid /home/ahkcid
COPY --from=builder /out/pancake-ahkcid /usr/local/bin/pancake-ahkcid
USER ahkcid
WORKDIR /home/ahkcid

EXPOSE 8444
VOLUME /home/ahkcid

ENTRYPOINT ["/usr/local/bin/pancake-ahkcid"]
