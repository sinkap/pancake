# pancake-sign — owns the code-signing leaf cert + private key.
# Build server delegates UKI + manifest signing here; the key never
# leaves this container's process memory + mounted volume.
#
# Build (context = REPO ROOT):
#   docker build -f tools/pancake-go/sign-server/Dockerfile -t pancake-sign .
#
# Run (compose handles this — see ../compose.yaml):
#   docker run -d --name pancake-sign \
#       -p 7880:7880 \
#       -v pancake-sign-state:/var/lib/pancake-sign \
#       pancake-sign

# ----- stage 1: Go build -------------------------------------------
FROM golang:1.25-bookworm AS builder
WORKDIR /src/tools/pancake-go
COPY tools/pancake-go/go.mod tools/pancake-go/go.sum ./
RUN go mod download
COPY tools/pancake-go ./
RUN CGO_ENABLED=0 go build -ldflags='-s -w' -o /out/pancake-sign ./sign-server/cmd

# ----- stage 2: runtime --------------------------------------------
FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive

# sbsigntool: the SignUKI op shells out to sbsign(1).
RUN apt-get update && apt-get install -y --no-install-recommends \
        sbsigntool \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/pancake-sign /usr/local/bin/pancake-sign

RUN mkdir -p /var/lib/pancake-sign
VOLUME /var/lib/pancake-sign

EXPOSE 7880

ENTRYPOINT ["/usr/local/bin/pancake-sign"]
CMD ["-listen=:7880", \
     "-key=/var/lib/pancake-sign/sign.key", \
     "-cert=/var/lib/pancake-sign/sign.crt"]
