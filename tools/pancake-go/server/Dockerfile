# pancake-build-server: container image for the build server. Layer
# cache lives at /var/lib/pancake-build-server — mount a host volume
# (or named volume) there to keep artifacts across container restarts.
#
# Build (context = tools/pancake-go/):
#   docker build -f server/Dockerfile -t pancake-build-server tools/pancake-go/
#
# Run with named volume:
#   docker volume create pancake-build-cache
#   docker run -d --name pancake-build-server \
#       --privileged \
#       -p 7879:7879 \
#       -v pancake-build-cache:/var/lib/pancake-build-server \
#       pancake-build-server
#
# Or a host bind-mount (so cache survives `docker rm -v`):
#   docker run -d --name pancake-build-server \
#       --privileged \
#       -p 7879:7879 \
#       -v /srv/pancake-build-cache:/var/lib/pancake-build-server \
#       pancake-build-server
#
# Why --privileged: mmdebstrap performs chroot + bind-mount, which
# need CAP_SYS_ADMIN. veritysetup also wants device-mapper. Default
# Docker capabilities are too restrictive. If you'd rather scope
# tightly: --cap-add SYS_ADMIN --device /dev/loop-control --device
# /dev/mapper/control plus --security-opt apparmor=unconfined and a
# tmpfs at /tmp may suffice; --privileged is the easy button.
#
# Health: the server logs "[pancake-build-server] listening on :7879"
# at start. Until LookupLayer / a healthcheck RPC exist, do `nc -z
# host 7879` for a basic up-check.

# ----- stage 1: build the Go binary --------------------------------
FROM golang:1.25-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags='-s -w' \
        -o /out/pancake-build-server ./server/cmd

# ----- stage 2: runtime --------------------------------------------
FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive

# System tools the build path shells out to. Kept minimal — anything
# not in this list will fail loudly at first BuildGeneration call.
#   mmdebstrap        — sandbox bootstrapper (the heavy lift)
#   e2fsprogs         — mkfs.ext4 (per-layer image format)
#   cryptsetup-bin    — veritysetup (per-layer dm-verity hash tree)
#   dpkg              — dpkg-query (already in ubuntu base, listed for clarity)
#   sudo              — runner.Sudo wrappers in internal/runner
#   tar, coreutils, util-linux — staging + ownership ops (in base)
RUN apt-get update && apt-get install -y --no-install-recommends \
        mmdebstrap \
        e2fsprogs \
        cryptsetup-bin \
        dpkg \
        sudo \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/pancake-build-server /usr/local/bin/pancake-build-server

# Cache lives here; mount a host volume to persist.
RUN mkdir -p /var/lib/pancake-build-server
VOLUME /var/lib/pancake-build-server

EXPOSE 7879

ENTRYPOINT ["/usr/local/bin/pancake-build-server"]
CMD ["-listen=:7879", "-cache=/var/lib/pancake-build-server"]
