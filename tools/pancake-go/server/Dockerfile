# pancake-build-server: container image for the build server. Layer
# cache lives at /var/lib/pancake-build-server — mount a host volume
# (or named volume) there to keep artifacts across container restarts.
#
# Build (context = REPO ROOT, not tools/pancake-go/):
#   docker build -f tools/pancake-go/server/Dockerfile -t pancake-build-server .
#
# This wider context lets the image bake in the canonical pancake +
# pancaked + mount-overlay + pivot-root binaries (under
# /usr/local/share/pancake-bundled/) so recipes that don't get
# operator-uploaded override blobs can fall back to known-good
# versions shipped with the build server image.
#
# The compose.yaml in tools/pancake-go/ uses the right context;
# manual `docker build` invocations need to be from the repo root.
#
# Run with named volume:
#   docker volume create pancake-build-cache
#   docker run -d --name pancake-build-server \
#       --privileged \
#       -p 7879:7879 \
#       -v pancake-build-cache:/var/lib/pancake-build-server \
#       pancake-build-server
#
# Why --privileged: mmdebstrap performs chroot + bind-mount, which
# need CAP_SYS_ADMIN. veritysetup also wants device-mapper.

# ----- stage 1: build all the Go + C binaries ----------------------
FROM golang:1.25-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/tools/pancake-go
COPY tools/pancake-go/go.mod tools/pancake-go/go.sum ./
RUN go mod download
COPY tools/pancake-go ./
RUN CGO_ENABLED=0 go build -ldflags='-s -w' -o /out/pancake-build-server ./server/cmd
RUN CGO_ENABLED=0 go build -ldflags='-s -w' -o /out/pancake          ./cmd/pancake
RUN CGO_ENABLED=0 go build -ldflags='-s -w' -o /out/pancaked         ./daemon/pancaked

# C helpers — sourced from the wider repo context.
WORKDIR /src
COPY initramfs/mount-overlay.c ./mount-overlay.c
COPY pivot-root.c ./pivot-root.c
RUN gcc -O2 -Wall -Wextra -static -o /out/mount-overlay ./mount-overlay.c
RUN gcc -O2 -Wall -Wextra -static -o /out/pivot-root    ./pivot-root.c

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
#   openssh-client    — ssh-keygen for fresh host-key fallback in pancake-host recipe
#   tar               — modules tarball extraction in pancake-modules recipe
RUN apt-get update && apt-get install -y --no-install-recommends \
        mmdebstrap \
        e2fsprogs \
        squashfs-tools \
        cryptsetup-bin \
        dpkg \
        sudo \
        openssh-client \
        tar \
        kmod \
        cpio \
        gzip \
        systemd-ukify \
        sbsigntool \
        binutils \
        gdisk \
        dosfstools \
        mtools \
        systemd-boot-efi \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/pancake-build-server /usr/local/bin/pancake-build-server

# Bundled binaries the recipe handlers fall back to when the operator
# doesn't UploadBlob an override. Path matches server's
# --bundled-bins-dir default.
RUN mkdir -p /usr/local/share/pancake-bundled
COPY --from=builder /out/pancake          /usr/local/share/pancake-bundled/pancake
COPY --from=builder /out/pancaked         /usr/local/share/pancake-bundled/pancaked
COPY --from=builder /out/mount-overlay    /usr/local/share/pancake-bundled/mount-overlay
COPY --from=builder /out/pivot-root       /usr/local/share/pancake-bundled/pivot-root

# initramfs entrypoint script (sh + openssl + tpm2-tools). Server
# stages this into every initramfs it builds via build_image.go;
# operators can't override this v1.
COPY initramfs/init                       /usr/local/share/pancake-bundled/init

# Cache lives here; mount a host volume to persist.
RUN mkdir -p /var/lib/pancake-build-server
VOLUME /var/lib/pancake-build-server

EXPOSE 7879

ENTRYPOINT ["/usr/local/bin/pancake-build-server"]
CMD ["-listen=:7879", "-cache=/var/lib/pancake-build-server"]
