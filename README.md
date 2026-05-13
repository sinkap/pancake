# pancake / pancake-os

A Debian-derived OS where every package is its own dm-verity image and the
rootfs is reassembled atomically via `pivot_root(2)`.

```
                            ┌──────────────────────────────────┐
                            │  upperdir  (tmpfs, ephemeral)    │  writes
                            ├──────────────────────────────────┤
                       /    │  nano                            │  ← layered
                   overlay  ├──────────────────────────────────┤
                            │  openssh-server                  │
                            ├──────────────────────────────────┤
                            │  systemd                         │
                            ├──────────────────────────────────┤
                            │  libc6                           │
                            ├──────────────────────────────────┤
                            │  ... ~140 .deb-derived layers    │
                            ╞══════════════════════════════════╡
                            │  nullfs    (immutable, empty)    │  real rootfs
                            └──────────────────────────────────┘
```

Built on Christian Brauner's vfs work (lands in Linux 7.2): the immutable
`nullfs` rootfs gives `/` a real parent, making `pivot_root(2)` legal on a
running multi-process system. `pivot_root` then calls `chroot_fs_refs()`
in-kernel, which atomically rebases every running task's `fs.root` to the
new tree. systemd and every daemon keep running and immediately see the new
content. No reboot, no systemd cooperation, no per-daemon hooks.

## Layout

```
pancake/
├── pivot-root.c              the kernel-syscall helper for the live swap
├── slides.md                 walkthrough deck (Marp markdown)
├── DESIGN.md                 architecture + manifest schema + workflows
│
├── tools/pancake-go/         Go module
│   ├── cmd/pancake/              the operator CLI
│   ├── daemon/pancaked/          in-VM agent daemon
│   ├── server/                   build server (lib + cmd/main.go + Dockerfile)
│   └── internal/                 buildpb, orchpb, orchsrv, deb, kit, layer, ...
│
└── initramfs/                manifest-driven /init
    ├── init                      reads /var/lib/pancake/current/lowers,
    │                             opens verity for each layer, mounts
    │                             overlay via fsconfig, switch_root
    └── mount-overlay.c           fsopen + N × fsconfig(lowerdir+) + fsmount
                                  — bypasses mount(2)'s 4 KiB option-string
                                  cap (essential for 100+ lowerdirs)
```

## Required kernel

`bpf-next/for-next` or any tree containing Brauner's series:

| Commit | What |
|--------|------|
| `576ee5dfd459` | `fs: add immutable rootfs` (nullfs) |
| `313c47f4fe4d` | `fs: use nullfs unconditionally as the real rootfs` |
| `3c1b73fc6a4d` | `fs: add init_pivot_root()` |
| `ccfac16e0be5` | `move_mount: allow MOVE_MOUNT_BENEATH on the rootfs` |
| `c62a4766937e` | `move_mount: transfer MNT_LOCKED` |

Lands in Linux 7.2.

## Quick start

### TL;DR — one-shot demo

```sh
demo/demo.sh --bzimage=/path/to/bpf-next/arch/x86/boot/bzImage
```

Builds binaries → builds + starts the build-server container with a
named cache volume → bootstraps a signed UEFI kit → boots it under
OVMF + swtpm → runs `pancake enroll` inside the VM → runs `pancake
attest` from the host (5 checks). Idempotent — re-running tears down
prior state. ~3 min cold, <30 s on cache hit.

Requirements: `docker`, `qemu-system-x86_64`, OVMF firmware, `swtpm`,
`tpm2-tools`, `nc`, `go`.

### 0. Build the binaries (one-time per checkout)

The Go module produces three statically-linked binaries:

```sh
cd tools/pancake-go
go build -ldflags="-s -w" -o bin/pancake              ./cmd/pancake
go build -ldflags="-s -w" -o bin/pancaked             ./daemon/pancaked
go build -ldflags="-s -w" -o bin/pancake-build-server ./server/cmd
```

| Binary | Where it runs | What it does |
|---|---|---|
| `pancake` | build host + inside the VM | the CLI: `bootstrap`, `list`, `show`, `install`, `swap`, `rollback`, `enroll`, `orchestrate`, `build` |
| `pancaked` | inside each pancake-os VM | gRPC agent; receives signed manifests from the orchestrator and applies them |
| `pancake-build-server` | a persistent build host (e.g. a containerized service) | gRPC builder; runs `mmdebstrap` + per-package layer construction once, caches by roothash, serves cached artifacts over `GetLayer` |

Tree layout, for orientation:

```
tools/pancake-go/
├── cmd/pancake/             # the operator CLI
├── daemon/pancaked/         # in-VM agent daemon
├── server/                  # build server: lib in package "server"
│   ├── server.go, build.go, stream.go, filters.go
│   ├── cmd/main.go          #   server binary entry point
│   └── Dockerfile           #   container image with persistent cache volume
└── internal/
    ├── buildpb/             # build server gRPC schema + recipe catalog
    ├── orchpb/              # orchestrator/agent gRPC schema
    ├── orchsrv/             # in-VM agent's RPC handlers
    └── ... (deb, kit, layer, runner, sign, ...)
```

### 0b. Run the build server (recommended)

The build server centralizes the heavy work — `mmdebstrap`, per-package
verity layer construction, `mkfs.ext4` / `veritysetup` — and caches every
built layer keyed by roothash. Clients (`pancake bootstrap` on the build
host, `pancake install/update` inside a VM) call into it over gRPC and
download canonical bytes instead of rebuilding.

**Easiest: run the server in Docker** with a persistent host volume so
the layer cache survives container restarts:

```sh
docker build -f tools/pancake-go/server/Dockerfile \
             -t pancake-build-server tools/pancake-go/

docker volume create pancake-build-cache       # or use a host bind mount
docker run -d --name pancake-build-server \
    --privileged \
    -p 7879:7879 \
    -v pancake-build-cache:/var/lib/pancake-build-server \
    pancake-build-server
```

`--privileged` is required because `mmdebstrap` does chroot + bind-mount
and `veritysetup` uses device-mapper. (Tightly-scoped capability sets
work too — see the Dockerfile header.)

**Or run directly on a host** with the right tools installed
(`mmdebstrap`, `e2fsprogs`, `cryptsetup-bin`, `dpkg`, `sudo`):

```sh
sudo ./tools/pancake-go/bin/pancake-build-server \
    -listen=:7879 \
    -cache=/var/lib/pancake-build-server
```

The server logs `[pancake-build-server] listening on :7879, cache=…` on
start. Until a healthcheck RPC exists, `nc -z host 7879` is the basic
up-check.

### 1. Build a kit + disk image + initramfs in one command

The clean way is a TOML recipe — one file instead of 21 flags. Save as
`./pancake-recipe.toml` and `sudo pancake bootstrap` picks it up
automatically; otherwise pass the path positionally.

```toml
# ./pancake-recipe.toml
output   = "/var/tmp/pancake-kit"
hostname = "pancake"
packages = ["openssh-server", "chrony", "nano"]

[distro]
suite = "noble"

[ssh]
authorized-keys = "~/.ssh/authorized_keys"

[kernel]
version = "tree"   # read it out of bzimage; or pin "7.0.0-g..." literally
bzimage = "~/projects/linux-bpf-for-next/arch/x86/boot/bzImage"

[outputs]
image     = "/var/tmp/pancake-state.img"
initramfs = "/var/tmp/pancake-initramfs.cpio.gz"
bzimage   = "/var/tmp/pancake-bzImage"
```

```sh
sudo tools/pancake-go/bin/pancake bootstrap          # uses ./pancake-recipe.toml
sudo tools/pancake-go/bin/pancake bootstrap path/to/other.toml
sudo tools/pancake-go/bin/pancake bootstrap recipe.toml --hostname=other
                                                     # CLI flag wins over recipe
```

CLI flag > recipe value > built-in default. `~` expands to the invoking
user's home (honors `SUDO_USER`, not `/root`). Unknown TOML keys cause
a parse error so typos are caught up front. The full schema is the
package doc on `internal/recipe`.

The equivalent flag-only invocation:

```sh
sudo tools/pancake-go/bin/pancake bootstrap \
    --suite      noble \
    --packages   openssh-server,chrony,nano \
    --output     /var/tmp/pancake-kit \
    --hostname   pancake \
    --src-root   $(pwd) \
    --ssh-authorized-keys ~/.ssh/authorized_keys \
    --image      /var/tmp/pancake-state.img \
    --initramfs  /var/tmp/pancake-initramfs.cpio.gz \
    --kernel     7.0.0-g9f5b3ffc3f1d \
    --bzimage    ~/projects/linux-bpf-for-next/arch/x86/boot/bzImage \
    --bzimage-out /var/tmp/pancake-bzImage
```

**Outputs (all defaults to current directory):**

| flag | default | what it produces |
|---|---|---|
| `--output` | (required) | the kit dir (repo/, generations/, current symlink) |
| `--image` | `./pancake-state.img` | ext4 disk image of the kit, for QEMU `-drive` |
| `--initramfs` | `./pancake-initramfs.cpio.gz` | manifest-driven initramfs, for QEMU `-initrd` |
| `--bzimage-out` | `./pancake-bzImage` | the kernel binary, for QEMU `-kernel` |
| `--efi` | `""` (off) | UEFI-bootable disk image (GPT + ESP + rootfs, systemd-boot + UKI). When set, QEMU needs only OVMF + this image — no `-kernel`/`-initrd`. |
| `--cmdline` | `console=ttyS0 rdinit=/init pancake.state=LABEL=PANCAKE_STATE` | kernel cmdline baked into the UKI for `--efi` |
| `--sign-key` | `""` (off) | PEM RSA private key. When set with `--sign-cert`, signs UKI for Secure Boot AND signs the generation manifest; bakes the cert's pubkey into the initramfs at `/etc/pancake/manifest.pubkey`. |
| `--sign-cert` | `""` (off) | PEM X.509 cert matching `--sign-key`. Both files are auto-generated as a self-signed dev pair if neither exists yet. |

Pass an empty string to skip any one step (e.g. `--image=""`).

**With a build server (faster, deduped fleetwide):** add `--builder=<host:port>`
to delegate `mmdebstrap` + per-package layer construction to a running
`pancake-build-server`. The client still produces `pancake-host`,
`pancake-runtime`, `pancake-kernel`, `pancake-modules` locally (per-host
identity + build-host-specific bytes); everything else streams in via
`GetLayer` from the server cache.

```sh
sudo tools/pancake-go/bin/pancake bootstrap \
    --builder=localhost:7879 \
    pancake-recipe.toml
```

A fresh build is dominated by the server's mmdebstrap (~2-3 minutes for
~150 packages); subsequent runs against the same package set hit the
roothash-keyed cache and finish in seconds.

### Layer landscape

A built kit has these top-of-stack layers in addition to the per-`.deb`
ones:

| Layer | Built by | Contents |
|---|---|---|
| `pancake-host` | client | hostname, ssh keys, `/root/.ssh/authorized_keys`, `sshd_config`, `resolv.conf`, `10-wired.network`, `machine-id` placeholder |
| `pancake-runtime` | client | pancake CLI binary, `mount-overlay`/`pivot-root` C helpers, `pancake-{state-rw,debug}.service` units, the `pancake-defaults` systemd generator that enables networkd at boot |
| `pancake-base` | server | the ~36 cross-cutting baseline files no individual `.deb` owns: `/etc/passwd`/`shadow`/`group`/PAM common-* / `/etc/hosts` / `/etc/profile` / etc. Deterministic from the sorted package set. |
| `pancake-kernel` | client | `/boot/vmlinuz` from a custom `--bzimage` |
| `pancake-modules` | client | `/lib/modules/<ver>/` from the build host |
| `pancaked` | client | the agent daemon binary + systemd unit |

Things deliberately **not** in any verity layer (regenerated per boot
or dropped entirely): `/var/lib/dpkg/`, `/etc/apt/`, `/var/lib/ucf/`,
`/usr/share/{man,info,doc}/`, the `apt`/`dpkg` package payloads (build-only),
`/etc/ld.so.cache` and `/usr/lib/udev/hwdb.bin` (regenerated by
boot-time services in `pancake-runtime`).

### `pancake-host` — the per-host identity layer

Per-host content lives in its own verity layer at `kit/repo/pancake-host/`,
pinned at the top of the overlay stack. It contains exactly:

- `/etc/hostname`
- `/etc/ssh/ssh_host_*_key{,.pub}` (from `[ssh] host-keys-dir`, else
  generated fresh)
- `/root/.ssh/authorized_keys` (from `[ssh] authorized-keys`, optional)

Bootstrap filters these paths out of every other layer (base-files,
openssh-server, pancake-state) via an `isPerHostPath` predicate, so the
shared layers' roothashes are a function of the .deb set and the recipe
only — not of which host you ran bootstrap on. That's the precondition
for an orchestrator shipping one fleetwide manifest while each node
keeps its own pancake-host pinned in place.

### `pancaked` — the update daemon

The receiver side runs as a long-lived daemon, NOT a CLI subcommand.
Bootstrap ships a separate `pancaked` binary inside its own verity
layer (`kit/repo/pancaked/`) along with a systemd unit:

```
[Unit]
After=pancake-state-rw.service
Requires=pancake-state-rw.service
[Service]
ExecStart=/usr/sbin/pancaked --tpm-token=auto
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

The unit's `multi-user.target.wants` symlink ships in the layer too,
so first boot brings the daemon up automatically — no `systemctl
enable` needed. Inspect it with `systemctl status pancaked` like any
other service.

Because the daemon lives in its OWN layer (separate from
pancake-state, pancake-kernel, etc.), pushing a new generation that
swaps in a newer pancaked is a normal manifest update — pancaked
itself becomes a fleet-managed component.

### TPM-sealed daemon auth (PCR 7 + 11)

By default pancaked starts unauthenticated (signature on the manifest
is the integrity floor). For real fleets, bind the daemon's
bearer-token auth to the boot chain so a tampered VM can't accept
updates:

```sh
# in-VM, after first boot:
pancake enroll                              # prints bearer token "abc123…"
                                            # sealed blob at /etc/pancake/orch-token.creds
systemctl restart pancaked                  # daemon picks up the sealed
                                            # token via --tpm-token=auto
```

Subsequent boots into the same kernel/initrd unseal cleanly. If the
boot chain changes (kernel update, initrd swap), PCR 11 differs, the
TPM refuses to release the token, pancaked falls back to refusing
auth (or, if the file exists but unseal fails, refuses to start).
Re-enroll after any deliberate boot-chain change.

The orchestrator side is unchanged — operator passes the plaintext
token via `--token-file`:

```sh
pancake orchestrate push --target VM:7878 --kit ./kit --gen-id N \
    --token-file ~/secrets/vm-orch-token
```

### Remote attestation (`pancake attest`)

`pancaked` provisions a per-boot AK + EK at startup and exposes an
`Attest(nonce, pcrs[])` RPC. On the operator side, `pancake attest`
runs five checks against the response:

```sh
# in-VM (one-time per host; folded into pancake enroll):
pancake enroll        # also writes /etc/pancake/ek.pub

# operator side:
scp root@vm:/etc/pancake/ek.pub ./vm-ek.pub
pancake attest --target=vm:7878 --ek-pub=./vm-ek.pub --kit=./kit --gen=N
```

```
[attest] OK    EK pubkey matches enrolled
[attest] OK    credential activation (AK is in same TPM as enrolled EK)
[attest] OK    quote signature valid (AK signed nonce + PCRs)
[attest] OK    PCR 13 = extend(sha256(manifest.toml))
[attest] OK    PCR 14 = extend(sha256(lowers))
[attest] INFO  PCR 11 firmware-event-log replay (12 firmware entries):
  [34] PCR11 sha256=0da293e3… event=".linux"
  [35] PCR11 sha256=04b7730f… event=".linux"
  [36] PCR11 sha256=3fb9e4e3… event=".osrel"
  [37..] event=".cmdline" .initrd .uname
[attest] OVERALL PASS
```

What each check means:

| Check | What it proves |
|---|---|
| EK pubkey | Same TPM as the one we registered at enroll time |
| Credential activation | Cryptographic AK ↔ EK binding (`tpm2_makecredential` + `tpm2_activatecredential` round-trip) — not just byte-equality |
| Quote signature | The TPM signed (PCRs ‖ nonce) under AK; not replayable |
| PCR 13 | The exact `manifest.toml` we expected this VM to run was loaded by initramfs |
| PCR 14 | The exact lowers TSV (every layer's roothash) was loaded |
| PCR 11 (INFO) | UKI sections loaded by systemd-stub (`.linux`, `.initrd`, `.cmdline`, `.osrel`, `.uname`) — replay the firmware event log to derive the value the UKI alone produces; live PCR 11 typically extends further from userspace (`systemd-pcrextend`), so this is reported as INFO not strict equality |

Tamper a layer → PCR 14 mismatch. Swap kernel → PCR 11 firmware-replay
diverges from what `--kit` claims. Both flagged.

### Push updates: orchestrator → VM via gRPC

`pancake serve` runs inside the VM and exposes a tiny gRPC service
(`internal/orchpb/pancake.proto`) with two RPCs:

- `GetCurrentManifest()` — what the VM is currently set to boot
- `Update(Manifest)` — atomically install a new signed manifest

The orchestrator (any host with the kit + signing materials) calls these
via `pancake orchestrate get-current` and `pancake orchestrate push`.
Only the **signed manifest** crosses the wire — layer files (image.img /
image.hash) live on the VM's disk already, populated either at bootstrap
or by `pancake install`. If the pushed manifest references a layer the
VM doesn't have, Update returns the missing slugs and the operator
ships them out-of-band (TODO: `PushLayer` RPC, deterministic-rebuild
from apt).

Demo on one host (orchestrator on the host, VM in QEMU with port 7878
forwarded):

```sh
# inside the VM:
pancake serve --listen :7878 &

# on the orchestrator host:
pancake orchestrate get-current --target localhost:7878
# → VM is on generation 1 (counter 1, 147 layers)

pancake orchestrate push --target localhost:7878 --kit /var/tmp/kit --gen-id 2
# → installed generation 2 on localhost:7878

# back in the VM:
pancake swap 2     # live-pivot, no reboot
```

The VM's Update handler enforces the same gates as boot: signature must
verify against `/etc/pancake/manifest.pubkey` (baked at bootstrap),
counter must be strictly greater than any local manifest's counter, and
every referenced layer must already be in `kit/repo/`.

### Boot integrity (signing)

When `--sign-key` + `--sign-cert` are passed, three things happen:

1. **UKI signing** via `ukify --secureboot-private-key/--secureboot-certificate` →
   `sbsign`. Resulting UKI is a valid Secure Boot PE binary; UEFI verifies
   against `db` before loading. (To make Secure Boot actually verify in
   QEMU, the cert must be enrolled in OVMF's `db` — covered in DESIGN.md.)
2. **Manifest signing**: `generations/N/manifest.toml.sig` is a raw
   RSA-PKCS1v15-SHA256 signature over the manifest bytes. Verifiable as:
   ```sh
   openssl dgst -sha256 -verify pubkey.pem -signature manifest.toml.sig manifest.toml
   ```
3. **Pubkey baked into initramfs** at `/etc/pancake/manifest.pubkey`. The
   `init` script runs the openssl verify above before opening any verity
   device. A failed signature drops to an emergency shell — the kit owner
   cannot be coerced into mounting a tampered layer set.

The PCR layout (UKI sections measured into PCR 11 by systemd-stub,
manifest hash extended into PCR 13 by `init` if `tpm2_pcrextend` is
present) is documented in DESIGN.md.

### EFI boot (no `-kernel` arg)

When `--efi PATH` is set, bootstrap also writes:

- a Unified Kernel Image (UKI) at `<PATH>.uki.efi` — bzImage + initrd + cmdline as one signable PE binary, built via `systemd-ukify`
- a GPT disk at `PATH` with two partitions:
  - p1: ESP (vfat, ~256 MB) holding `systemd-bootx64.efi` + `/EFI/Linux/pancake-1.efi` (the UKI) + `/loader/loader.conf`
  - p2: ext4 with the kit, label `PANCAKE_STATE`

Boot:

```sh
sudo cp /usr/share/OVMF/OVMF_VARS_4M.fd /var/tmp/OVMF_VARS-pancake.fd
sudo chmod 666 /var/tmp/OVMF_VARS-pancake.fd
sudo qemu-system-x86_64 -enable-kvm -cpu host -m 4G \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=/var/tmp/OVMF_VARS-pancake.fd \
    -drive file=/var/tmp/pancake-efi.img,format=raw,if=virtio \
    -netdev user,id=n,hostfwd=tcp::2222-:22 -device virtio-net,netdev=n \
    -nographic
```

OVMF reads the ESP, loads systemd-boot, autodiscovers the UKI in
`/EFI/Linux/`, jumps to the kernel; initramfs finds `LABEL=PANCAKE_STATE`,
mounts the overlay, switches root. Whole boot chain is one disk file plus
the firmware.

This path is also where the future TPM signing story lands: the UKI is a
single file that `sbsign` / `cosign` can sign, and UEFI Secure Boot
verifies before loading. Each generation can ship its own signed UKI.

**Kernel selection:**

| flag | meaning |
|---|---|
| `--kernel` | VERSION suffix of `/lib/modules/<value>` on the build host. Modules baked into the initramfs come from there. Default: `uname -r`. |
| `--bzimage PATH` | path to a custom-built bzImage. When set, bootstrap **skips `linux-image-generic`** and instead packs two synthetic verity layers: `pancake-kernel` (`/boot/vmlinuz` from PATH) and `pancake-modules` (`/lib/modules/<--kernel>/` from the host). Use this for kernels not in any apt repo (bpf-next, linux-next, your own builds). |

**Without `--bzimage`** the suite's `linux-image-generic` is pulled by
mmdebstrap, which lands as natural `linux-image-X.Y.Z` and
`linux-modules-X.Y.Z` pancake layers (one per .deb).

The bootstrap-side `--kernel` and the binary at `--bzimage` must obviously
be the same kernel version, but the build tools don't enforce that — the
user is responsible for `make modules_install` having matched the
bzImage they're shipping.

### 2. Boot

```sh
# format=raw,readonly=off so `pancake install` / `pancake swap` can write
# back into the kit at runtime.
sudo qemu-system-x86_64 -enable-kvm -cpu host -m 4G -smp 4 \
    -kernel ~/projects/linux-bpf-for-next/arch/x86/boot/bzImage \
    -initrd /var/tmp/pancake-initramfs.cpio.gz \
    -append "console=ttyS0 rdinit=/init pancake.state=SERIAL=pancake-state" \
    -drive file=/var/tmp/pancake-state.img,format=raw,if=none,id=pstate \
    -device virtio-blk,drive=pstate,serial=pancake-state \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \
    -device virtio-net,netdev=net0 \
    -nographic
# → systemd up, multi-user.target reached in ~3 s, ~150 verity layers stacked
```

### 3. Use the `pancake` CLI

The same binary runs on the host (operating on a kit dir on disk) and inside
the booted VM (where it can also do `install` and `swap`).

```sh
# Host side: just inspect the kit
$ tools/pancake-go/bin/pancake --kit /var/tmp/pancake-kit list
generation 1  (initial generation (149 layers))
  layers : 149
  pancake-state           1.0.0
  systemd                 255.4-1ubuntu8
  ...

# Inside the booted VM (ssh -p 2222 root@localhost):

$ pancake history
    id  created                    layers  description
 *   1  2026-05-11T09:56:03+00:00     149  initial generation (149 layers)

$ pancake install vim --activate     # apt resolves deps; each becomes a verity layer
[pancake] apt update + install [vim]
...
[pancake] 12 new packages (after dep resolution)
  → vim 2:9.1.0016-1ubuntu7
  → vim-runtime 2:9.1.0016-1ubuntu7
  ...
[pancake] activated generation 2

$ pancake swap                        # live atomic rootfs replacement, no reboot
[swap] preparing 161 layers (12 new, 0 to retire)
[swap] current → generations/2 (committed)
[step 3] pivot_root(".", "./oldroot")
         this calls chroot_fs_refs internally to update EVERY task fs.root
  pivot_root OK
[swap] live swap complete — running generation 2

$ which vim                           # vim is now usable; uptime didn't change
/usr/bin/vim
$ uptime
 12:02:29 up 3 min,  0 user

$ pancake rollback                    # set current → previous generation (offline);
                                      # next `pancake swap` will pivot back
```

## Architecture cheat sheet

| Concept | Storage / location |
|---|---|
| One package | `kit/repo/<name>-<ver>/image.img` (ext4) + `image.hash` (verity) + `manifest.toml` |
| One installed system snapshot ("generation") | `kit/generations/<n>/manifest.toml` + `lowers` (TSV sidecar) |
| The active snapshot | `kit/current` symlink → `generations/<n>` |
| Boot | initramfs reads `/var/lib/pancake/current/lowers`, verity-opens each layer, mounts overlay via `fsconfig(... lowerdir+ ...)`, `switch_root` |
| Live swap | `pancake install <pkg>` (or `add <foo.deb>`) → builds layer(s) → writes new generation; then `pancake swap` opens new lowers, builds new overlay at `/pancake-newroot`, calls `pivot_root(2)` which calls `chroot_fs_refs()` to atomically rebase every running task's `fs.root` |

See `DESIGN.md` for the full manifest schema and the bootstrap / install /
rollback workflows.

## Slides

```
github.com/sinkap/pancake/blob/main/slides.md   # source
github.com/sinkap/pancake/blob/main/slides.pdf  # rendered
```
