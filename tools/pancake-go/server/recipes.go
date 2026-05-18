// Server-side handlers for PancakeInternal recipes other than "base".
// Ported from cmd/pancake/bootstrap.go's pack* helpers; the operator
// uploads inputs as content-addressed blobs (UploadBlob → sha256) and
// the server stages + bakes the layer here.
//
// Convention: every input is a blob, including small string inputs
// (hostname, URLs) — the operator's CLI uploads them as tiny blobs
// before referring to their sha. This keeps the recipe message shape
// uniform and makes the layer cache key naturally include all inputs.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sinkap/pancake/tools/pancake-go/internal/buildpb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/deb"
	"github.com/sinkap/pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/pancake/tools/pancake-go/internal/layer"
)

// bakeStaged turns a pre-populated staging directory into a cached
// verity layer + LayerHandle. Sister to bakeLayer (which handles
// per-package APT staging); this variant is for synthetic layers
// where the caller has already laid out files under `staging`.
func (s *Server) bakeStaged(
	workRoot, staging, name, version, arch, description string,
) (*buildpb.LayerHandle, error) {
	dirName := name
	if version != "" {
		dirName = fmt.Sprintf("%s-%s", name, deb.SlugifyVersion(version))
	}
	tmpLayer := filepath.Join(workRoot, "L-"+dirName)
	if err := os.MkdirAll(tmpLayer, 0o755); err != nil {
		return nil, err
	}
	roothash, dataSize, err := layer.MakeVerity(staging,
		filepath.Join(tmpLayer, "image.img"),
		truncate(name, 12), 0, dirName)
	if err != nil {
		return nil, fmt.Errorf("MakeVerity %s: %w", name, err)
	}
	if err := kit.WritePackageManifest(tmpLayer, kit.PackageManifest{
		Package: kit.PackageBlock{
			Name: name, Version: version, Arch: arch,
			Description: description,
		},
		Image: kit.ImageBlock{DataSize: dataSize, Roothash: roothash},
	}); err != nil {
		return nil, fmt.Errorf("WritePackageManifest %s: %w", name, err)
	}
	final := s.layerDir(roothash)
	if _, err := os.Stat(final); err == nil {
		os.RemoveAll(tmpLayer)
	} else {
		if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
			return nil, err
		}
		if err := os.Rename(tmpLayer, final); err != nil {
			return nil, fmt.Errorf("rename layer to cache: %w", err)
		}
	}
	// Preserve the staging tree alongside the verity image so
	// AssembleImage can read files (kernel image, modules,
	// systemd units) without loop-mounting image.img. Skipped
	// silently on cache hit (existing staging dir wins).
	stagingFinal := s.layerStagingDir(roothash)
	if _, err := os.Stat(stagingFinal); err == nil {
		// Existing cached staging — drop ours.
		os.RemoveAll(staging)
	} else {
		if err := os.MkdirAll(filepath.Dir(stagingFinal), 0o755); err != nil {
			return nil, err
		}
		if err := os.Rename(staging, stagingFinal); err != nil {
			// Cross-fs rename can fail (e.g., staging in /tmp,
			// cache on a volume). Fall back to nothing — the
			// layer is still cached, just findKernelBzImage etc.
			// won't be able to source from this roothash.
			fmt.Fprintf(os.Stderr,
				"[bake] warn: could not cache staging for %s "+
					"(rename %s → %s: %v); kernel/modules sourcing "+
					"may fall back to host paths\n",
				name, staging, stagingFinal, err)
		}
	}
	mf, err := os.ReadFile(filepath.Join(final, "manifest.toml"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	hashSize := int64(0)
	if fi, err := os.Stat(filepath.Join(final, "image.hash")); err == nil {
		hashSize = fi.Size()
	}
	return &buildpb.LayerHandle{
		Roothash:     roothash,
		ManifestToml: mf,
		Name:         name,
		Version:      version,
		Arch:         arch,
		DataSize:     dataSize,
		HashSize:     hashSize,
	}, nil
}

// bakeInternal dispatches a non-base PancakeInternal recipe to its
// handler. Returns the resulting layer handle (or error).
func (s *Server) bakeInternal(
	workRoot string, in *buildpb.PancakeInternal,
) (*buildpb.LayerHandle, error) {
	switch in.Recipe {
	case "runtime":
		return s.bakeRuntime(workRoot, in)
	case "kernel":
		return s.bakeKernel(workRoot, in)
	case "modules":
		return s.bakeModules(workRoot, in)
	case "pancaked":
		return s.bakePancaked(workRoot, in)
	case "pancake-host":
		return s.bakePancakeHost(workRoot, in)
	case "orch-config":
		return s.bakeOrchConfig(workRoot, in)
	default:
		return nil, fmt.Errorf("unknown recipe %q", in.Recipe)
	}
}

// ----- runtime -------------------------------------------------------

const runtimeGenerator = `#!/bin/sh
# pancake-defaults: systemd generator. Materializes default unit
# enables under /run/systemd/generator/ on every boot. Runs before
# systemd reads the unit tree, so its symlinks are honored on the
# first activation of multi-user.target.
#
# args: $1 normal-dir, $2 early-dir, $3 late-dir
set -e
ND="$1"
mkdir -p "$ND/multi-user.target.wants" "$ND/sockets.target.wants"
ln -sf /lib/systemd/system/systemd-networkd.service \
    "$ND/multi-user.target.wants/systemd-networkd.service"
ln -sf /lib/systemd/system/systemd-networkd.socket \
    "$ND/sockets.target.wants/systemd-networkd.socket"
exit 0
`

const runtimeStateRwUnit = `[Unit]
Description=Remount /var/lib/pancake read-write for pancake CLI
DefaultDependencies=no
ConditionPathIsMountPoint=/var/lib/pancake
After=local-fs.target
Before=multi-user.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/mount -o remount,rw /var/lib/pancake
[Install]
WantedBy=multi-user.target
`

const runtimeDebugUnit = `[Unit]
Description=pancake-os end-of-boot diagnostic dump
DefaultDependencies=no
After=multi-user.target
[Service]
Type=oneshot
StandardOutput=journal+console
ExecStart=/bin/sh -c 'echo === PANCAKE DEBUG ===; echo --- ip ---; ip -4 addr 2>&1 | head -10; echo --- ss listening ---; ss -tlnp 2>&1 | head; echo --- ssh status ---; systemctl status ssh.socket ssh.service --no-pager -l 2>&1 | head -20; echo === END DEBUG ==='
[Install]
WantedBy=multi-user.target
`

// bakeRuntime: pancake CLI binary + C helpers + systemd units. Inputs:
//
//	blobs[pancake-binary]          (or fallback: bundled-bins-dir/pancake)
//	blobs[mount-overlay-binary]    (or fallback: .../mount-overlay)
//	blobs[pivot-root-binary]       (or fallback: .../pivot-root)
//	blobs[manifest-pubkey]         optional — when set, baked at
//	                               /etc/pancake/manifest.pubkey
func (s *Server) bakeRuntime(
	workRoot string, in *buildpb.PancakeInternal,
) (*buildpb.LayerHandle, error) {
	pancakeBin, err := s.blobOrBundled(in.Blobs["pancake-binary"], "pancake")
	if err != nil {
		return nil, err
	}
	mountOverlayBin, err := s.blobOrBundled(in.Blobs["mount-overlay-binary"], "mount-overlay")
	if err != nil {
		return nil, err
	}
	pivotRootBin, err := s.blobOrBundled(in.Blobs["pivot-root-binary"], "pivot-root")
	if err != nil {
		return nil, err
	}

	staging, err := os.MkdirTemp(workRoot, "stage-runtime-")
	if err != nil {
		return nil, err
	}
	for _, d := range []string{
		"usr/sbin", "usr/local/bin",
		"usr/lib/systemd/system-generators",
		"etc/systemd/system",
		"etc/systemd/system/multi-user.target.wants",
	} {
		if err := os.MkdirAll(filepath.Join(staging, d), 0o755); err != nil {
			return nil, err
		}
	}

	if err := os.WriteFile(filepath.Join(staging,
		"usr/lib/systemd/system-generators/pancake-defaults"),
		[]byte(runtimeGenerator), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging, "usr/sbin/mount-overlay"),
		mountOverlayBin, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging, "usr/sbin/pivot-root"),
		pivotRootBin, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging, "usr/local/bin/pancake"),
		pancakeBin, 0o755); err != nil {
		return nil, err
	}

	if err := os.WriteFile(filepath.Join(staging,
		"etc/systemd/system/pancake-state-rw.service"),
		[]byte(runtimeStateRwUnit), 0o644); err != nil {
		return nil, err
	}
	if err := os.Symlink("/etc/systemd/system/pancake-state-rw.service",
		filepath.Join(staging,
			"etc/systemd/system/multi-user.target.wants/pancake-state-rw.service")); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging,
		"etc/systemd/system/pancake-debug.service"),
		[]byte(runtimeDebugUnit), 0o644); err != nil {
		return nil, err
	}
	if err := os.Symlink("/etc/systemd/system/pancake-debug.service",
		filepath.Join(staging,
			"etc/systemd/system/multi-user.target.wants/pancake-debug.service")); err != nil {
		return nil, err
	}

	var pubBytes []byte
	if pubSha := in.Blobs["manifest-pubkey"]; pubSha != "" {
		b, err := s.readBlob(pubSha)
		if err != nil {
			return nil, err
		}
		pubBytes = b
	} else if s.signer != nil {
		cert, err := s.signer.Cert(context.Background())
		if err == nil {
			if p2, err := pubkeyFromCertBytes(cert); err == nil {
				pubBytes = p2
			}
		}
	}
	if len(pubBytes) > 0 {
		if err := os.MkdirAll(filepath.Join(staging, "etc/pancake"), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(staging,
			"etc/pancake/manifest.pubkey"), pubBytes, 0o644); err != nil {
			return nil, err
		}
	}

	return s.bakeStaged(workRoot, staging,
		"pancake-runtime", "1.0.0", "all",
		"pancake-os runtime defaults (CLI + helpers + systemd units)")
}

// ----- pancaked ------------------------------------------------------

// pancakeEnrollUnit template — hostname is hardcoded at build time from
// the recipe so the certificate SAN matches /etc/hostname.
func pancakeEnrollUnit(hostname string) string {
	return fmt.Sprintf(`[Unit]
Description=pancake auto-enrollment (ACME device-attest-01)
Documentation=https://github.com/sinkap/pancake
After=pancake-state-rw.service
Requires=pancake-state-rw.service
Before=pancaked.service
ConditionPathExists=!/etc/pancake/server.crt

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pancake enroll --san DNS:%s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`, hostname)
}

const pancakedUnit = `[Unit]
Description=pancake update daemon (orchestrator gRPC receiver)
Documentation=https://github.com/sinkap/pancake
After=pancake-state-rw.service pancake-enroll.service
Requires=pancake-state-rw.service

[Service]
ExecStart=/usr/sbin/pancaked
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

// bakePancaked: /usr/sbin/pancaked + systemd unit. Inputs:
//
//	blobs[binary]     (or fallback: bundled-bins-dir/pancaked)
//	params[hostname]  hostname for auto-enrollment SAN
//	in.Version        version label for the layer (e.g. git sha)
func (s *Server) bakePancaked(
	workRoot string, in *buildpb.PancakeInternal,
) (*buildpb.LayerHandle, error) {
	bin, err := s.blobOrBundled(in.Blobs["binary"], "pancaked")
	if err != nil {
		return nil, err
	}
	hostname := strings.TrimSpace(in.Params["hostname"])
	if hostname == "" {
		return nil, fmt.Errorf("pancaked recipe: params[hostname] required " +
			"(needed to hardcode SAN in auto-enrollment unit)")
	}
	version := in.Version
	if version == "" {
		version = "1.0.0"
	}
	staging, err := os.MkdirTemp(workRoot, "stage-pancaked-")
	if err != nil {
		return nil, err
	}
	for _, d := range []string{
		"usr/sbin", "etc/systemd/system",
		"etc/systemd/system/multi-user.target.wants",
	} {
		if err := os.MkdirAll(filepath.Join(staging, d), 0o755); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(staging, "usr/sbin/pancaked"),
		bin, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging,
		"etc/systemd/system/pancake-enroll.service"),
		[]byte(pancakeEnrollUnit(hostname)), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging,
		"etc/systemd/system/pancaked.service"),
		[]byte(pancakedUnit), 0o644); err != nil {
		return nil, err
	}
	if err := os.Symlink("/etc/systemd/system/pancake-enroll.service",
		filepath.Join(staging,
			"etc/systemd/system/multi-user.target.wants/pancake-enroll.service")); err != nil {
		return nil, err
	}
	if err := os.Symlink("/etc/systemd/system/pancaked.service",
		filepath.Join(staging,
			"etc/systemd/system/multi-user.target.wants/pancaked.service")); err != nil {
		return nil, err
	}
	return s.bakeStaged(workRoot, staging,
		"pancaked", version, "all",
		"pancake update daemon — gRPC receiver for orchestrator pushes")
}

// ----- kernel --------------------------------------------------------

// bakeKernel: /boot/vmlinuz from an uploaded bzImage. Inputs:
//
//	blobs[bzimage]    required
//	in.Version        kernel uname (e.g. "6.13.0-rc1+")
func (s *Server) bakeKernel(
	workRoot string, in *buildpb.PancakeInternal,
) (*buildpb.LayerHandle, error) {
	if in.Version == "" {
		return nil, fmt.Errorf("kernel recipe: version required")
	}
	bzSha := in.Blobs["bzimage"]
	if bzSha == "" {
		return nil, fmt.Errorf("kernel recipe: blobs[bzimage] required")
	}
	bz, err := s.readBlob(bzSha)
	if err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(workRoot, "stage-kernel-")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(staging, "boot"), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging, "boot/vmlinuz"),
		bz, 0o644); err != nil {
		return nil, err
	}
	return s.bakeStaged(workRoot, staging,
		"pancake-kernel", in.Version, "all",
		fmt.Sprintf("custom kernel %s (%d bytes)", in.Version, len(bz)))
}

// ----- modules -------------------------------------------------------

// bakeModules: /lib/modules/<version> from an uploaded tarball. Inputs:
//
//	blobs[tarball]    required (.tar.gz; layout = lib/modules/<ver>/...)
//	in.Version        kernel uname
func (s *Server) bakeModules(
	workRoot string, in *buildpb.PancakeInternal,
) (*buildpb.LayerHandle, error) {
	if in.Version == "" {
		return nil, fmt.Errorf("modules recipe: version required")
	}
	tarSha := in.Blobs["tarball"]
	if tarSha == "" {
		return nil, fmt.Errorf("modules recipe: blobs[tarball] required")
	}
	tarPath := s.blobPath(tarSha)
	if _, err := os.Stat(tarPath); err != nil {
		return nil, fmt.Errorf("modules tarball %s: %w", tarSha, err)
	}
	staging, err := os.MkdirTemp(workRoot, "stage-modules-")
	if err != nil {
		return nil, err
	}
	// Untar into staging. The tarball must lay out
	// lib/modules/<version>/... so we just extract at root.
	if err := untarInto(tarPath, staging); err != nil {
		return nil, fmt.Errorf("untar modules: %w", err)
	}
	return s.bakeStaged(workRoot, staging,
		"pancake-modules", in.Version, "all",
		fmt.Sprintf("kernel modules for %s", in.Version))
}

// ----- pancake-host --------------------------------------------------

const sshdConf = `# /etc/ssh/sshd_config — pancake-os baseline (pancake-host layer)
Port 22
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication no
UsePAM no
UseDNS no
GSSAPIAuthentication no
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
`

const networkdWired = "[Match]\nType=ether\n[Network]\nDHCP=yes\n"

// bakePancakeHost: hostname + ssh identity + sshd_config + networkd.
// Inputs (all blobs; tiny strings encoded as their bytes):
//
//	blobs[hostname]                   required (raw bytes = hostname string)
//	blobs[ssh-authorized-keys]        optional
//	blobs[ssh-host-rsa-key]           optional (private key bytes)
//	blobs[ssh-host-rsa-key.pub]       optional
//	blobs[ssh-host-ecdsa-key]         optional
//	blobs[ssh-host-ecdsa-key.pub]     optional
//	blobs[ssh-host-ed25519-key]       optional
//	blobs[ssh-host-ed25519-key.pub]   optional
//
// When host keys are not supplied, the server is the trust boundary —
// the operator must accept that the build server generated them. For
// stable identity across rebuilds, upload them.
func (s *Server) bakePancakeHost(
	workRoot string, in *buildpb.PancakeInternal,
) (*buildpb.LayerHandle, error) {
	hnSha := in.Blobs["hostname"]
	if hnSha == "" {
		return nil, fmt.Errorf("pancake-host recipe: blobs[hostname] required")
	}
	hnBytes, err := s.readBlob(hnSha)
	if err != nil {
		return nil, err
	}
	hostname := strings.TrimSpace(string(hnBytes))
	if hostname == "" {
		return nil, fmt.Errorf("pancake-host: hostname blob is empty")
	}

	staging, err := os.MkdirTemp(workRoot, "stage-host-")
	if err != nil {
		return nil, err
	}
	for _, d := range []string{
		"etc/ssh", "root/.ssh", "etc/systemd/network",
	} {
		if err := os.MkdirAll(filepath.Join(staging, d), 0o755); err != nil {
			return nil, err
		}
	}
	if err := os.Chmod(filepath.Join(staging, "root"), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(filepath.Join(staging, "root/.ssh"), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging, "etc/hostname"),
		[]byte(hostname+"\n"), 0o644); err != nil {
		return nil, err
	}

	// SSH host keys — copy whichever the operator uploaded; fall
	// through to ssh-keygen when none provided.
	hostKeyTypes := []string{"rsa", "ecdsa", "ed25519"}
	supplied := false
	for _, kt := range hostKeyTypes {
		role := "ssh-host-" + kt + "-key"
		if sha := in.Blobs[role]; sha != "" {
			supplied = true
			b, err := s.readBlob(sha)
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(staging,
				"etc/ssh/ssh_host_"+kt+"_key"), b, 0o600); err != nil {
				return nil, err
			}
		}
		if sha := in.Blobs[role+".pub"]; sha != "" {
			b, err := s.readBlob(sha)
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(staging,
				"etc/ssh/ssh_host_"+kt+"_key.pub"), b, 0o644); err != nil {
				return nil, err
			}
		}
	}
	if !supplied {
		// Generate fresh keys server-side. Same effect as the
		// classic client-side fallback.
		if err := generateHostKeys(filepath.Join(staging, "etc/ssh")); err != nil {
			return nil, fmt.Errorf("ssh-keygen host keys: %w", err)
		}
	}

	if sha := in.Blobs["ssh-authorized-keys"]; sha != "" {
		b, err := s.readBlob(sha)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(staging,
			"root/.ssh/authorized_keys"), b, 0o600); err != nil {
			return nil, err
		}
	}

	if err := os.WriteFile(filepath.Join(staging, "etc/ssh/sshd_config"),
		[]byte(sshdConf), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging, "etc/resolv.conf"),
		[]byte("nameserver 10.0.2.3\n"), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(staging,
		"etc/systemd/network/10-wired.network"),
		[]byte(networkdWired), 0o644); err != nil {
		return nil, err
	}

	return s.bakeStaged(workRoot, staging,
		"pancake-host", "1.0.0", "all",
		"per-host identity (hostname, ssh keys, authorized_keys)")
}

// ----- orch-config ---------------------------------------------------

// bakeOrchConfig stages the per-deployment orchestrator-config layer:
// CA URL (operator-supplied via params["ca-url"]) plus the TLS trust
// root (read from the build server's local trust volume — recipe
// carries no PEMs, so the operator never extracts certs from running
// containers).
//
// Unified CA mode (recommended):
//   params["ca-url"] only, no params["attest-ca-url"]
//   Layer contains: trust-root.crt (step-ca intermediate + root)
//   VMs use dev EK CA for local AK cert issuance
//
// Legacy dual-CA mode (deprecated):
//   params["ca-url"] + params["attest-ca-url"]
//   Layer contains: trust-root.crt + attest-ca-root.crt
//
// Layer contents:
//
//   /etc/pancake/orch/trust-root.crt     PEM, step-ca's TLS root
//   /etc/pancake/orch/config.json        {ca_url, [attest_ca_url],
//                                         trust_root, [attest_ca_root],
//                                         client_ca_root}
//
// client_ca_root points at the same trust-root.crt — pancaked
// validates incoming orchestrator mTLS against step-ca's root, since
// the orchestrator's client cert is step-ca-issued.
func (s *Server) bakeOrchConfig(
	workRoot string, in *buildpb.PancakeInternal,
) (*buildpb.LayerHandle, error) {
	caURL := strings.TrimSpace(in.Params["ca-url"])
	if caURL == "" {
		return nil, fmt.Errorf("orch-config: params[ca-url] required")
	}
	attestURL := strings.TrimSpace(in.Params["attest-ca-url"])
	fleetURL := strings.TrimSpace(in.Params["fleet-server"])

	if s.trustDir == "" {
		return nil, fmt.Errorf("orch-config: server has no --trust-dir " +
			"configured; cannot locate the TLS trust roots")
	}
	caRootPath := filepath.Join(s.trustDir, "trust-root.crt")
	caRoot, err := os.ReadFile(caRootPath)
	if err != nil {
		return nil, fmt.Errorf("orch-config: read %s: %w", caRootPath, err)
	}

	staging, err := os.MkdirTemp(workRoot, "stage-orch-")
	if err != nil {
		return nil, err
	}
	orchDir := filepath.Join(staging, "etc/pancake/orch")
	if err := os.MkdirAll(orchDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(orchDir, "trust-root.crt"),
		caRoot, 0o644); err != nil {
		return nil, err
	}

	// Unified CA mode: include dev EK CA for local AK cert issuance
	// This allows VMs to sign their own AK certs without calling attest-ca.
	// Note: dev EK CA private key is included (for dev only - production
	// should use hardware TPMs with manufacturer-signed EKs/AKs).
	devEKCADir := filepath.Join(s.trustDir, "dev-ek-ca")
	if _, err := os.Stat(filepath.Join(devEKCADir, "ca.crt")); err == nil {
		ekCADir := filepath.Join(orchDir, "dev-ek-ca")
		if err := os.MkdirAll(ekCADir, 0o755); err != nil {
			return nil, err
		}
		// Copy dev EK CA cert and key
		for _, f := range []string{"ca.crt", "ca.key"} {
			src := filepath.Join(devEKCADir, f)
			dst := filepath.Join(ekCADir, f)
			data, err := os.ReadFile(src)
			if err == nil {
				os.WriteFile(dst, data, 0o644)
			}
		}
		fmt.Fprintf(os.Stderr,
			"[build-server] baked dev EK CA into orch-config layer\n")
	}

	cfg := struct {
		CAURL        string `json:"ca_url"`
		AttestCAURL  string `json:"attest_ca_url,omitempty"`
		TrustRoot    string `json:"trust_root"`
		AttestCARoot string `json:"attest_ca_root,omitempty"`
		ClientCARoot string `json:"client_ca_root"`
		FleetServer  string `json:"fleet_server,omitempty"`
	}{
		CAURL:        caURL,
		TrustRoot:    "/etc/pancake/orch/trust-root.crt",
		ClientCARoot: "/etc/pancake/orch/trust-root.crt",
		FleetServer:  fleetURL,
	}

	// Legacy dual-CA mode: if attest-ca-url is set, include it
	if attestURL != "" {
		attestRootPath := filepath.Join(s.trustDir, "attest-ca-root.crt")
		attestRoot, err := os.ReadFile(attestRootPath)
		if err != nil {
			return nil, fmt.Errorf("orch-config: read %s: %w", attestRootPath, err)
		}
		if err := os.WriteFile(filepath.Join(orchDir, "attest-ca-root.crt"),
			attestRoot, 0o644); err != nil {
			return nil, err
		}
		cfg.AttestCAURL = attestURL
		cfg.AttestCARoot = "/etc/pancake/orch/attest-ca-root.crt"
	}

	cfgBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(orchDir, "config.json"),
		append(cfgBytes, '\n'), 0o644); err != nil {
		return nil, err
	}
	return s.bakeStaged(workRoot, staging,
		"pancake-orch-config", "1.0.0", "all",
		"orchestrator URLs + TLS trust roots (per-deployment)")
}
