// customize.go: post-mmdebstrap surgery on the sandbox.
//
// Two responsibilities:
//   - customizeSandbox: shared (non-per-host) surgery — sshd_config,
//     networkd config, debug.service, resolv.conf. Identical on every
//     machine so it lives in the per-package / pancake-state layers,
//     which makes those layers' roothashes share-able across the fleet.
//   - bakePancakeRuntime: drop the Go pancake CLI + the C helpers
//     (mount-overlay, pivot-root) + the systemd remount-rw unit so the
//     booted VM can actually run `pancake install` / `pancake swap`.
//
// Per-host content (hostname, ssh host keys, authorized_keys) lives in
// its own pancake-host layer — see packPancakeHostLayer in bootstrap.go
// and isPerHostPath for the path filter that keeps it out of every
// other layer.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sinkap/pancake/tools/pancake-go/internal/runner"
	"github.com/sinkap/pancake/tools/pancake-go/internal/sign"
)

// signPubkeyFromCert is a tiny indirection so the bake step can call into
// internal/sign without growing the existing imports list ergonomics.
func signPubkeyFromCert(certPath, outPath string) error {
	return sign.PubkeyFromCert(certPath, outPath)
}

func customizeSandbox(sandbox string, a bootstrapArgs) error {
	fmt.Fprintln(os.Stderr, "\n[bootstrap] customizing sandbox (shared)")

	// pancake-debug.service: end-of-boot diagnostic dump → console.
	debugUnit := `[Unit]
Description=pancake-os end-of-boot diagnostic dump
DefaultDependencies=no
After=multi-user.target
[Service]
Type=oneshot
StandardOutput=journal+console
ExecStart=/bin/sh -c 'echo === PANCAKE DEBUG ===; echo --- ip ---; ip -4 addr 2>&1 | head -10; echo --- ss listening ---; ss -tlnp 2>&1 | head; echo --- ssh status ---; systemctl status ssh.socket ssh.service --no-pager -l 2>&1 | head -20; echo --- /etc/passwd sshd ---; grep ^sshd /etc/passwd; echo === END DEBUG ==='
[Install]
WantedBy=multi-user.target
`
	if err := writeFileSudo(
		filepath.Join(sandbox, "etc/systemd/system/pancake-debug.service"),
		debugUnit, 0o644); err != nil {
		return err
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mkdir", "-p",
			filepath.Join(sandbox, "etc/systemd/system/multi-user.target.wants")},
		Sudo: true,
	}); err != nil {
		return err
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"ln", "-sf",
			"/etc/systemd/system/pancake-debug.service",
			filepath.Join(sandbox,
				"etc/systemd/system/multi-user.target.wants/pancake-debug.service")},
		Sudo: true,
	}); err != nil {
		return err
	}

	// Network: DHCP via systemd-networkd; resolv.conf hardcoded for QEMU.
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mkdir", "-p", filepath.Join(sandbox, "etc/systemd/network")},
		Sudo: true,
	}); err != nil {
		return err
	}
	netConf := "[Match]\nType=ether\n[Network]\nDHCP=yes\n"
	if err := writeFileSudo(
		filepath.Join(sandbox, "etc/systemd/network/10-wired.network"),
		netConf, 0o644); err != nil {
		return err
	}
	_ = runner.RunOK(runner.Cmd{
		Argv: []string{"chroot", sandbox, "systemctl", "enable", "systemd-networkd"},
		Sudo: true,
	})
	if err := writeFileSudo(filepath.Join(sandbox, "etc/resolv.conf"),
		"nameserver 10.0.2.3\n", 0o644); err != nil {
		return err
	}

	// /etc/ssh/sshd_config wholesale replace. The .deb-shipped one is a
	// stub waiting for debconf; sshd_config.d/* is NOT included unless
	// we write the include line ourselves.
	sshdConf := `# /etc/ssh/sshd_config — pancake-os baseline
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
	if err := writeFileSudo(filepath.Join(sandbox, "etc/ssh/sshd_config"),
		sshdConf, 0o644); err != nil {
		return err
	}

	// Pancake runtime: Go binary + C helpers + remount unit.
	return bakePancakeRuntime(sandbox, a)
}

func bakePancakeRuntime(sandbox string, a bootstrapArgs) error {
	fmt.Fprintln(os.Stderr,
		"\n[bootstrap] baking pancake runtime into sandbox")

	srcRoot := a.SrcRoot
	if srcRoot == "" {
		// Default: two dirs above this binary's parent (tools/pancake-go/cmd/...)
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		// .../tools/pancake-go/bin/pancake-bootstrap (or similar);
		// the .c sources live at .../initramfs/ and .../pivot-root.c.
		srcRoot = filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(exe))))
	}

	// 1. Compile mount-overlay + pivot-root from C, statically linked,
	// then install into <sandbox>/sbin (which is a usrmerge symlink to
	// /usr/sbin in noble).
	for _, pair := range []struct{ src, name string }{
		{filepath.Join(srcRoot, "initramfs/mount-overlay.c"), "mount-overlay"},
		{filepath.Join(srcRoot, "pivot-root.c"), "pivot-root"},
	} {
		if _, err := os.Stat(pair.src); err != nil {
			return fmt.Errorf("missing source: %s (use --src-root to override)",
				pair.src)
		}
		tmpBin := filepath.Join("/tmp", "_pancake-build-"+pair.name)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"cc", "-O2", "-static", "-o", tmpBin, pair.src},
		}); err != nil {
			return err
		}
		if err := runner.Run(runner.Cmd{
			Argv: []string{"install", "-m", "0755", tmpBin,
				filepath.Join(sandbox, "sbin", pair.name)},
			Sudo: true,
		}); err != nil {
			return err
		}
		_ = os.Remove(tmpBin)
	}

	// 2. Drop the single Go pancake binary into /usr/local/bin/. Default
	// path is the executable that's running right now (this `pancake`
	// itself), so `pancake bootstrap` always bakes in the same version of
	// the CLI it ships. Override with --pancake-bin if cross-building.
	{
		bin := a.PancakeBin
		if bin == "" {
			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("locate self: %w", err)
			}
			bin = exe
		}
		if _, err := os.Stat(bin); err != nil {
			return fmt.Errorf("--pancake-bin: %w", err)
		}
		if err := runner.Run(runner.Cmd{
			Argv: []string{"install", "-d", "-m", "0755",
				filepath.Join(sandbox, "usr/local/bin")},
			Sudo: true,
		}); err != nil {
			return err
		}
		if err := runner.Run(runner.Cmd{
			Argv: []string{"install", "-m", "0755", bin,
				filepath.Join(sandbox, "usr/local/bin", "pancake")},
			Sudo: true,
		}); err != nil {
			return err
		}
	}

	// 3. Bake the manifest pubkey into the running rootfs too, so the
	// in-VM `pancake serve` / `pancake update` can verify pushed bundles
	// (the initramfs has its own copy at /etc/pancake/manifest.pubkey
	// but the running system mounts a different overlay; this puts a
	// copy inside one of the kit layers). Only when --sign-cert is set
	// at bootstrap time.
	if a.SignCert != "" {
		if err := runner.Run(runner.Cmd{
			Argv: []string{"install", "-d", "-m", "0755",
				filepath.Join(sandbox, "etc/pancake")},
			Sudo: true,
		}); err != nil {
			return err
		}
		// Reuse the pubkey extraction from sign.PubkeyFromCert via a
		// tempfile, then install it.
		tmpPub := filepath.Join("/tmp", "_pancake-pubkey-bake.pem")
		if err := signPubkeyFromCert(a.SignCert, tmpPub); err != nil {
			return err
		}
		defer os.Remove(tmpPub)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"install", "-m", "0644", tmpPub,
				filepath.Join(sandbox, "etc/pancake/manifest.pubkey")},
			Sudo: true,
		}); err != nil {
			return err
		}
	}

	// 4. systemd unit to remount /var/lib/pancake rw at boot. The initramfs
	// mounts it RO; pancake install/swap need to write into kit/repo/.
	unit := `[Unit]
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
	if err := writeFileSudo(filepath.Join(sandbox,
		"etc/systemd/system/pancake-state-rw.service"), unit, 0o644); err != nil {
		return err
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mkdir", "-p",
			filepath.Join(sandbox, "etc/systemd/system/multi-user.target.wants")},
		Sudo: true,
	}); err != nil {
		return err
	}
	return runner.Run(runner.Cmd{
		Argv: []string{"ln", "-sf",
			"/etc/systemd/system/pancake-state-rw.service",
			filepath.Join(sandbox,
				"etc/systemd/system/multi-user.target.wants/pancake-state-rw.service")},
		Sudo: true,
	})
}

// (locateBin removed: with the consolidated single-binary CLI, the bake
// step always uses os.Executable() — the running pancake itself.)

// writeFileSudo writes content to dst using `sh -c "cat > dst"` under sudo
// so root-owned destinations work without changing process credentials.
func writeFileSudo(dst, content string, _ os.FileMode) error {
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mkdir", "-p", filepath.Dir(dst)}, Sudo: true,
	}); err != nil {
		return err
	}
	// Use tee so we don't worry about quoting heredoc contents.
	tmpf, err := os.CreateTemp("", "pancake-cust-")
	if err != nil {
		return err
	}
	if _, err := tmpf.WriteString(content); err != nil {
		tmpf.Close()
		os.Remove(tmpf.Name())
		return err
	}
	tmpf.Close()
	defer os.Remove(tmpf.Name())
	return runner.Run(runner.Cmd{
		Argv: []string{"install", "-m", "0644", tmpf.Name(), dst}, Sudo: true,
	})
}
