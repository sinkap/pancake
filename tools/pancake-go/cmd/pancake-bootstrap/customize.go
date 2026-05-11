// customize.go: post-mmdebstrap surgery on the sandbox.
//
// Two responsibilities:
//   - customizeSandbox: machine identity (hostname, ssh keys + authorized_keys,
//     sshd_config, debug.service, networkd config). All baked in BEFORE
//     per-package snapshot so the changes land in whichever layer owns each
//     path (or the orphan pancake-state image).
//   - bakePancakeRuntime: drop the Go pancake CLI + the C helpers
//     (mount-overlay, pivot-root) + the systemd remount-rw unit so the
//     booted VM can actually run `pancake install` / `pancake swap`.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/runner"
)

func customizeSandbox(sandbox string, a bootstrapArgs) error {
	fmt.Fprintln(os.Stderr, "\n[bootstrap] customizing sandbox")

	// /etc/hostname (owned by base-files; goes into base-files' layer).
	fmt.Fprintf(os.Stderr, "  hostname → %s\n", a.Hostname)
	if err := writeFileSudo(filepath.Join(sandbox, "etc/hostname"),
		a.Hostname+"\n", 0o644); err != nil {
		return err
	}

	// SSH host keys.
	sshDir := filepath.Join(sandbox, "etc/ssh")
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mkdir", "-p", sshDir}, Sudo: true,
	}); err != nil {
		return err
	}
	if a.SSHHostKeysDir != "" {
		fmt.Fprintf(os.Stderr, "  ssh host keys ← %s\n", a.SSHHostKeysDir)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"sh", "-c",
				fmt.Sprintf("cp -a %s/ssh_host_* %s/",
					a.SSHHostKeysDir, sshDir)},
			Sudo: true,
		}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(os.Stderr, "  generating fresh ssh host keys in %s\n", sshDir)
		for _, kt := range []string{"rsa", "ecdsa", "ed25519"} {
			kf := filepath.Join(sshDir, "ssh_host_"+kt+"_key")
			if err := runner.Run(runner.Cmd{
				Argv: []string{"sh", "-c",
					fmt.Sprintf("rm -f %s %s.pub && ssh-keygen -q -N '' -t %s -f %s",
						kf, kf, kt, kf)},
				Sudo: true,
			}); err != nil {
				return err
			}
		}
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"sh", "-c",
			fmt.Sprintf("chmod 600 %s/ssh_host_*_key && chmod 644 %s/ssh_host_*_key.pub",
				sshDir, sshDir)},
		Sudo: true,
	}); err != nil {
		return err
	}

	// /root/.ssh/authorized_keys (only login path: passwords are awkward
	// against an RO rootfs).
	if a.SSHAuthKeysFile != "" {
		if fi, err := os.Stat(a.SSHAuthKeysFile); err != nil || fi.IsDir() {
			return fmt.Errorf("--ssh-authorized-keys: not a file: %s",
				a.SSHAuthKeysFile)
		}
		fmt.Fprintf(os.Stderr, "  /root/.ssh/authorized_keys ← %s\n",
			a.SSHAuthKeysFile)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"mkdir", "-p", filepath.Join(sandbox, "root/.ssh")},
			Sudo: true,
		}); err != nil {
			return err
		}
		if err := runner.Run(runner.Cmd{
			Argv: []string{"chmod", "700", filepath.Join(sandbox, "root/.ssh")},
			Sudo: true,
		}); err != nil {
			return err
		}
		if err := runner.Run(runner.Cmd{
			Argv: []string{"cp", a.SSHAuthKeysFile,
				filepath.Join(sandbox, "root/.ssh/authorized_keys")},
			Sudo: true,
		}); err != nil {
			return err
		}
		if err := runner.Run(runner.Cmd{
			Argv: []string{"chmod", "600",
				filepath.Join(sandbox, "root/.ssh/authorized_keys")},
			Sudo: true,
		}); err != nil {
			return err
		}
	}

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

	// 2. Drop the Go pancake + pancake-build binaries. Locate them in this
	// order: explicit --pancake-bin / --pancake-build-bin flag → next to
	// the bootstrap binary → $PATH.
	for _, pair := range []struct{ flagPath, name string }{
		{a.PancakeBin, "pancake"},
		{a.PancakeBuildBin, "pancake-build"},
	} {
		bin, err := locateBin(pair.flagPath, pair.name)
		if err != nil {
			return err
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
				filepath.Join(sandbox, "usr/local/bin", pair.name)},
			Sudo: true,
		}); err != nil {
			return err
		}
	}

	// 3. systemd unit to remount /var/lib/pancake rw at boot. The initramfs
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

// locateBin: explicit > sibling-of-bootstrap > $PATH. Errors if none found.
func locateBin(explicit, name string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("--%s: %w", name+"-bin", err)
		}
		return explicit, nil
	}
	exe, err := os.Executable()
	if err == nil {
		sibling := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(sibling); err == nil {
			return sibling, nil
		}
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("cannot find %q binary; pass --%s-bin",
		name, name)
}

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
