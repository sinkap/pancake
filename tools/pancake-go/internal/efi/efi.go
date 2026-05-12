// Package efi turns a pancake kit into a UEFI-bootable disk image:
//
//   - BuildUKI calls systemd-ukify to bundle bzImage + initramfs + cmdline
//     into one PE-format Unified Kernel Image (UKI). One signable artifact
//     per generation.
//
//   - PackEFIDisk builds a GPT-partitioned image with two partitions:
//
//       p1  EFI System Partition (vfat, ~256 MB)
//             /EFI/BOOT/BOOTX64.EFI                   ← removable-media fallback
//             /EFI/systemd/systemd-bootx64.efi        ← real loader
//             /EFI/Linux/pancake-<gen-id>.efi         ← the UKI
//             /loader/loader.conf                     ← default + timeout
//
//       p2  pancake state (ext4 with the kit, label PANCAKE_STATE)
//
// Boot path in QEMU:
//
//     cp /usr/share/OVMF/OVMF_VARS.fd /tmp/OVMF_VARS.fd
//     qemu-system-x86_64 -enable-kvm -m 4G \
//         -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
//         -drive if=pflash,format=raw,file=/tmp/OVMF_VARS.fd \
//         -drive file=disk.img,format=raw,if=virtio \
//         -netdev user,id=n,hostfwd=tcp::2222-:22 -device virtio-net,netdev=n \
//         -nographic
//
// No -kernel, no -initrd: OVMF reads the ESP, loads systemd-boot, which
// auto-discovers the UKI in /EFI/Linux/, kernel + initramfs come from the
// PE sections, initramfs mounts /dev/disk/by-label/PANCAKE_STATE.
package efi

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/runner"
)

// UKIOpts: build a Unified Kernel Image.
type UKIOpts struct {
	Linux   string // bzImage path
	Initrd  string // initramfs.cpio.gz path
	Cmdline string // kernel cmdline string ("console=... rdinit=/init ...")
	Out     string // output .efi path
	UName   string // optional: --uname value (kernel version label)
	// SignKey + SignCert: when both set, ukify chains to sbsign and
	// produces a sb-signed UKI (one signed PE binary). UEFI Secure Boot
	// verifies the signature against db before loading.
	SignKey, SignCert string
}

// BuildUKI invokes systemd-ukify(1).
func BuildUKI(o UKIOpts) error {
	if o.Linux == "" || o.Initrd == "" || o.Out == "" {
		return fmt.Errorf("uki: Linux, Initrd, Out all required")
	}
	args := []string{"build",
		"--linux", o.Linux,
		"--initrd", o.Initrd,
		"--cmdline", o.Cmdline,
		"--output", o.Out,
	}
	if o.UName != "" {
		args = append(args, "--uname", o.UName)
	}
	if o.SignKey != "" && o.SignCert != "" {
		args = append(args,
			"--secureboot-private-key", o.SignKey,
			"--secureboot-certificate", o.SignCert)
	}
	if err := os.MkdirAll(filepath.Dir(o.Out), 0o755); err != nil {
		return err
	}
	if err := runner.Run(runner.Cmd{
		Argv: append([]string{"ukify"}, args...),
	}); err != nil {
		return err
	}
	st, _ := os.Stat(o.Out)
	tag := ""
	if o.SignKey != "" {
		tag = " [signed]"
	}
	fmt.Fprintf(os.Stderr, "[efi] UKI %s (%s)%s\n",
		o.Out, humanSize(st.Size()), tag)
	return nil
}

// EFIDiskOpts configures the bootable EFI disk image.
type EFIDiskOpts struct {
	Out         string // disk image path
	KitDir      string // kit dir to copy into the rootfs partition
	UKI         string // pre-built UKI .efi (gets installed at /EFI/Linux/)
	GenID       int    // generation id (used in entry filename)
	ESPSizeMB   int    // size of ESP, default 256
	BootEFIDir  string // host dir with systemd-bootx64.efi etc; default
	// /usr/lib/systemd/boot/efi
}

// PackEFIDisk builds the bootable image.
func PackEFIDisk(o EFIDiskOpts) error {
	if o.Out == "" || o.KitDir == "" || o.UKI == "" {
		return fmt.Errorf("efi: Out, KitDir, UKI all required")
	}
	if o.ESPSizeMB == 0 {
		o.ESPSizeMB = 256
	}
	if o.BootEFIDir == "" {
		o.BootEFIDir = "/usr/lib/systemd/boot/efi"
	}
	for _, f := range []string{"systemd-bootx64.efi"} {
		if _, err := os.Stat(filepath.Join(o.BootEFIDir, f)); err != nil {
			return fmt.Errorf("efi: missing %s/%s — install systemd-boot-efi",
				o.BootEFIDir, f)
		}
	}

	// Sizing: kit du * 1.30 + 64 MB headroom + ESP.
	duOut, err := runner.Capture(runner.Cmd{
		Argv: []string{"du", "-sk", o.KitDir}, Sudo: true,
	})
	if err != nil {
		return err
	}
	kitKB, err := strconv.Atoi(strings.Fields(strings.TrimSpace(duOut))[0])
	if err != nil {
		return fmt.Errorf("efi: parse du: %w", err)
	}
	rootfsKB := (kitKB*130/100 + 64*1024 + 3) / 4 * 4
	espKB := o.ESPSizeMB * 1024
	// 2 MB for GPT + alignment overhead at start + end.
	totalKB := espKB + rootfsKB + 2*1024
	totalKB = (totalKB + 3) / 4 * 4

	fmt.Fprintf(os.Stderr,
		"[efi] %d KiB image (ESP=%d, rootfs=%d) → %s\n",
		totalKB, espKB, rootfsKB, o.Out)

	if err := os.MkdirAll(filepath.Dir(o.Out), 0o755); err != nil {
		return err
	}
	_ = os.Remove(o.Out)
	if err := runner.Run(runner.Cmd{
		Argv: []string{"truncate", "-s", fmt.Sprintf("%dK", totalKB), o.Out},
	}); err != nil {
		return err
	}

	// Write GPT: ESP first (start at 1 MiB for alignment), rootfs second.
	if err := runner.Run(runner.Cmd{
		Argv: []string{"sgdisk",
			"--new=1:2048:+" + fmt.Sprintf("%dK", espKB),
			"--typecode=1:EF00",
			"--change-name=1:EFI",
			"--new=2:0:0",
			"--typecode=2:8300",
			"--change-name=2:PANCAKE_STATE",
			o.Out},
	}); err != nil {
		return err
	}

	// Loop-mount with -P so kernel exposes /dev/loopXp1 + /dev/loopXp2.
	loopOut, err := runner.Capture(runner.Cmd{
		Argv: []string{"losetup", "-P", "--show", "-f", o.Out}, Sudo: true,
	})
	if err != nil {
		return err
	}
	loopdev := strings.TrimSpace(loopOut)
	defer runner.RunOK(runner.Cmd{
		Argv: []string{"losetup", "-d", loopdev}, Sudo: true,
	})

	espDev := loopdev + "p1"
	rootfsDev := loopdev + "p2"

	// Format both partitions.
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mkfs.vfat", "-F", "32", "-n", "PANCAKE_ESP", espDev},
		Sudo: true,
	}); err != nil {
		return err
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mkfs.ext4", "-q", "-F", "-L", "PANCAKE_STATE",
			"-d", o.KitDir, "-E", "no_copy_xattrs", rootfsDev},
		Sudo: true,
	}); err != nil {
		return err
	}

	// Mount ESP, populate, unmount.
	espMnt, err := os.MkdirTemp("", "pancake-esp-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(espMnt)
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mount", espDev, espMnt}, Sudo: true,
	}); err != nil {
		return err
	}
	defer runner.RunOK(runner.Cmd{
		Argv: []string{"umount", espMnt}, Sudo: true,
	})

	for _, d := range []string{
		"EFI/BOOT", "EFI/systemd", "EFI/Linux", "loader", "loader/entries",
	} {
		if err := runner.Run(runner.Cmd{
			Argv: []string{"install", "-d", "-m", "0755",
				filepath.Join(espMnt, d)},
			Sudo: true,
		}); err != nil {
			return err
		}
	}
	// systemd-boot at the standard locations + the removable-media fallback.
	for _, dst := range []string{
		"EFI/systemd/systemd-bootx64.efi",
		"EFI/BOOT/BOOTX64.EFI",
	} {
		if err := runner.Run(runner.Cmd{
			Argv: []string{"install", "-m", "0644",
				filepath.Join(o.BootEFIDir, "systemd-bootx64.efi"),
				filepath.Join(espMnt, dst)},
			Sudo: true,
		}); err != nil {
			return err
		}
	}
	// The UKI itself.
	ukiName := fmt.Sprintf("pancake-%d.efi", o.GenID)
	if err := runner.Run(runner.Cmd{
		Argv: []string{"install", "-m", "0644", o.UKI,
			filepath.Join(espMnt, "EFI/Linux", ukiName)},
		Sudo: true,
	}); err != nil {
		return err
	}
	// loader.conf — systemd-boot auto-discovers UKIs in /EFI/Linux, but
	// we still set the default + timeout for predictable behaviour.
	loaderConf := fmt.Sprintf(
		"default %s\n"+
			"timeout 3\n"+
			"console-mode max\n"+
			"editor no\n",
		ukiName)
	tmpf, err := os.CreateTemp("", "pancake-loader-conf-")
	if err != nil {
		return err
	}
	if _, err := tmpf.WriteString(loaderConf); err != nil {
		tmpf.Close()
		os.Remove(tmpf.Name())
		return err
	}
	tmpf.Close()
	defer os.Remove(tmpf.Name())
	if err := runner.Run(runner.Cmd{
		Argv: []string{"install", "-m", "0644", tmpf.Name(),
			filepath.Join(espMnt, "loader/loader.conf")},
		Sudo: true,
	}); err != nil {
		return err
	}

	// Hand the disk back to the invoking user; loop-mount + mkfs ran as root.
	uid := strconv.Itoa(syscall.Getuid())
	gid := strconv.Itoa(syscall.Getgid())
	_ = runner.RunOK(runner.Cmd{
		Argv: []string{"chown", uid + ":" + gid, o.Out}, Sudo: true,
	})

	fmt.Fprintf(os.Stderr,
		"[efi] done. Boot in QEMU with:\n"+
			"  cp /usr/share/OVMF/OVMF_VARS.fd /tmp/OVMF_VARS-pancake.fd\n"+
			"  qemu-system-x86_64 -enable-kvm -cpu host -m 4G \\\n"+
			"    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \\\n"+
			"    -drive if=pflash,format=raw,file=/tmp/OVMF_VARS-pancake.fd \\\n"+
			"    -drive file=%s,format=raw,if=virtio \\\n"+
			"    -netdev user,id=n,hostfwd=tcp::2222-:22 -device virtio-net,netdev=n \\\n"+
			"    -nographic\n",
		o.Out)
	return nil
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%dM", n/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%dK", n/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}
