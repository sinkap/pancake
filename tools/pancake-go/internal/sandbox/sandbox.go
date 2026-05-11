// Package sandbox handles the runtime side of building or installing into
// a kit:
//
//   - Materialize: open dm-verity for each layer in the current generation,
//     RO-mount each, then stack them all into one overlay using the
//     mount-overlay helper. The result is a complete chroot-able tree.
//   - BindChrootRuntime: drop the /proc /sys /dev binds + apt scaffolding
//     dirs + /etc/resolv.conf into the materialized tree so apt-get install
//     works from inside.
//
// The Sandbox struct tracks every dm device + mount we created so Teardown
// can reverse them in the right order, even on the failure path.
//
// IMPORTANT: this code stresses the kernel (mounts a 100+ lower overlay,
// opens many dm-verity devices). It must NEVER run on the host — only
// inside the booted pancake-os VM, or on a throwaway test machine. See
// memory feedback "Test pancake-os ops in QEMU, not on host".
package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/kit"
	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/runner"
)

// Sandbox is a materialized union of a generation's verity layers, with
// optional bind-mounts for /proc /sys /dev. Construct via Materialize or
// MaterializeFromLowers; tear down via Teardown.
type Sandbox struct {
	// Path is the chroot-able merged overlay (caller passes this to
	// `chroot`, `dpkg-query`, etc).
	Path string

	scratch  string   // root scratch dir; everything below lives here
	rwTmpfs  string   // tmpfs we mount for upper/work (overlayfs forbids
	// upperdir-on-overlayfs)
	openedDM []string // verity device names, in open order
	mounts   []string // paths in mount(2) order; teardown reverses
	bound    []string // bind-mount targets for /proc /sys /dev
}

// MaterializeCurrent opens + RO-mounts every layer in <kit>/current and
// stacks them into one overlay at <scratch>/sandbox.
//
// All mounts go under <scratch>/. The caller MUST call Teardown when done
// (typically via defer right after the constructor returns ok).
//
// `tag` is mixed into the dm-mapper device names so concurrent runs can't
// collide on /dev/mapper/v_<slug>. Pass something like fmt.Sprintf("pkadd%d",
// os.Getpid()).
func MaterializeCurrent(k *kit.Kit, scratch, tag string,
	mountOverlayBin string) (*Sandbox, error) {
	cur, err := k.CurrentGeneration()
	if err != nil {
		return nil, err
	}
	lowers, err := kit.ReadLowers(filepath.Join(cur, "lowers"))
	if err != nil {
		return nil, err
	}
	return materialize(k, scratch, tag, mountOverlayBin, lowers)
}

func materialize(k *kit.Kit, scratch, tag, mountOverlayBin string,
	lowers []kit.LowerEntry) (*Sandbox, error) {
	fmt.Fprintf(os.Stderr,
		"[pancake] materializing current generation as overlay "+
			"(%d layers, no sandbox copy needed)\n", len(lowers))

	if err := os.MkdirAll(scratch, 0o755); err != nil {
		return nil, err
	}
	lowersDir := filepath.Join(scratch, "lowers")
	sandboxPath := filepath.Join(scratch, "sandbox")
	rwRoot := filepath.Join(scratch, "rw")
	for _, d := range []string{lowersDir, sandboxPath, rwRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}

	sb := &Sandbox{
		Path:    sandboxPath,
		scratch: scratch,
		rwTmpfs: rwRoot,
	}

	// overlayfs rejects upperdir/workdir that are themselves on overlayfs
	// (which is the case inside pancake-os, where / is the runtime overlay).
	// Mount a fresh tmpfs over rw_root so upper/work always live on a plain
	// fs regardless of where scratch sits.
	if err := runner.Run(runner.Cmd{
		Argv: []string{"mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", rwRoot},
		Sudo: true,
	}); err != nil {
		sb.Teardown() // nothing to tear down yet but keep the contract
		return nil, err
	}
	sb.mounts = append(sb.mounts, rwRoot)
	upper := filepath.Join(rwRoot, "upper")
	work := filepath.Join(rwRoot, "work")
	for _, d := range []string{upper, work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			sb.Teardown()
			return nil, err
		}
	}

	// Open + mount each lower. Verity-open names are tag-prefixed to avoid
	// dm collisions across concurrent runs.
	lowerArgs := make([]string, 0, 2*len(lowers))
	for _, L := range lowers {
		dmName := truncate(fmt.Sprintf("v_%s_%s", tag, L.Slug), 120)
		img := filepath.Join(k.Dir, L.ImageRel)
		hashf := filepath.Join(k.Dir, L.HashRel)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"veritysetup", "open", img, dmName, hashf, L.Roothash},
			Sudo: true,
		}); err != nil {
			sb.Teardown()
			return nil, err
		}
		sb.openedDM = append(sb.openedDM, dmName)

		mp := filepath.Join(lowersDir, L.Slug)
		if err := os.MkdirAll(mp, 0o755); err != nil {
			sb.Teardown()
			return nil, err
		}
		if err := runner.Run(runner.Cmd{
			Argv: []string{"mount", "-o", "ro", "/dev/mapper/" + dmName, mp},
			Sudo: true,
		}); err != nil {
			sb.Teardown()
			return nil, err
		}
		sb.mounts = append(sb.mounts, mp)
		lowerArgs = append(lowerArgs, "--lower", mp)
	}

	// Stack the lowers. mount-overlay uses fsopen + repeated
	// fsconfig "lowerdir+", which sidesteps mount(2)'s 4 KiB option-string
	// cap (essential past ~30 lowers).
	args := append([]string{
		"--upper", upper, "--work", work, "--target", sandboxPath,
	}, lowerArgs...)
	if err := runner.Run(runner.Cmd{
		Argv: append([]string{mountOverlayBin}, args...),
		Sudo: true,
	}); err != nil {
		sb.Teardown()
		return nil, err
	}
	sb.mounts = append(sb.mounts, sandboxPath)

	return sb, nil
}

// BindChrootRuntime sets up the chroot-runtime side of the materialized
// sandbox: rbind /proc /sys /dev (with --make-rslave to keep our binds from
// propagating back), creates /tmp and apt's empty-dir scaffolding (older
// layers don't always carry these), and copies the host's /etc/resolv.conf
// so apt-get update can reach archive mirrors.
//
// Tear-down happens in Teardown alongside the verity unmounts.
func (s *Sandbox) BindChrootRuntime() error {
	for _, sub := range []string{"proc", "sys", "dev"} {
		tgt := filepath.Join(s.Path, sub)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"mkdir", "-p", tgt}, Sudo: true,
		}); err != nil {
			return err
		}
		if err := runner.Run(runner.Cmd{
			Argv: []string{"mount", "--rbind", "/" + sub, tgt}, Sudo: true,
		}); err != nil {
			return err
		}
		// non-fatal: --make-rslave can fail under some kernels; the rbind
		// is what matters for visibility.
		_ = runner.RunOK(runner.Cmd{
			Argv: []string{"mount", "--make-rslave", tgt}, Sudo: true,
		})
		s.bound = append(s.bound, tgt)
	}
	// /tmp: apt drops privs to _apt user which needs a sticky world-writable
	// /tmp to stage apt-key configs. No .deb ships /tmp so we create it.
	if err := runner.Run(runner.Cmd{
		Argv: []string{"install", "-d", "-m", "1777",
			filepath.Join(s.Path, "tmp")},
		Sudo: true,
	}); err != nil {
		return err
	}
	// apt empty-dir scaffolding. New layers built by `pancake install` will
	// carry these (deb.PackageFiles preserves empty dirs); older layers
	// were built before that fix, so create here as a fallback.
	for _, d := range []string{
		"var/cache/apt/archives/partial",
		"var/lib/apt/lists/partial",
		"var/log/apt",
		"var/log",
		"etc/apt/preferences.d",
		"etc/apt/sources.list.d",
		"etc/apt/apt.conf.d",
		"etc/apt/auth.conf.d",
		"etc/apt/keyrings",
	} {
		if err := runner.Run(runner.Cmd{
			Argv: []string{"install", "-d", "-m", "0755",
				filepath.Join(s.Path, d)},
			Sudo: true,
		}); err != nil {
			return err
		}
	}
	if _, err := os.Stat("/etc/resolv.conf"); err == nil {
		_ = runner.Run(runner.Cmd{
			Argv: []string{"mkdir", "-p", filepath.Join(s.Path, "etc")},
			Sudo: true,
		})
		if err := runner.Run(runner.Cmd{
			Argv: []string{"cp", "-f", "--dereference", "/etc/resolv.conf",
				filepath.Join(s.Path, "etc/resolv.conf")},
			Sudo: true,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Chroot returns an exec.Cmd that runs argv inside the materialized
// sandbox. The caller usually wraps this with .Run/.Output/.CombinedOutput.
//
// Currently unused by the install path (which goes through runner.Cmd for
// uniform "▸ " trace + sudo handling), but exposed for external callers
// that want a more direct chroot.
func (s *Sandbox) Chroot(env []string, argv ...string) *exec.Cmd {
	cmd := exec.Command("chroot", append([]string{s.Path}, argv...)...)
	cmd.Env = env
	return cmd
}

// Teardown reverses every mount and verity-open, in reverse of the order
// they were created. Best-effort: every individual op uses RunOK so a
// stuck mount doesn't prevent us from closing the verity device beneath it.
//
// The scratch directory itself is NOT removed — the caller controls its
// lifetime (so it can also keep listfiles, staging dirs, etc).
func (s *Sandbox) Teardown() {
	if s == nil {
		return
	}
	// Unbind /proc /sys /dev first — they're nested under the overlay
	// sandbox, and lazy-detaching them releases overlay refcounts.
	for i := len(s.bound) - 1; i >= 0; i-- {
		_ = runner.RunOK(runner.Cmd{
			Argv: []string{"umount", "-l", s.bound[i]}, Sudo: true,
		})
	}
	// Unmount the overlay sandbox + per-layer RO mounts + tmpfs.
	for i := len(s.mounts) - 1; i >= 0; i-- {
		_ = runner.RunOK(runner.Cmd{
			Argv: []string{"umount", "-l", s.mounts[i]}, Sudo: true,
		})
	}
	// Close dm-verity devices last; with everything unmounted they should
	// no longer be in-use. If they are, leak rather than wedge.
	for i := len(s.openedDM) - 1; i >= 0; i-- {
		_ = runner.RunOK(runner.Cmd{
			Argv: []string{"veritysetup", "close", s.openedDM[i]}, Sudo: true,
		})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// FindHelper locates a binary like mount-overlay or pivot-root. Search
// order matches the python find_helper:
//  1. /sbin/<name>          (in-VM install via pancake-state)
//  2. /usr/sbin/<name>      (usrmerge variant — what bake_pancake_runtime
//     actually drops)
//  3. /usr/local/sbin/<name>
//  4. <repoRoot>/<srcSubdir>/<name>  (uncompiled source-tree fallback;
//     compiled on demand from <name>.c if missing)
//
// repoRoot is typically derived from os.Args[0] for local dev.
func FindHelper(name, repoRoot, srcSubdir string) (string, error) {
	for _, p := range []string{
		"/sbin/" + name,
		"/usr/sbin/" + name,
		"/usr/local/sbin/" + name,
	} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	if repoRoot != "" && srcSubdir != "" {
		bin := filepath.Join(repoRoot, srcSubdir, name)
		if _, err := os.Stat(bin); err == nil {
			return bin, nil
		}
		src := filepath.Join(repoRoot, srcSubdir, name+".c")
		if _, err := os.Stat(src); err == nil {
			if err := runner.Run(runner.Cmd{
				Argv: []string{"cc", "-O2", "-o", bin, src},
			}); err != nil {
				return "", err
			}
			return bin, nil
		}
	}
	return "", fmt.Errorf("cannot find helper %q (checked /sbin, /usr/sbin, "+
		"/usr/local/sbin, source tree)", name)
}

// RunningInPancakeOS reports whether / is an overlay mount and /lowers exists,
// which is the signature of a booted pancake-os system. cmd_swap requires
// this; cmd_install doesn't but uses it to choose chroot-vs-host paths.
func RunningInPancakeOS() bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		if f[1] == "/" && f[2] == "overlay" {
			if fi, err := os.Stat("/lowers"); err == nil && fi.IsDir() {
				return true
			}
		}
	}
	return false
}
