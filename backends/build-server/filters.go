package server

import "strings"

// shouldIgnore mirrors the ignorePatterns list in cmd/pancake/bootstrap.go.
// Files matching any prefix here are stripped from BOTH per-package
// layers and the base orphan layer — they exist in the build sandbox
// (mmdebstrap needs them) but ship nowhere.
//
// TODO: factor this out of cmd/pancake/bootstrap.go into a shared
// internal/layerfilter package so server and client agree by
// construction, not by hand-keeping-in-sync.
var ignorePatterns = []string{
	"/var/cache/", "/var/log/", "/var/lib/apt/",
	"/var/lib/systemd/random-seed",
	"/run/", "/proc/", "/sys/", "/dev/", "/tmp/",
	"/usr/share/man/", "/usr/share/info/", "/usr/share/doc/",
	"/var/lib/ucf/",
	"/var/lib/dpkg/",
	"/etc/apt/",
}

func shouldIgnore(p string) bool {
	for _, pat := range ignorePatterns {
		if strings.HasPrefix(p, pat) {
			return true
		}
	}
	return false
}

// isPerHostPath mirrors the same predicate in cmd/pancake/bootstrap.go.
// These belong in the per-host layer (built client-side) and must
// never enter any server-built layer.
func isPerHostPath(p string) bool {
	switch p {
	case "/etc/hostname",
		"/etc/machine-id",
		"/etc/resolv.conf",
		"/etc/ssh/sshd_config",
		"/etc/systemd/network/10-wired.network",
		"/root/.ssh",
		"/root/.ssh/authorized_keys":
		return true
	}
	return strings.HasPrefix(p, "/etc/ssh/ssh_host_")
}

// buildOnlyPackages: installed in sandbox so mmdebstrap+dpkg work,
// but produce no per-package layer (and their files are claimed in
// ownedPaths so they don't become orphans).
//
// Same set as cmd/pancake/bootstrap.go.
var buildOnlyPackages = map[string]bool{
	"dpkg":                   true,
	"apt":                    true,
	"apt-utils":              true,
	"libapt-pkg6.0t64":       true,
	"gpgv":                   true,
	"debian-archive-keyring": true,
}
