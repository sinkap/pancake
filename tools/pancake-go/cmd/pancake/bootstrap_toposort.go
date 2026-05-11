package main

import (
	"sort"
	"strings"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/deb"
)

// topologicalOrder returns package names in DEPENDENCY-FIRST order
// (libc6 → ... → openssh-server). Caller REVERSES for overlay order.
//
// For "a (>= 1) | b" alternatives, takes the first satisfiable alternative
// (matches the python tooling's behavior). Cycles fall back to arbitrary
// order at the tail; rare in practice for Debian/Ubuntu archives.
func topologicalOrder(pkgs []deb.InstalledPackage, sandbox string) []string {
	nameSet := map[string]bool{}
	for _, p := range pkgs {
		nameSet[p.Name] = true
	}

	deps := map[string]map[string]bool{}  // pkg → {it depends on}
	rdeps := map[string]map[string]bool{} // pkg → {pkgs depending on it}
	for _, p := range pkgs {
		field, _ := deb.PackageField(sandbox, p.Name, "Depends")
		for _, d := range deb.ParseDepends(field) {
			for _, alt := range strings.Split(d, "|") {
				bare := strings.TrimSpace(alt)
				if i := strings.IndexAny(bare, " ("); i >= 0 {
					bare = bare[:i]
				}
				if i := strings.IndexByte(bare, ':'); i >= 0 {
					bare = bare[:i]
				}
				if nameSet[bare] && bare != p.Name {
					if deps[p.Name] == nil {
						deps[p.Name] = map[string]bool{}
					}
					deps[p.Name][bare] = true
					if rdeps[bare] == nil {
						rdeps[bare] = map[string]bool{}
					}
					rdeps[bare][p.Name] = true
					break // first satisfiable alt wins
				}
			}
		}
	}

	// Kahn's: start with nodes with no remaining deps.
	var ready []string
	for _, p := range pkgs {
		if len(deps[p.Name]) == 0 {
			ready = append(ready, p.Name)
		}
	}
	sort.Strings(ready) // determinism
	var out []string
	for len(ready) > 0 {
		n := ready[0]
		ready = ready[1:]
		out = append(out, n)
		var next []string
		for child := range rdeps[n] {
			delete(deps[child], n)
			if len(deps[child]) == 0 {
				next = append(next, child)
			}
		}
		sort.Strings(next)
		ready = append(ready, next...)
	}
	// Cycles: append leftovers in original order.
	seen := map[string]bool{}
	for _, n := range out {
		seen[n] = true
	}
	for _, p := range pkgs {
		if !seen[p.Name] {
			out = append(out, p.Name)
		}
	}
	return out
}
