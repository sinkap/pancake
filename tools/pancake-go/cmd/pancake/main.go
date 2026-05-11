// pancake — operate on a pancake-os kit (list / history / show / add /
// install / activate / rollback / swap).
//
// Subcommands are dispatched manually rather than via cobra/urfave to keep
// the binary tiny and dependency-free. Each subcommand has its own *flag.FlagSet
// so flags don't bleed across.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/sinkap/fs-pancake/tools/pancake-go/internal/kit"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: pancake [--kit DIR] <subcommand> [args]

  list                show packages in the active generation
  history             list all generations
  show <pkg>          dump a package manifest
  activate <id>       set current → generations/<id>
  rollback            current → previous generation

  add <foo.deb>       build a new layer from a .deb + create gen N+1
                      (requires --keep-sandbox or runs materialize_current)
  install <pkg>...    apt-resolve + build deps as layers + create gen N+1
  swap [<id>]         live pivot_root onto a generation (in-VM only)

Default --kit is /var/lib/pancake (the in-system path).`)
}

func main() {
	// global --kit must come before subcommand
	kitDir := "/var/lib/pancake"
	args := os.Args[1:]
	if len(args) >= 2 && args[0] == "--kit" {
		kitDir, args = args[1], args[2:]
	} else if len(args) >= 1 && len(args[0]) > 6 && args[0][:6] == "--kit=" {
		kitDir, args = args[0][6:], args[1:]
	}
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	sub, args := args[0], args[1:]

	if sub == "-h" || sub == "--help" || sub == "help" {
		usage()
		return
	}

	k, err := kit.Open(kitDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pancake: %v\n", err)
		os.Exit(1)
	}

	var rc int
	switch sub {
	case "list":
		rc = cmdList(k, args)
	case "history":
		rc = cmdHistory(k, args)
	case "show":
		rc = cmdShow(k, args)
	case "activate":
		rc = cmdActivate(k, args)
	case "rollback":
		rc = cmdRollback(k, args)
	case "add", "install", "swap":
		fmt.Fprintf(os.Stderr, "pancake: %q not yet implemented in the Go port\n", sub)
		rc = 2
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "pancake: unknown subcommand %q\n", sub)
		usage()
		rc = 2
	}
	os.Exit(rc)
}

func cmdList(k *kit.Kit, _ []string) int {
	gen, err := k.CurrentGeneration()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	m, err := kit.ReadGenerationManifest(filepath.Join(gen, "manifest.toml"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("generation %d  (%s)\n", m.Generation.ID, m.Generation.Description)
	fmt.Printf("  created: %s\n", m.Generation.Created)
	fmt.Printf("  layers : %d\n", len(m.Layer))
	fmt.Println()
	fmt.Printf("  %-36s  %-28s\n", "name", "version")
	for _, L := range m.Layer {
		fmt.Printf("  %-36s  %-28s\n", L.Name, L.Version)
	}
	return 0
}

func cmdHistory(k *kit.Kit, _ []string) int {
	curID, err := k.CurrentID()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ids, err := k.SortGenerations()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("  %4s  %-25s  %6s  %s\n", "id", "created", "layers", "description")
	for _, id := range ids {
		path := filepath.Join(k.Generations(), strconv.Itoa(id), "manifest.toml")
		m, err := kit.ReadGenerationManifest(path)
		if err != nil {
			continue
		}
		marker := "  "
		if id == curID {
			marker = " *"
		}
		fmt.Printf("%s%4d  %-25s  %6d  %s\n",
			marker, id, m.Generation.Created, len(m.Layer),
			m.Generation.Description)
	}
	return 0
}

func cmdShow(k *kit.Kit, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: pancake show <pkg>")
		return 2
	}
	pkg := args[0]
	gen, err := k.CurrentGeneration()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	m, err := kit.ReadGenerationManifest(filepath.Join(gen, "manifest.toml"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, L := range m.Layer {
		if L.Name == pkg {
			path := filepath.Join(k.Dir, L.Manifest)
			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			fmt.Print(string(data))
			return 0
		}
	}
	fmt.Fprintf(os.Stderr, "pancake: %s not in current generation\n", pkg)
	return 1
}

func cmdActivate(k *kit.Kit, args []string) int {
	fs := flag.NewFlagSet("activate", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pancake activate <id>")
		return 2
	}
	id, err := strconv.Atoi(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pancake: bad generation id: %v\n", err)
		return 2
	}
	target := filepath.Join(k.Generations(), strconv.Itoa(id))
	if _, err := os.Stat(target); err != nil {
		fmt.Fprintf(os.Stderr, "pancake: no such generation: %d\n", id)
		return 1
	}
	if err := k.SetCurrent(id); err != nil {
		fmt.Fprintf(os.Stderr, "pancake: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[pancake] current → generations/%d\n", id)
	return 0
}

func cmdRollback(k *kit.Kit, _ []string) int {
	curID, err := k.CurrentID()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cur := filepath.Join(k.Generations(), strconv.Itoa(curID), "manifest.toml")
	m, err := kit.ReadGenerationManifest(cur)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if m.Generation.Parent == 0 {
		fmt.Fprintln(os.Stderr, "pancake: current generation has no parent")
		return 1
	}
	return cmdActivate(k, []string{strconv.Itoa(m.Generation.Parent)})
}

// Currently-unused helper kept for the install/swap port. Sorting helper
// is right here so we don't pull in extra packages.
var _ = sort.Ints
