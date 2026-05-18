// `pancake ca-server`: orchestrator-side wrapper around the step-ca
// container. Five subcommands:
//
//	up          build + start the pancake-ca-server container
//	status      hit step-ca /health, print root fingerprint
//	trust-roots install attestation-root chain into the ACME provisioner
//	            (this is what gates which TPM EKs are accepted —
//	            for swtpm: the /var/lib/swtpm-localca CA; for hardware:
//	            the Intel/Infineon/AMD manufacturer roots)
//	show-config print the current ca.json (debugging)
//	down        stop + remove the container (volume preserved)
//
// All admin operations talk to step-ca via shell-out to the `step`
// CLI baked into the container — that's the documented interface
// for one-shot config edits and we don't want to reimplement
// step-ca's JWS-protected admin API in Go for a single trusted host.
//
// We do NOT ship `step` inside the VM image. The in-VM `pancake
// enroll` uses Go libraries (Slice 2 phase 2) so guest images stay
// minimal.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sinkap/pancake/common/go/kit"
	"github.com/sinkap/pancake/common/go/runner"
)

// Defaults match the Dockerfile's published port and ENV.
const (
	defaultCAContainer    = "pancake-ca-server"
	defaultCAImage        = "pancake-ca-server"
	defaultCAVolume       = "pancake-ca-state"
	defaultCAPort         = 8443
	defaultCAProvisioner  = "tpm"
	defaultCAImageContext = "deployment/docker/ca-server"
)

func cmdCAServer(_ *kit.Kit, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr,
			"usage: pancake ca-server <subcommand>\n"+
				"  up            build + start the pancake-ca-server container\n"+
				"  status        health-check + print root fingerprint\n"+
				"  trust-roots   set --attestation-roots on the ACME-tpm provisioner\n"+
				"                (PEM file containing CA(s) that signed the EKs you'll trust)\n"+
				"  show-config   print the current ca.json\n"+
				"  down          stop + remove the container (volume preserved)")
		return 2
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "up":
		return cmdCAServerUp(args)
	case "status":
		return cmdCAServerStatus(args)
	case "trust-roots":
		return cmdCAServerTrustRoots(args)
	case "show-config":
		return cmdCAServerShowConfig(args)
	case "down":
		return cmdCAServerDown(args)
	default:
		fmt.Fprintf(os.Stderr, "pancake ca-server: unknown subcommand %q\n", sub)
		return 2
	}
}

func cmdCAServerUp(args []string) int {
	fs := flag.NewFlagSet("ca-server up", flag.ContinueOnError)
	repo := fs.String("repo", ".",
		"path to the fs-pancake checkout root (so we can find ca-server/Dockerfile)")
	container := fs.String("container", defaultCAContainer,
		"docker container name")
	image := fs.String("image", defaultCAImage,
		"docker image tag to build + run")
	volume := fs.String("volume", defaultCAVolume,
		"named docker volume for /home/step (CA state)")
	port := fs.Int("port", defaultCAPort,
		"host port to bind step-ca's HTTPS listener to")
	dns := fs.String("dns", "localhost,127.0.0.1",
		"comma-separated DNS / IP entries baked into the CA's leaf SAN")
	caName := fs.String("name", "pancake-ca",
		"CA name embedded in root + intermediate certs")
	build := fs.Bool("build", true,
		"docker build the image before run; pass --build=false to reuse")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctxDir := filepath.Join(*repo, defaultCAImageContext)
	if _, err := os.Stat(filepath.Join(ctxDir, "Dockerfile")); err != nil {
		return die(fmt.Errorf("can't find %s/Dockerfile — pass --repo to the "+
			"fs-pancake root (got --repo=%s)", ctxDir, *repo))
	}

	if *build {
		fmt.Fprintf(os.Stderr, "[ca-server] docker build %s\n", *image)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"docker", "build", "-t", *image, ctxDir},
		}); err != nil {
			return die(err)
		}
	}

	// rm -f tolerates "no such container"; volume create is idempotent.
	_ = runner.Run(runner.Cmd{
		Argv: []string{"docker", "rm", "-f", *container},
	})
	if err := runner.Run(runner.Cmd{
		Argv: []string{"docker", "volume", "create", *volume},
	}); err != nil {
		return die(err)
	}

	fmt.Fprintf(os.Stderr,
		"[ca-server] docker run %s (port %d, volume %s)\n",
		*container, *port, *volume)
	if err := runner.Run(runner.Cmd{
		Argv: []string{"docker", "run", "-d",
			"--name", *container,
			"-p", fmt.Sprintf("%d:8443", *port),
			"-v", *volume + ":/home/step",
			"-e", "PANCAKE_CA_DNS=" + *dns,
			"-e", "PANCAKE_CA_NAME=" + *caName,
			*image},
	}); err != nil {
		return die(err)
	}

	fmt.Fprintf(os.Stderr,
		"[ca-server] up. Verify with: pancake ca-server status --port=%d\n",
		*port)
	return 0
}

func cmdCAServerStatus(args []string) int {
	fs := flag.NewFlagSet("ca-server status", flag.ContinueOnError)
	container := fs.String("container", defaultCAContainer,
		"docker container name")
	port := fs.Int("port", defaultCAPort, "host port")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	out, err := runner.Capture(runner.Cmd{
		Argv: []string{"docker", "exec", *container,
			"step", "certificate", "fingerprint",
			"/home/step/certs/root_ca.crt"},
	})
	if err != nil {
		return die(fmt.Errorf("docker exec fingerprint: %w "+
			"(is the container running? `docker ps`)", err))
	}
	fmt.Printf("step-ca fingerprint: %s\n", strings.TrimSpace(out))

	hOut, hErr := runner.Capture(runner.Cmd{
		Argv: []string{"docker", "exec", *container,
			"curl", "-sk", "https://localhost:8443/health"},
	})
	if hErr != nil {
		return die(fmt.Errorf("/health probe: %w", hErr))
	}
	fmt.Printf("step-ca /health (port %d): %s\n", *port, strings.TrimSpace(hOut))
	return 0
}

func cmdCAServerTrustRoots(args []string) int {
	fs := flag.NewFlagSet("ca-server trust-roots", flag.ContinueOnError)
	container := fs.String("container", defaultCAContainer,
		"docker container name")
	provisioner := fs.String("provisioner", defaultCAProvisioner,
		"ACME provisioner name to install the roots into")
	roots := fs.String("roots", "",
		"PEM file containing the CA cert(s) that signed the EKs you "+
			"trust. For swtpm: usually /var/lib/swtpm-localca/issuercert.pem. "+
			"For hardware TPMs: TPM manufacturer roots (Intel, Infineon, AMD). "+
			"step-ca then accepts ACME-tpm enrollments from any device whose "+
			"EK chains to one of these roots.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *roots == "" {
		fmt.Fprintln(os.Stderr,
			"pancake ca-server trust-roots: --roots required")
		return 2
	}
	pem, err := os.ReadFile(*roots)
	if err != nil {
		return die(fmt.Errorf("read --roots: %w", err))
	}

	// Push the file into the container, then call provisioner update.
	// Admin operations need explicit credentials in non-interactive
	// mode — we pass the JWK admin provisioner created at init time
	// (`pancake-admin`, super-admin subject `step`) plus the password
	// file the init script stashed inside the volume.
	containerPath := fmt.Sprintf("/tmp/%s.attestation-roots.pem", *provisioner)
	if err := runner.Run(runner.Cmd{
		Argv: []string{"docker", "exec", "-i", *container,
			"sh", "-c", fmt.Sprintf("cat > %s", containerPath)},
		Stdin: pem,
	}); err != nil {
		return die(err)
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"docker", "exec", *container,
			"step", "ca", "provisioner", "update", *provisioner,
			"--attestation-roots=" + containerPath,
			"--ca-config=/home/step/config/ca.json"},
	}); err != nil {
		return die(fmt.Errorf("step ca provisioner update: %w", err))
	}

	// Hot-reload step-ca so the new roots take effect without a restart.
	// step-ca documents SIGHUP as the reload signal.
	if err := runner.Run(runner.Cmd{
		Argv: []string{"docker", "kill", "--signal=HUP", *container},
	}); err != nil {
		fmt.Fprintf(os.Stderr,
			"[ca-server] WARN: SIGHUP failed (%v) — `docker restart %s` "+
				"to pick up the new attestation roots\n", err, *container)
		return 1
	}
	fmt.Fprintf(os.Stderr,
		"[ca-server] attestation roots installed on provisioner %q "+
			"(%d bytes); SIGHUP sent to step-ca\n",
		*provisioner, len(pem))
	return 0
}

func cmdCAServerShowConfig(args []string) int {
	fs := flag.NewFlagSet("ca-server show-config", flag.ContinueOnError)
	container := fs.String("container", defaultCAContainer,
		"docker container name")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return runOrDie(runner.Run(runner.Cmd{
		Argv: []string{"docker", "exec", *container,
			"cat", "/home/step/config/ca.json"},
	}))
}

func cmdCAServerDown(args []string) int {
	fs := flag.NewFlagSet("ca-server down", flag.ContinueOnError)
	container := fs.String("container", defaultCAContainer,
		"docker container name")
	purge := fs.Bool("purge-volume", false,
		"also delete the named volume (DESTROYS THE CA — every issued "+
			"cert becomes orphaned). Default: keep state.")
	volume := fs.String("volume", defaultCAVolume,
		"docker volume name (only used with --purge-volume)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := runner.Run(runner.Cmd{
		Argv: []string{"docker", "rm", "-f", *container},
	}); err != nil {
		return die(err)
	}
	if *purge {
		fmt.Fprintf(os.Stderr,
			"[ca-server] PURGING volume %s — all CA state lost\n", *volume)
		if err := runner.Run(runner.Cmd{
			Argv: []string{"docker", "volume", "rm", *volume},
		}); err != nil {
			return die(err)
		}
	}
	return 0
}

func runOrDie(err error) int {
	if err != nil {
		return die(err)
	}
	return 0
}
