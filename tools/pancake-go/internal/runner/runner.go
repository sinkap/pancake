// Package runner is the central subprocess wrapper used by every pancake
// tool. It mirrors pancake_lib.run() from the Python implementation:
//
//   - Logs "  ▸ <command>" to stderr before exec, so the user sees what
//     mounts/verity ops are happening (the trace is useful for both teaching
//     and debugging the kernel-stress path).
//   - Conditionally prefixes "sudo" only when not already root, so the same
//     code works on the host (kpsingh + sudo) and inside the booted VM
//     (root, no sudo binary present).
//   - Two flavors: Run streams stdout/stderr through; Capture returns stdout
//     as a string for tools that need to parse output (dpkg-query, etc).
package runner

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Cmd describes one invocation. Sudo=true means "use sudo if euid != 0".
type Cmd struct {
	Argv  []string
	Env   []string // appended to os.Environ(); KEY=VAL form
	Sudo  bool
	Stdin []byte // optional; written to the process's stdin
}

// log prints the trace line in the same shape as pancake_lib.run().
func log(argv []string) {
	fmt.Fprintf(os.Stderr, "  ▸ %s\n", strings.Join(argv, " "))
}

// resolved returns the final argv after the optional sudo prefix.
func (c Cmd) resolved() []string {
	if c.Sudo && os.Geteuid() != 0 {
		return append([]string{"sudo"}, c.Argv...)
	}
	return c.Argv
}

// Run streams stdout and stderr to the parent. Returns nil on rc=0, an error
// otherwise; the error message includes the failing argv and the rc so the
// caller doesn't have to re-format it.
func Run(c Cmd) error {
	argv := c.resolved()
	log(argv)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = os.Stderr // pancake mirrors python: traces + tool output go to stderr
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), c.Env...)
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return nil
}

// RunOK is Run but ignores non-zero exits (matches python's check=False).
// The error is still returned for IO/exec failures (binary not found, etc).
func RunOK(c Cmd) error {
	argv := c.resolved()
	log(argv)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), c.Env...)
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return nil // non-zero exit, by request, ignored
		}
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return nil
}

// Capture returns stdout as a string. stderr passes through to the parent
// so error messages from the child are still visible.
func Capture(c Cmd) (string, error) {
	argv := c.resolved()
	log(argv)
	cmd := exec.Command(argv[0], argv[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), c.Env...)
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return out.String(), nil
}

// Pipe runs `producer | consumer` with stderr passing through. Used by
// stage_files to do `tar -c | tar -x` between two locations. Returns the
// first non-nil error from either side.
func Pipe(producer, consumer Cmd) error {
	pArgv := producer.resolved()
	cArgv := consumer.resolved()
	log(append(append([]string{}, pArgv...), append([]string{"|"}, cArgv...)...))

	pCmd := exec.Command(pArgv[0], pArgv[1:]...)
	pCmd.Stderr = os.Stderr
	pCmd.Env = append(os.Environ(), producer.Env...)
	stdout, err := pCmd.StdoutPipe()
	if err != nil {
		return err
	}

	cCmd := exec.Command(cArgv[0], cArgv[1:]...)
	cCmd.Stdin = stdout
	cCmd.Stdout = os.Stderr
	cCmd.Stderr = os.Stderr
	cCmd.Env = append(os.Environ(), consumer.Env...)

	if err := pCmd.Start(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(pArgv, " "), err)
	}
	if err := cCmd.Start(); err != nil {
		_ = pCmd.Wait()
		return fmt.Errorf("%s: %w", strings.Join(cArgv, " "), err)
	}
	pErr := pCmd.Wait()
	cErr := cCmd.Wait()
	if pErr != nil {
		return fmt.Errorf("producer %s: %w", strings.Join(pArgv, " "), pErr)
	}
	if cErr != nil {
		return fmt.Errorf("consumer %s: %w", strings.Join(cArgv, " "), cErr)
	}
	return nil
}
