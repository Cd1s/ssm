//go:build unix

package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// The classic "ssh -n" problem: a loop that reads hosts from stdin and runs
// sshctl inside must see every line when each call opts out of forwarding.
func TestCompiledNoStdinKeepsCallerLoopInput(t *testing.T) {
	cli, _ := newCompiledExecRunHarness(t, "loop")
	loop := `while read h; do "$SSHCTL" --offline run loop --no-stdin --argv echo "$h"; done`
	cmd := exec.Command("sh", "-c", loop) //nolint:gosec // fixed shell loop driving the test-built compiled CLI
	cmd.Env = isolatedCompiledCLIEnvironmentWith(cli.home, cli.temp, map[string]string{
		"SSM_MASTER_PASS_FILE": cli.passPath,
		"SSHCTL":               cli.paths["sshctl"],
	})
	cmd.Stdin = strings.NewReader("h1\nh2\nh3\nh4\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("loop failed: %v; stderr=%q", err, stderr.String())
	}
	if got := stdout.String(); got != "h1\nh2\nh3\nh4\n" {
		t.Fatalf("loop output = %q, want every input line processed; stderr=%q", got, stderr.String())
	}
}

func TestCompiledDefaultForwardingInLoopConsumesRemainingInput(t *testing.T) {
	cli, _ := newCompiledExecRunHarness(t, "loop")
	// Documents the default: without --no-stdin the first call forwards the
	// rest of the caller's stdin to the remote command.
	loop := `while read h; do "$SSHCTL" --offline run loop --argv cat; done`
	cmd := exec.Command("sh", "-c", loop) //nolint:gosec // fixed shell loop driving the test-built compiled CLI
	cmd.Env = isolatedCompiledCLIEnvironmentWith(cli.home, cli.temp, map[string]string{
		"SSM_MASTER_PASS_FILE": cli.passPath,
		"SSHCTL":               cli.paths["sshctl"],
	})
	cmd.Stdin = strings.NewReader("h1\nh2\nh3\n")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != "h2\nh3\n" {
		t.Fatalf("default forwarding output = %q, want the remaining lines echoed once", got)
	}
}

func TestCompiledJSONRunStdinBinarySafeThroughRealShell(t *testing.T) {
	cli, _ := newCompiledExecRunHarness(t, "bin")
	result := cli.Run(t, "sshctl", []byte("x y\n"), "--offline", "--json", "run", "bin", "--stdin", "--argv", "sh", "-c", "tr a-z A-Z")
	document := assertCompiledJSONSuccess(t, result)
	if document["stdout"] != "X Y\n" || document["stdin_forwarded"] != true {
		t.Fatalf("result = %#v", document)
	}
}
