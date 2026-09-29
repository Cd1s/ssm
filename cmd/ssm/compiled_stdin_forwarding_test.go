package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ssm/internal/config"
)

// newCompiledStdinFixture serves the cross-platform fake SSH host whose "cat"
// command echoes forwarded stdin byte for byte, so these tests run unchanged
// on Windows native CI.
func newCompiledStdinFixture(t *testing.T) *compiledCLIHarness {
	t.Helper()
	const password = "STDIN_FORWARDING_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("alpha", password)}})
	return cli
}

// decodeCompiledStdinFailure decodes the one JSON failure document a
// rejected run wrote to stdout or stderr.
func decodeCompiledStdinFailure(t *testing.T, result compiledCLIResult) map[string]any {
	t.Helper()
	text := result.Stdout
	if strings.TrimSpace(text) == "" {
		text = result.Stderr
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(text), &document); err != nil {
		t.Fatalf("output is not one JSON object: %v; output=%s", err, compiledOutputIdentity(result))
	}
	return document
}

func TestCompiledJSONRunStdinFlagForwardsPipe(t *testing.T) {
	cli := newCompiledStdinFixture(t)
	result := cli.Run(t, "sshctl", []byte("a\nb\n"), "--offline", "--json", "run", "alpha", "--stdin", "--argv", "cat")
	document := assertCompiledJSONSuccess(t, result)
	if document["stdout"] != "a\nb\n" {
		t.Fatalf("stdout = %#v, want forwarded stdin", document["stdout"])
	}
	if document["stdin_forwarded"] != true {
		t.Fatalf("stdin_forwarded = %#v, want true", document["stdin_forwarded"])
	}
	if _, present := document["warning"]; present {
		t.Fatalf("forwarded result carries a warning: %#v", document["warning"])
	}
}

func TestCompiledHumanRunForwardsNonTTYStdinByDefault(t *testing.T) {
	cli := newCompiledStdinFixture(t)
	result := cli.Run(t, "sshctl", []byte("hello\n"), "--offline", "run", "alpha", "--argv", "cat")
	if result.ProcessExit != 0 || result.Stdout != "hello\n" || result.Stderr != "" {
		t.Fatalf("human default did not forward piped stdin: exit=%d %s", result.ProcessExit, compiledOutputIdentity(result))
	}
}

func TestCompiledHumanRunForwardsSlowUpstreamWithoutProbe(t *testing.T) {
	cli := newCompiledStdinFixture(t)
	reader, writer := io.Pipe()
	go func() {
		time.Sleep(1200 * time.Millisecond)
		_, _ = io.WriteString(writer, "late\n")
		_ = writer.Close()
	}()
	result := cli.runWithStdin(t, "sshctl", reader, map[string]string{"SSM_MASTER_PASS_FILE": cli.passPath}, "--offline", "run", "alpha", "--argv", "cat")
	if result.ProcessExit != 0 || result.Stdout != "late\n" {
		t.Fatalf("slow upstream was dropped: exit=%d %s", result.ProcessExit, compiledOutputIdentity(result))
	}
}

func TestCompiledJSONRunDefaultReportsUnforwardedPipe(t *testing.T) {
	cli := newCompiledStdinFixture(t)
	result := cli.Run(t, "sshctl", []byte("data\n"), "--offline", "--json", "run", "alpha", "--argv", "cat")
	document := assertCompiledJSONSuccess(t, result)
	if _, present := document["stdout"]; present {
		t.Fatalf("--json default forwarded stdin: %#v", document["stdout"])
	}
	if document["stdin_forwarded"] != false {
		t.Fatalf("stdin_forwarded = %#v, want false", document["stdin_forwarded"])
	}
	warning, _ := document["warning"].(string)
	if !strings.Contains(warning, "--stdin") {
		t.Fatalf("warning = %q, want a pointer to --stdin", warning)
	}
}

func TestCompiledJSONRunOmitsStdinMarkerForNullDevice(t *testing.T) {
	cli := newCompiledStdinFixture(t)
	result := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "alpha", "--argv", "true")
	document := assertCompiledJSONSuccess(t, result)
	for _, key := range []string{"stdin_forwarded", "warning"} {
		if _, present := document[key]; present {
			t.Fatalf("null-device stdin produced %s = %#v", key, document[key])
		}
	}
}

func TestCompiledRunNoStdinDoesNotForward(t *testing.T) {
	cli := newCompiledStdinFixture(t)
	human := cli.Run(t, "sshctl", []byte("hidden\n"), "--offline", "run", "alpha", "--no-stdin", "--argv", "cat")
	if human.ProcessExit != 0 || human.Stdout != "" {
		t.Fatalf("--no-stdin forwarded stdin: %s", compiledOutputIdentity(human))
	}
	jsonResult := cli.Run(t, "sshctl", []byte("hidden\n"), "--offline", "--json", "run", "alpha", "--no-stdin", "--argv", "cat")
	document := assertCompiledJSONSuccess(t, jsonResult)
	if _, present := document["stdout"]; present {
		t.Fatalf("--no-stdin forwarded stdin in JSON: %#v", document["stdout"])
	}
	if _, present := document["warning"]; present {
		t.Fatalf("explicit --no-stdin produced a warning: %#v", document["warning"])
	}
}

func TestCompiledRunStdinFileIsEquivalentToRedirect(t *testing.T) {
	cli := newCompiledStdinFixture(t)
	path := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := cli.Run(t, "sshctl", []byte("ignored-pipe\n"), "--offline", "--json", "run", "alpha", "--stdin-file", path, "--argv", "cat")
	document := assertCompiledJSONSuccess(t, result)
	if document["stdout"] != "from-file\n" || document["stdin_forwarded"] != true {
		t.Fatalf("stdin-file result = %#v", document)
	}
	human := cli.Run(t, "sshctl", nil, "--offline", "run", "alpha", "--stdin-file="+path, "--argv", "cat")
	if human.ProcessExit != 0 || human.Stdout != "from-file\n" {
		t.Fatalf("human --stdin-file: %s", compiledOutputIdentity(human))
	}
	missing := cli.Run(t, "sshctl", nil, "--offline", "run", "alpha", "--json", "--stdin-file", filepath.Join(t.TempDir(), "absent"), "--argv", "cat")
	failure := decodeCompiledStdinFailure(t, missing)
	if missing.ProcessExit != 2 || failure["error"] != "invalid_arguments" {
		t.Fatalf("missing stdin file: exit=%d %#v", missing.ProcessExit, failure)
	}
}

func TestCompiledSSMForwardStdinEnvironment(t *testing.T) {
	cli := newCompiledStdinFixture(t)
	forwardEnv := map[string]string{"SSM_FORWARD_STDIN": "1"}
	result := cli.RunWithEnv(t, "sshctl", []byte("env-on\n"), forwardEnv, "--offline", "--json", "run", "alpha", "--argv", "cat")
	document := assertCompiledJSONSuccess(t, result)
	if document["stdout"] != "env-on\n" || document["stdin_forwarded"] != true {
		t.Fatalf("SSM_FORWARD_STDIN=1 --json result = %#v", document)
	}
	off := cli.RunWithEnv(t, "sshctl", []byte("env-off\n"), map[string]string{"SSM_FORWARD_STDIN": "0"}, "--offline", "run", "alpha", "--argv", "cat")
	if off.ProcessExit != 0 || off.Stdout != "" {
		t.Fatalf("SSM_FORWARD_STDIN=0 forwarded stdin: %s", compiledOutputIdentity(off))
	}
	flagOn := cli.RunWithEnv(t, "sshctl", []byte("flag-on\n"), map[string]string{"SSM_FORWARD_STDIN": "0"}, "--offline", "run", "alpha", "--stdin", "--argv", "cat")
	if flagOn.Stdout != "flag-on\n" {
		t.Fatalf("--stdin did not override SSM_FORWARD_STDIN=0: %s", compiledOutputIdentity(flagOn))
	}
	flagOff := cli.RunWithEnv(t, "sshctl", []byte("flag-off\n"), forwardEnv, "--offline", "run", "alpha", "--no-stdin", "--argv", "cat")
	if flagOff.Stdout != "" {
		t.Fatalf("--no-stdin did not override SSM_FORWARD_STDIN=1: %s", compiledOutputIdentity(flagOff))
	}
}

func TestCompiledStdinOptionsRejectedWhereStdinIsNotAvailable(t *testing.T) {
	cli := newCompiledStdinFixture(t)
	script := filepath.Join(t.TempDir(), "s.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(payload, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"script -f with --stdin":       {"run", "alpha", "-f", script, "--stdin"},
		"script -f with --stdin-file":  {"run", "alpha", "--stdin-file", payload, "-f", script},
		"script -s with --stdin":       {"run", "alpha", "-s", "--stdin"},
		"scripts with --stdin":         {"run", "alpha", "--scripts", script, "--stdin"},
		"map with --stdin":             {"map", "alpha", "--stdin", "--argv", "cat"},
		"map with --stdin-file":        {"map", "alpha", "--stdin-file", payload, "--argv", "cat"},
		"stream with --stdin":          {"run", "alpha", "--stream", "--stdin"},
		"stream with --stdin-file":     {"run", "alpha", "--stream", "--stdin-file", payload},
		"--stdin with --no-stdin":      {"run", "alpha", "--stdin", "--no-stdin", "--argv", "cat"},
		"--stdin-file with --no-stdin": {"run", "alpha", "--stdin-file", payload, "--no-stdin", "--argv", "cat"},
		"--stdin with --stdin-file":    {"run", "alpha", "--stdin", "--stdin-file", payload, "--argv", "cat"},
	} {
		t.Run(name, func(t *testing.T) {
			// Argument errors are rendered as JSON when --json follows the alias.
			full := append([]string{"--offline", args[0], args[1], "--json"}, args[2:]...)
			result := cli.Run(t, "sshctl", []byte("ignored\n"), full...)
			if result.ProcessExit != 2 {
				t.Fatalf("exit = %d, want 2; output=%s", result.ProcessExit, compiledOutputIdentity(result))
			}
			failure := decodeCompiledStdinFailure(t, result)
			if failure["error"] != "invalid_arguments" || failure["ok"] != false {
				t.Fatalf("failure = %#v", failure)
			}
		})
	}
}

func TestCompiledRunExitsAfterRemoteExitWithHeldOpenStdin(t *testing.T) {
	cli := newCompiledStdinFixture(t)
	// The default human run forwards the (never-closing) pipe; the forwarding
	// goroutine must not keep the process alive once the remote command ended.
	result := cli.RunWithHeldOpenStdin(t, "sshctl", "--offline", "run", "alpha", "--argv", "true")
	if result.ProcessExit != 0 {
		t.Fatalf("exit = %d, want 0: %s", result.ProcessExit, compiledOutputIdentity(result))
	}
	jsonResult := cli.RunWithHeldOpenStdin(t, "sshctl", "--offline", "--json", "run", "alpha", "--stdin", "--argv", "true")
	assertCompiledJSONSuccess(t, jsonResult)
}

func TestCompiledConnectionFailureDoesNotReportStdinForwarded(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	refused := newCompiledRefusedTCPPort(t)
	const password = "STDIN_REFUSED_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
		Name: "refused", Host: refused.host, Port: refused.port, User: "runner", Password: password,
	}}})
	for name, args := range map[string][]string{
		"--stdin":      {"--offline", "run", "refused", "--json", "--stdin", "--argv", "cat"},
		"json default": {"--offline", "run", "refused", "--json", "--argv", "cat"},
		"--stdin-file": nil,
	} {
		if args == nil {
			path := filepath.Join(t.TempDir(), "in.txt")
			if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			args = []string{"--offline", "run", "refused", "--json", "--stdin-file", path, "--argv", "cat"}
		}
		t.Run(name, func(t *testing.T) {
			result := cli.Run(t, "sshctl", []byte("data\n"), args...)
			if result.ProcessExit == 0 {
				t.Fatalf("connection to a refused port succeeded: %s", compiledOutputIdentity(result))
			}
			failure := decodeCompiledStdinFailure(t, result)
			if value, present := failure["stdin_forwarded"]; present {
				t.Fatalf("failed connection reported stdin_forwarded = %#v", value)
			}
			if _, present := failure["warning"]; present {
				t.Fatal("failed connection carried a stdin warning")
			}
		})
	}
}
