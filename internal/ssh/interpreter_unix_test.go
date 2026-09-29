//go:build unix

package ssh

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// requireInterpreter skips when a real interpreter is missing locally, but
// fails on GitHub Actions so acceptance tests cannot be silently skipped there.
func requireInterpreter(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("%s is required on CI but was not found: %v", name, err)
		}
		t.Skipf("%s is not installed on this host", name)
	}
}

func runGeneratedScript(t *testing.T, script ScriptSpec) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", BuildScriptRunner(script)) //nolint:gosec // fixed Unix test runner exercising generated quoting
	cmd.Stdin = strings.NewReader(script.Body)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestNonShellRunnerExecutesPythonFromStdinWithExactArgs(t *testing.T) {
	requireInterpreter(t, "python3")
	body := "import sys\nprint(sys.argv[1:])\nprint(len(sys.argv))\n"
	for _, interpreter := range []string{"python3", "env python3"} {
		script, err := PrepareScriptWithInterpreter("t.py", []byte(body), "", interpreter, []string{"a", "b c", "it's", "-x", "--"})
		if err != nil {
			t.Fatal(err)
		}
		out, err := runGeneratedScript(t, script)
		if err != nil {
			t.Fatalf("%s: %v\n%s", interpreter, err, out)
		}
		if want := "['a', 'b c', \"it's\", '-x', '--']\n6\n"; out != want {
			t.Fatalf("%s: output = %q, want %q", interpreter, out, want)
		}
	}
}

func TestNonShellRunnerMissingInterpreterUsesInterpreterMarker(t *testing.T) {
	script, err := PrepareScriptWithInterpreter("t", []byte("x\n"), "", "no-such-interpreter-81", nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := runGeneratedScript(t, script)
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 127 || !strings.Contains(out, "no-such-interpreter-81") {
		t.Fatalf("err=%v out=%q", err, out)
	}
	env, err := PrepareScriptWithInterpreter("t", []byte("x\n"), "", "env no-such-interpreter-81", nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err = runGeneratedScript(t, env)
	exitErr, ok = err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 127 {
		t.Fatalf("env form: err=%v out=%q", err, out)
	}
}

func TestInterpreterValueCannotInjectCommands(t *testing.T) {
	marker := t.TempDir() + "/pwned"
	for _, value := range []string{"python3; touch " + marker, "$(touch " + marker + ")", "`touch " + marker + "`", "env python3; touch " + marker} {
		if _, err := PrepareScriptWithInterpreter("t", []byte("x\n"), "", value, nil); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestShebangBashScriptRunsWithBash(t *testing.T) {
	requireInterpreter(t, "bash")
	script, err := PrepareScript("t.sh", []byte("#!/usr/bin/env bash\r\narr=(x y)\r\necho \"${arr[1]}-$1\"\r\n"), "", []string{"z"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := runGeneratedScript(t, script)
	if err != nil || out != "y-z\n" {
		t.Fatalf("err=%v out=%q", err, out)
	}
}

func TestNonShellRunnerPassesSecretsToPythonEnvironment(t *testing.T) {
	requireInterpreter(t, "python3")
	body := "import os\nprint('token=<%s>' % os.environ['TOKEN'])\nprint('arg=<%s>' % os.environ.get('ARGV1', 'none'))\n"
	script, err := PrepareScriptWithInterpreter("t.py", []byte(body), "", "python3", nil)
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"TOKEN": "secret with ' quote and $x"}
	remote := BuildScriptRemoteCommand(BuildScriptRunner(script), secrets)
	cmd := exec.Command("sh", "-c", remote) //nolint:gosec // fixed Unix test runner exercising generated quoting
	cmd.Stdin = strings.NewReader(script.Body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("runner failed: %v\n%s", err, out)
	}
	if want := "token=<secret with ' quote and $x>\narg=<none>\n"; string(out) != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}
