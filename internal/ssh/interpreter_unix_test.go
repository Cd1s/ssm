//go:build unix

package ssh

import (
	"os/exec"
	"strings"
	"testing"
)

func runGeneratedScript(t *testing.T, script ScriptSpec) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", BuildScriptRunner(script)) //nolint:gosec // fixed Unix test runner exercising generated quoting
	cmd.Stdin = strings.NewReader(script.Body)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestNonShellRunnerExecutesPythonFromStdinWithExactArgs(t *testing.T) {
	// The interpreter is only skipped where it is absent (for example a
	// minimal Windows/macOS CI image); Windows never reaches this Unix file.
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed on this host")
	}
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
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed on this host")
	}
	script, err := PrepareScript("t.sh", []byte("#!/usr/bin/env bash\r\narr=(x y)\r\necho \"${arr[1]}-$1\"\r\n"), "", []string{"z"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := runGeneratedScript(t, script)
	if err != nil || out != "y-z\n" {
		t.Fatalf("err=%v out=%q", err, out)
	}
}
