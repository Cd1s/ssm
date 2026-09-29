package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

type interpreterFixture struct {
	*remoteArgvFixture
}

func newInterpreterFixture(t *testing.T, contains, stdout string, stderr []string, exit uint32) interpreterFixture {
	t.Helper()
	const password = "INTERPRETER_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	recorder := &remoteArgvRecorder{}
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password:           password,
		RunCommandContains: contains,
		RunStdoutFragments: []string{stdout},
		RunStderrFragments: stderr,
		RunExitStatus:      exit,
		RunDrainStdin:      true,
		RecordCommand:      recorder.record,
	})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("alpha", password)}})
	return interpreterFixture{&remoteArgvFixture{cli: cli, server: server, recorder: recorder}}
}

func (f interpreterFixture) script(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(f.cli.temp, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCompiledInterpreterPythonScriptOverStdin(t *testing.T) {
	f := newInterpreterFixture(t, "command -v 'python3'", "['a', 'b']\n", nil, 0)
	script := f.script(t, "t.py", "import sys\nprint(sys.argv[1:])\n")
	result := f.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "alpha", "-f", script, "--interpreter", "python3", "--", "a", "b")
	document := assertCompiledJSONSuccess(t, result)
	if document["interpreter"] != "python3" || document["stdout"] != "['a', 'b']\n" {
		t.Fatalf("document = %#v", document)
	}
	f.requireCommand(t, "command -v 'python3'", "exec 'python3' '-' 'a' 'b'")
	if command := f.recorder.Commands()[0]; strings.Contains(command, "sys.argv") || f.server.SessionCount() != 1 {
		t.Fatalf("script body must travel over stdin in exactly one session: %q sessions=%d", command, f.server.SessionCount())
	}
}

func TestCompiledInterpreterEnvFormAndStdinScript(t *testing.T) {
	f := newInterpreterFixture(t, "command -v 'python3'", "ok\n", nil, 0)
	result := f.cli.Run(t, "sshctl", []byte("print(1)\n"), "--offline", "run", "alpha", "-s", "--interpreter", "env python3", "--", "x")
	if result.ProcessExit != 0 || !strings.Contains(result.Stdout, "ok\n") {
		t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
	}
	f.requireCommand(t, "exec 'env' 'python3' '-' 'x'")
}

func TestCompiledShebangBashIsRespectedWithoutInterpreter(t *testing.T) {
	f := newInterpreterFixture(t, "command -v 'bash'", "bash-ran\n", nil, 0)
	script := f.script(t, "t.sh", "#!/usr/bin/env bash\r\narr=(a b)\r\necho ${arr[1]}\r\n")
	result := f.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "alpha", "-f", script)
	document := assertCompiledJSONSuccess(t, result)
	if document["interpreter"] != "bash" {
		t.Fatalf("document = %#v", document)
	}
	f.requireCommand(t, "exec 'bash' '-s' '--'")
}

func TestCompiledNonShellShebangWithoutInterpreterIsInvalidArguments(t *testing.T) {
	f := newInterpreterFixture(t, "never", "", nil, 0)
	script := f.script(t, "t.py", "#!/usr/bin/env python3\nprint(1)\n")
	result := f.cli.Run(t, "sshctl", nil, "--offline", "run", "alpha", "--json", "-f", script)
	document := decodeExactlyOneJSONObject(t, result.Stdout)
	hint, _ := document["hint"].(string)
	if result.ProcessExit != 2 || document["ok"] != false || document["error"] != "invalid_arguments" || !strings.Contains(hint, "--interpreter python3") {
		t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
	}
	if f.server.SessionCount() != 0 {
		t.Fatalf("validation must fail before any SSH session; sessions=%d", f.server.SessionCount())
	}
}

func TestCompiledInterpreterRejectsUnsafeValuesAndShellPreflight(t *testing.T) {
	f := newInterpreterFixture(t, "never", "", nil, 0)
	script := f.script(t, "t.py", "print(1)\n")
	for name, args := range map[string][]string{
		"injection":         {"--interpreter", "python3; touch /tmp/pwned"},
		"interpreter flags": {"--interpreter", "python3 -u"},
		"preflight":         {"--interpreter", "python3", "--preflight"},
	} {
		t.Run(name, func(t *testing.T) {
			argv := append([]string{"--offline", "run", "alpha", "--json", "-f", script}, args...)
			result := f.cli.Run(t, "sshctl", nil, argv...)
			document := decodeExactlyOneJSONObject(t, result.Stdout)
			if result.ProcessExit != 2 || document["error"] != "invalid_arguments" {
				t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
			}
		})
	}
	if f.server.SessionCount() != 0 {
		t.Fatalf("sessions = %d", f.server.SessionCount())
	}
}

func TestCompiledMissingNonShellInterpreterIsInterpreterNotFound(t *testing.T) {
	f := newInterpreterFixture(t, "command -v 'python3'", "", []string{machinecontract.InterpreterNotFoundDiagnostic("python3") + "\n"}, 127)
	script := f.script(t, "t.py", "print(1)\n")
	result := f.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "alpha", "-f", script, "--interpreter", "python3")
	document := decodeExactlyOneJSONObject(t, result.Stdout)
	hint, _ := document["hint"].(string)
	if result.ProcessExit != 127 || document["error"] != "interpreter_not_found" || document["stage"] != "interpreter" ||
		!strings.Contains(hint, `remote interpreter "python3" is unavailable`) {
		t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
	}
}

func TestCompiledRequestInterpreter(t *testing.T) {
	f := newInterpreterFixture(t, "command -v 'python3'", "req-ok\n", nil, 0)
	script := f.script(t, "t.py", "print(1)\n")
	body := `{"version":1,"op":"run","alias":"alpha","script_file":` + jsonString(t, script) + `,"script_args":["a"],"interpreter":"python3"}`
	result := f.cli.Run(t, "sshctl", []byte(body), "--offline", "request", "--file", "-")
	document := assertCompiledJSONSuccess(t, result)
	if document["interpreter"] != "python3" {
		t.Fatalf("document = %#v", document)
	}
	f.requireCommand(t, "exec 'python3' '-' 'a'")
	if f.server.SessionCount() != 1 {
		t.Fatalf("no preflight session is expected for a non-shell interpreter; sessions=%d", f.server.SessionCount())
	}
}

func jsonString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
