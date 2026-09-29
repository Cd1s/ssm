package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"ssm/internal/config"
)

// remoteArgvRecorder collects the exact command lines the fake SSH server
// receives so tests can prove which tokens reached the remote side.
type remoteArgvRecorder struct {
	mu       sync.Mutex
	commands []string
}

func (r *remoteArgvRecorder) record(command string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, command)
}

func (r *remoteArgvRecorder) Commands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.commands...)
}

type remoteArgvFixture struct {
	cli      *compiledCLIHarness
	server   *compiledSSHFixture
	recorder *remoteArgvRecorder
}

func newRemoteArgvFixture(t *testing.T, contains, stdout string, exit uint32) *remoteArgvFixture {
	t.Helper()
	const password = "REMOTE_ARGV_BOUNDARY_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	recorder := &remoteArgvRecorder{}
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password:           password,
		RunCommandContains: contains,
		RunStdoutFragments: []string{stdout},
		RunExitStatus:      exit,
		RunDrainStdin:      true,
		RecordCommand:      recorder.record,
	})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("alpha", password)}})
	return &remoteArgvFixture{cli: cli, server: server, recorder: recorder}
}

func (f *remoteArgvFixture) requireCommand(t *testing.T, want ...string) {
	t.Helper()
	commands := f.recorder.Commands()
	if len(commands) == 0 {
		t.Fatalf("remote command was never executed; sessions=%d", f.server.SessionCount())
	}
	for _, fragment := range want {
		if !strings.Contains(commands[0], fragment) {
			t.Fatalf("remote command %q does not contain %q", commands[0], fragment)
		}
	}
}

func requireNoSSHCTLUsage(t *testing.T, result compiledCLIResult) {
	t.Helper()
	if strings.Contains(result.Stdout, "Usage:") || strings.Contains(result.Stderr, "Usage:") {
		t.Fatalf("sshctl captured a remote argv token as help: %s", compiledOutputIdentity(result))
	}
}

func TestCompiledRemoteArgvBoundaryExecutesRemoteHelpAndHumanFlags(t *testing.T) {
	for _, executable := range []string{"sshctl", "ssm"} {
		runVerb := "run"
		if executable == "ssm" {
			runVerb = "exec"
		}
		t.Run(executable+" --argv df -h exits with the remote status", func(t *testing.T) {
			f := newRemoteArgvFixture(t, "df", "df-ran\n", 7)
			result := f.cli.Run(t, executable, nil, "--offline", runVerb, "alpha", "--argv", "df", "-h")
			requireNoSSHCTLUsage(t, result)
			if result.ProcessExit != 7 || !strings.Contains(result.Stdout, "df-ran\n") {
				t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
			}
			f.requireCommand(t, "'df' '-h'")
		})
		t.Run(executable+" -- free -h", func(t *testing.T) {
			f := newRemoteArgvFixture(t, "free", "free-ran\n", 3)
			result := f.cli.Run(t, executable, nil, "--offline", runVerb, "alpha", "--", "free", "-h")
			requireNoSSHCTLUsage(t, result)
			if result.ProcessExit != 3 || !strings.Contains(result.Stdout, "free-ran\n") {
				t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
			}
			f.requireCommand(t, "'free' '-h'")
		})
		t.Run(executable+" first positional starts the remote argv", func(t *testing.T) {
			f := newRemoteArgvFixture(t, "python3", "script-help\n", 0)
			result := f.cli.Run(t, executable, nil, "--offline", runVerb, "alpha", "python3", "/root/tool.py", "--help")
			requireNoSSHCTLUsage(t, result)
			if result.ProcessExit != 0 || !strings.Contains(result.Stdout, "script-help\n") {
				t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
			}
			f.requireCommand(t, "'python3' '/root/tool.py' '--help'")
		})
		t.Run(executable+" --argv echo --json stays human and reaches the remote", func(t *testing.T) {
			f := newRemoteArgvFixture(t, "echo", "--json\n", 0)
			result := f.cli.Run(t, executable, nil, "--offline", runVerb, "alpha", "--argv", "echo", "--json")
			if result.ProcessExit != 0 || result.Stdout != "--json\n" || result.Stderr != "" {
				t.Fatalf("human output was rewritten: %s", compiledOutputIdentity(result))
			}
			f.requireCommand(t, "'echo' '--json'")
		})
	}
}

func TestCompiledRemoteArgvBoundaryKeepsJSONOwnedBySSHCTL(t *testing.T) {
	t.Run("global --json with du -h", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "du", "du-ran\n", 0)
		result := f.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "alpha", "--argv", "du", "-h", ".")
		requireNoSSHCTLUsage(t, result)
		document := assertCompiledJSONSuccess(t, result)
		if document["stdout"] != "du-ran\n" {
			t.Fatalf("stdout = %#v", document["stdout"])
		}
		f.requireCommand(t, "'du' '-h' '.'")
	})
	t.Run("global --json with free -h keeps the remote exit", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "free", "free-ran\n", 9)
		result := f.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "alpha", "--argv", "free", "-h")
		requireNoSSHCTLUsage(t, result)
		if result.ProcessExit != 9 {
			t.Fatalf("exit = %d, want remote 9: %s", result.ProcessExit, compiledOutputIdentity(result))
		}
		var document map[string]any
		if err := json.Unmarshal([]byte(result.Stdout), &document); err != nil {
			t.Fatalf("stdout is not one JSON document: %v: %q", err, result.Stdout)
		}
		if document["stdout"] != "free-ran\n" {
			t.Fatalf("document = %#v", document)
		}
	})
	t.Run("--json echo --json carries the remote --json", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "echo", "--json\n", 0)
		result := f.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "alpha", "--argv", "echo", "--json")
		document := assertCompiledJSONSuccess(t, result)
		if document["stdout"] != "--json\n" {
			t.Fatalf("stdout = %#v, want \"--json\\n\"", document["stdout"])
		}
		f.requireCommand(t, "'echo' '--json'")
	})
	t.Run("--json before --argv is still an sshctl option", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "echo", "hello\n", 0)
		result := f.cli.Run(t, "sshctl", nil, "--offline", "run", "alpha", "--json", "--argv", "echo", "hello")
		document := assertCompiledJSONSuccess(t, result)
		if document["stdout"] != "hello\n" {
			t.Fatalf("stdout = %#v", document["stdout"])
		}
	})
	t.Run("alias shorthand keeps remote flags", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "df", "df-ran\n", 4)
		result := f.cli.Run(t, "sshctl", nil, "--offline", "alpha", "df", "-h", "--json")
		requireNoSSHCTLUsage(t, result)
		if result.ProcessExit != 4 || !strings.Contains(result.Stdout, "df-ran\n") || strings.HasPrefix(strings.TrimSpace(result.Stdout), "{") {
			t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
		}
		f.requireCommand(t, "'df' '-h' '--json'")
	})
}

func TestCompiledRunHelpIsRecognizedBeforeTheRemoteArgv(t *testing.T) {
	for _, executable := range []string{"sshctl", "ssm"} {
		runVerb := "run"
		if executable == "ssm" {
			runVerb = "exec"
		}
		for _, args := range [][]string{
			{runVerb, "--help"},
			{runVerb, "-h"},
			{"help", runVerb},
			{runVerb, "alpha", "--help"},
			{runVerb, "alpha", "-h"},
			{runVerb, "alpha", "--timeout", "5s", "--help"},
			{"--json", runVerb, "alpha", "--help"},
		} {
			t.Run(executable+" "+strings.Join(args, " "), func(t *testing.T) {
				f := newRemoteArgvFixture(t, "df", "must-not-run\n", 0)
				result := f.cli.Run(t, executable, nil, append([]string{"--offline"}, args...)...)
				if result.ProcessExit != 0 || !strings.Contains(result.Stdout, "Usage:") || strings.Contains(result.Stdout, "must-not-run") {
					t.Fatalf("help not printed: %s", compiledOutputIdentity(result))
				}
				if got := f.server.SessionCount(); got != 0 {
					t.Fatalf("help opened %d SSH sessions", got)
				}
			})
		}
	}
}

func TestCompiledMapKeepsRemoteArgvOutOfSSHCTLScanning(t *testing.T) {
	for _, executable := range []string{"sshctl", "ssm"} {
		t.Run(executable+" map --argv df -h", func(t *testing.T) {
			f := newRemoteArgvFixture(t, "df", "df-ran\n", 0)
			result := f.cli.Run(t, executable, nil, "--offline", "map", "alpha", "--argv", "df", "-h")
			requireNoSSHCTLUsage(t, result)
			if result.ProcessExit != 0 || !strings.Contains(result.Stdout, "alpha\tok\texit=0") {
				t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
			}
			f.requireCommand(t, "'df' '-h'")
		})
	}
	t.Run("map -- free -h -j 2 --json", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "free", "free-ran\n", 0)
		result := f.cli.Run(t, "sshctl", nil, "--offline", "map", "alpha", "-j", "2", "--json", "--", "free", "-h")
		requireNoSSHCTLUsage(t, result)
		var documents []map[string]any
		if err := json.Unmarshal([]byte(result.Stdout), &documents); err != nil || len(documents) != 1 {
			t.Fatalf("map JSON = %q err=%v", result.Stdout, err)
		}
		if documents[0]["stdout"] != "free-ran\n" {
			t.Fatalf("document = %#v", documents[0])
		}
		f.requireCommand(t, "'free' '-h'")
	})
	t.Run("map remote --json stays human", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "echo", "--json\n", 0)
		result := f.cli.Run(t, "sshctl", nil, "--offline", "map", "alpha", "--argv", "echo", "--json")
		if result.ProcessExit != 0 || !strings.HasPrefix(result.Stdout, "alpha\tok\texit=0") {
			t.Fatalf("map human output was rewritten: %s", compiledOutputIdentity(result))
		}
		f.requireCommand(t, "'echo' '--json'")
	})
	t.Run("map remote --json under global --json is one map document", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "echo", "--json\n", 0)
		result := f.cli.Run(t, "sshctl", nil, "--offline", "--json", "map", "alpha", "--argv", "echo", "--json")
		var documents []map[string]any
		if err := json.Unmarshal([]byte(result.Stdout), &documents); err != nil || len(documents) != 1 || documents[0]["stdout"] != "--json\n" {
			t.Fatalf("map JSON = %q err=%v", result.Stdout, err)
		}
	})
	t.Run("map --help before the argv still prints help", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "df", "must-not-run\n", 0)
		for _, args := range [][]string{{"map", "--help"}, {"map", "alpha", "--help"}, {"help", "map"}} {
			result := f.cli.Run(t, "sshctl", nil, append([]string{"--offline"}, args...)...)
			if result.ProcessExit != 0 || !strings.Contains(result.Stdout, "Usage: sshctl map") || f.server.SessionCount() != 0 {
				t.Fatalf("map help %v: %s", args, compiledOutputIdentity(result))
			}
		}
	})
}

func TestCompiledPlanKeepsRemoteArgvOutOfSSHCTLScanning(t *testing.T) {
	for _, executable := range []string{"sshctl", "ssm"} {
		t.Run(executable+" plan --argv df -h", func(t *testing.T) {
			f := newRemoteArgvFixture(t, "df", "must-not-run\n", 0)
			result := f.cli.Run(t, executable, nil, "--offline", "plan", "alpha", "--argv", "df", "-h")
			requireNoSSHCTLUsage(t, result)
			if result.ProcessExit != 0 || !strings.Contains(result.Stdout, "'df' '-h'") {
				t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
			}
			if f.server.SessionCount() != 0 {
				t.Fatal("plan must not dial")
			}
		})
	}
	t.Run("--json plan carries remote --json and -h", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "df", "must-not-run\n", 0)
		result := f.cli.Run(t, "sshctl", nil, "--offline", "--json", "plan", "alpha", "--argv", "df", "-h", "--json")
		requireNoSSHCTLUsage(t, result)
		document := assertCompiledJSONSuccess(t, result)
		if command, _ := document["remote_command"].(string); !strings.Contains(command, "'df' '-h' '--json'") {
			t.Fatalf("remote_command = %#v", document["remote_command"])
		}
	})
	t.Run("plan remote --json stays human", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "df", "must-not-run\n", 0)
		result := f.cli.Run(t, "sshctl", nil, "--offline", "plan", "alpha", "--argv", "echo", "--json")
		if result.ProcessExit != 0 || strings.HasPrefix(strings.TrimSpace(result.Stdout), "{") || !strings.Contains(result.Stdout, "'echo' '--json'") {
			t.Fatalf("plan human output was rewritten: %s", compiledOutputIdentity(result))
		}
	})
	t.Run("run --plan keeps the boundary", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "df", "must-not-run\n", 0)
		result := f.cli.Run(t, "sshctl", nil, "--offline", "run", "alpha", "--plan", "--argv", "df", "-h")
		requireNoSSHCTLUsage(t, result)
		if result.ProcessExit != 0 || !strings.Contains(result.Stdout, "'df' '-h'") || f.server.SessionCount() != 0 {
			t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
		}
	})
}

func TestCompiledScriptArgumentsAfterDashAreNotSSHCTLOptions(t *testing.T) {
	writeScript := func(t *testing.T, f *remoteArgvFixture, name string) string {
		t.Helper()
		path := filepath.Join(f.cli.temp, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho ok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Run("-f script -- -h --json", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "command -v 'sh'", "script-ran\n", 5)
		script := writeScript(t, f, "one.sh")
		result := f.cli.Run(t, "sshctl", nil, "--offline", "run", "alpha", "-f", script, "--", "-h", "--help", "--json")
		requireNoSSHCTLUsage(t, result)
		if result.ProcessExit != 5 || !strings.Contains(result.Stdout, "script-ran\n") || strings.HasPrefix(strings.TrimSpace(result.Stdout), "{") {
			t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
		}
		f.requireCommand(t, "-h", "--help", "--json")
	})
	t.Run("--json -f script -- --json", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "command -v 'sh'", "script-ran\n", 0)
		script := writeScript(t, f, "two.sh")
		result := f.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "alpha", "-f", script, "--", "--json", "-h")
		document := assertCompiledJSONSuccess(t, result)
		if document["stdout"] != "script-ran\n" {
			t.Fatalf("document = %#v", document)
		}
		f.requireCommand(t, "--json", "-h")
	})
	t.Run("-s -- args from stdin", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "command -v 'sh'", "stdin-ran\n", 0)
		result := f.cli.Run(t, "sshctl", []byte("echo hi\n"), "--offline", "run", "alpha", "-s", "--", "--help")
		requireNoSSHCTLUsage(t, result)
		if result.ProcessExit != 0 || !strings.Contains(result.Stdout, "stdin-ran\n") {
			t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
		}
		f.requireCommand(t, "--help")
	})
	t.Run("--scripts a,b -- --help runs both scripts", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "command -v 'sh'", "multi-ran\n", 0)
		first := writeScript(t, f, "a.sh")
		second := writeScript(t, f, "b.sh")
		result := f.cli.Run(t, "sshctl", nil, "--offline", "run", "alpha", "--scripts", first+","+second, "--", "--help", "--json")
		requireNoSSHCTLUsage(t, result)
		if result.ProcessExit != 0 || strings.HasPrefix(strings.TrimSpace(result.Stdout), "[") {
			t.Fatalf("exit/output: %s", compiledOutputIdentity(result))
		}
		if commands := f.recorder.Commands(); len(commands) != 2 {
			t.Fatalf("executed %d scripts, want 2: %q", len(commands), commands)
		}
	})
	t.Run("map --scripts a,b -- --help", func(t *testing.T) {
		f := newRemoteArgvFixture(t, "command -v 'sh'", "multi-ran\n", 0)
		first := writeScript(t, f, "c.sh")
		second := writeScript(t, f, "d.sh")
		result := f.cli.Run(t, "sshctl", nil, "--offline", "--json", "map", "alpha", "--scripts", first+","+second, "--", "--help", "-h")
		requireNoSSHCTLUsage(t, result)
		var documents []map[string]any
		if err := json.Unmarshal([]byte(result.Stdout), &documents); err != nil || len(documents) != 2 {
			t.Fatalf("map JSON = %q err=%v", result.Stdout, err)
		}
		if commands := f.recorder.Commands(); len(commands) != 2 {
			t.Fatalf("executed %d scripts, want 2: %q", len(commands), commands)
		}
	})
}
