package main

import (
	"strings"
	"testing"
	"time"

	"ssm/internal/config"
)

const timeoutsPassword = "TIMEOUTS_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary

// runCompiledWithin bounds a compiled CLI invocation so a regression that
// hangs fails the test instead of stalling the whole package.
func runCompiledWithin(t *testing.T, limit time.Duration, run func() compiledCLIResult) compiledCLIResult {
	t.Helper()
	done := make(chan compiledCLIResult, 1)
	go func() { done <- run() }()
	select {
	case result := <-done:
		return result
	case <-time.After(limit):
		t.Fatalf("compiled CLI did not exit within %s", limit)
		return compiledCLIResult{}
	}
}

func TestCompiledConnectTimeoutBoundsSilentHandshake(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	silent := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: timeoutsPassword, SilentHandshake: true})
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{silent.Connection("silent", timeoutsPassword)}})

	// --connect-timeout is the new name; --timeout stays a compatible alias.
	for _, flag := range []string{"--connect-timeout", "--timeout"} {
		t.Run(flag, func(t *testing.T) {
			started := time.Now()
			machine := runCompiledWithin(t, 30*time.Second, func() compiledCLIResult {
				return cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "silent", flag, "500ms", "--argv", "true")
			})
			if elapsed := time.Since(started); elapsed > 10*time.Second {
				t.Fatalf("%s 500ms took %s", flag, elapsed)
			}
			if machine.ProcessExit != 255 || machine.Stderr != "" {
				t.Fatalf("json exit=%d stderr=%q stdout=%q", machine.ProcessExit, machine.Stderr, machine.Stdout)
			}
			document := decodeExactlyOneJSONObject(t, machine.Stdout)
			if document["ok"] != false || document["error"] != "handshake_failed" || document["stage"] != "handshake" ||
				document["exit"] != float64(255) {
				t.Fatalf("json document = %s", machine.Stdout)
			}
			if hint, _ := document["hint"].(string); !strings.Contains(hint, "--connect-timeout") {
				t.Fatalf("handshake_failed hint = %q, want it to mention --connect-timeout", hint)
			}
			if _, present := document["outcome"]; present {
				t.Fatalf("handshake_failed must not carry outcome: %s", machine.Stdout)
			}

			human := runCompiledWithin(t, 30*time.Second, func() compiledCLIResult {
				return cli.Run(t, "sshctl", nil, "--offline", "run", "silent", flag, "500ms", "--argv", "true")
			})
			want := "ssm: error=handshake_failed stage=handshake alias=silent address=" + silent.Address() + "\n"
			if human.ProcessExit != 255 || human.Stdout != "" || !strings.HasPrefix(human.Stderr, want) {
				t.Fatalf("human exit=%d stdout=%q stderr=%q, want prefix %q", human.ProcessExit, human.Stdout, human.Stderr, want)
			}
		})
	}
}

func TestCompiledHelpDocumentsEachTimeout(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	for _, command := range []string{"run", "exec", "plan"} {
		help := cli.Run(t, "sshctl", nil, command, "--help")
		if help.ProcessExit != 0 {
			t.Fatalf("%s --help exit=%d stderr=%q", command, help.ProcessExit, help.Stderr)
		}
		for _, want := range []string{
			"--connect-timeout", "--exec-timeout", "SSM_KEEPALIVE",
			"connection timeout, not an execution timeout", "exec_timeout",
		} {
			if !strings.Contains(help.Stdout, want) {
				t.Fatalf("%s help missing %q:\n%s", command, want, help.Stdout)
			}
		}
	}
	for _, command := range []string{"map", "put"} {
		help := cli.Run(t, "sshctl", nil, command, "--help")
		if command == "map" && (!strings.Contains(help.Stdout, "--exec-timeout") || !strings.Contains(help.Stdout, "--connect-timeout")) {
			t.Fatalf("map help does not document the timeouts:\n%s", help.Stdout)
		}
		if command == "put" && !strings.Contains(help.Stdout, "transfer timeout") {
			t.Fatalf("put help must say --timeout is the transfer timeout:\n%s", help.Stdout)
		}
	}
	usage := cli.Run(t, "sshctl", nil, "--help")
	for _, want := range []string{"--connect-timeout", "--exec-timeout", "SSM_KEEPALIVE"} {
		if !strings.Contains(usage.Stdout, want) {
			t.Fatalf("sshctl --help missing %q:\n%s", want, usage.Stdout)
		}
	}
}
