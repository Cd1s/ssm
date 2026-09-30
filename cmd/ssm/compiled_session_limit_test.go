package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ssm/internal/config"
)

const sessionLimitPassword = "SESSION_LIMIT_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary

func writeSessionLimitScripts(t *testing.T, cli *compiledCLIHarness, count int) string {
	t.Helper()
	var paths []string
	for i := 0; i < count; i++ {
		path := filepath.Join(cli.temp, fmt.Sprintf("job%d.sh", i))
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho ok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return strings.Join(paths, ",")
}

// Issue #76: more parallel jobs than the server's per-connection session limit
// must queue on the shared connection instead of closing it.
func TestCompiledMapBeyondServerSessionLimitSucceeds(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: sessionLimitPassword, MaxSessions: 2, RunDelay: 150 * time.Millisecond,
		RunCommandContains: "command -v 'sh'", RunStdoutFragments: []string{"ok\n"},
	})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("busy", sessionLimitPassword)}})
	scripts := writeSessionLimitScripts(t, cli, 6)

	result := cli.Run(t, "sshctl", nil, "--offline", "--json", "map", "busy", "--scripts", scripts, "-j", "6")
	if result.ProcessExit != 0 {
		t.Fatalf("map exit=%d stdout=%s stderr=%s", result.ProcessExit, result.Stdout, result.Stderr)
	}
	var documents []map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &documents); err != nil || len(documents) != 6 {
		t.Fatalf("map JSON err=%v len=%d stdout=%s", err, len(documents), result.Stdout)
	}
	for _, document := range documents {
		if document["ok"] != true || document["stdout"] != "ok\n" {
			t.Fatalf("job failed: %v", document)
		}
	}
	if got := server.connections.Load(); got != 1 {
		t.Fatalf("SSH connections = %d, want the single shared connection", got)
	}
	if peak := server.peakSessions.Load(); peak > 2 {
		t.Fatalf("peak concurrent sessions = %d, above the server limit", peak)
	}
}

func TestCompiledRunReportsSessionLimitWhenSlotNeverFrees(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: sessionLimitPassword, MaxSessions: 1, RunDelay: 4 * time.Second,
		RunCommandContains: "command -v 'sh'", RunStdoutFragments: []string{"ok\n"},
	})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("busy", sessionLimitPassword)}})
	scripts := writeSessionLimitScripts(t, cli, 2)

	result := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TIMEOUT": "500ms"},
		"--offline", "--json", "map", "busy", "--scripts", scripts, "-j", "2")
	var documents []map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &documents); err != nil || len(documents) != 2 {
		t.Fatalf("map JSON err=%v stdout=%s stderr=%s", err, result.Stdout, result.Stderr)
	}
	var ok, limited int
	for _, document := range documents {
		switch {
		case document["ok"] == true:
			ok++
		case document["error"] == "session_limit":
			limited++
			hint, _ := document["hint"].(string)
			if document["stage"] != "session" || document["exit"] != float64(255) ||
				!strings.Contains(hint, "-j") || !strings.Contains(hint, "MaxSessions") {
				t.Fatalf("session_limit document = %v", document)
			}
		default:
			t.Fatalf("unexpected result: %v", document)
		}
	}
	if ok != 1 || limited != 1 {
		t.Fatalf("ok=%d session_limit=%d, want one running job kept and one refused: %s", ok, limited, result.Stdout)
	}
	if result.ProcessExit != 255 {
		t.Fatalf("exit=%d, want 255", result.ProcessExit)
	}
}

// A session-limit wait through a ProxyJump alias must keep queueing on the
// chain's one target connection, and not re-dial the chain.
func TestCompiledMapBeyondSessionLimitThroughJumpKeepsTheChain(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	jump := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: sessionLimitPassword, AllowForward: true})
	target := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: sessionLimitPassword, MaxSessions: 2, RunDelay: 150 * time.Millisecond,
		RunCommandContains: "command -v 'sh'", RunStdoutFragments: []string{"ok\n"},
	})
	cli.TrustSSHHost(t, jump)
	cli.TrustSSHHost(t, target)
	behind := target.Connection("behind", sessionLimitPassword)
	behind.ProxyJump = "jump"
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{jump.Connection("jump", sessionLimitPassword), behind}})
	scripts := writeSessionLimitScripts(t, cli, 6)

	result := cli.Run(t, "sshctl", nil, "--offline", "--json", "map", "behind", "--scripts", scripts, "-j", "6")
	var documents []map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &documents); err != nil || len(documents) != 6 || result.ProcessExit != 0 {
		t.Fatalf("map exit=%d err=%v stdout=%s stderr=%s", result.ProcessExit, err, result.Stdout, result.Stderr)
	}
	for _, document := range documents {
		if document["ok"] != true {
			t.Fatalf("job failed: %v", document)
		}
	}
	if got := target.connections.Load(); got != 1 {
		t.Fatalf("target connections = %d, want the one chain connection", got)
	}
	if got, forwards := jump.connections.Load(), jump.Forwards(); got != 1 || len(forwards) != 1 {
		t.Fatalf("jump connections=%d forwards=%v, want the chain dialed once", got, forwards)
	}
}
