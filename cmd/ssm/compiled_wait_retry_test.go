package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"

	"ssm/internal/config"
)

const waitRetryPassword = "WAIT_RETRY_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary

func waitRetryFreeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release address: %v", err)
	}
	return addr
}

// waitRetryTrustWrongKey records another key for the fixture's address, so the
// server's real key is a host-key mismatch.
func waitRetryTrustWrongKey(t *testing.T, h *compiledCLIHarness, server, other *compiledSSHFixture) {
	t.Helper()
	dir := filepath.Join(h.home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(server.Address())}, other.signer.PublicKey()) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitRetryJSON(t *testing.T, result compiledCLIResult) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\nstdout=%q stderr=%q", err, result.Stdout, result.Stderr)
	}
	return doc
}

func TestCompiledRunRetryDialSucceedsAfterDroppedHandshakes(t *testing.T) {
	h := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: waitRetryPassword, DropFirstConnections: 2, RunCommandContains: "retry-ok", RunStdoutFragments: []string{"fine\n"},
	})
	h.TrustSSHHost(t, server)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("retry", waitRetryPassword)}})

	result := h.Run(t, "sshctl", nil, "--offline", "--json", "run", "retry", "--retry-dial", "3:10ms", "--argv", "retry-ok")
	doc := waitRetryJSON(t, result)
	if result.ProcessExit != 0 || doc["ok"] != true || doc["dial_attempts"] != float64(3) {
		t.Fatalf("exit=%d doc=%s stderr=%q, want ok with dial_attempts 3", result.ProcessExit, result.Stdout, result.Stderr)
	}
	if got := server.AcceptedConnections(); got != 3 {
		t.Fatalf("accepted connections = %d, want 3", got)
	}
}

func TestCompiledRunRetryDialSucceedsAfterRefusedPort(t *testing.T) {
	h := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: waitRetryPassword, ListenAddress: waitRetryFreeAddress(t), DeferListen: true,
		RunCommandContains: "retry-ok", RunStdoutFragments: []string{"fine\n"},
	})
	h.TrustSSHHost(t, server)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("retry", waitRetryPassword)}})
	// The port refuses until the server binds; retries are generous (cumulative
	// backoff far exceeds the start delay), so only eventual success is asserted.
	time.AfterFunc(300*time.Millisecond, func() {
		if err := server.StartListening(); err != nil {
			t.Errorf("start listening: %v", err)
		}
	})

	result := h.Run(t, "sshctl", nil, "--offline", "--json", "run", "retry", "--retry-dial", "8:100ms", "--argv", "retry-ok")
	doc := waitRetryJSON(t, result)
	if result.ProcessExit != 0 || doc["ok"] != true {
		t.Fatalf("exit=%d doc=%s stderr=%q, want ok after refused attempts", result.ProcessExit, result.Stdout, result.Stderr)
	}
}

func TestCompiledRunWithoutRetryDialOmitsDialAttempts(t *testing.T) {
	h := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: waitRetryPassword, RunCommandContains: "plain-ok", RunStdoutFragments: []string{"fine\n"},
	})
	h.TrustSSHHost(t, server)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("plain", waitRetryPassword)}})

	result := h.Run(t, "sshctl", nil, "--offline", "--json", "run", "plain", "--argv", "plain-ok")
	doc := waitRetryJSON(t, result)
	if _, present := doc["dial_attempts"]; present || doc["ok"] != true {
		t.Fatalf("doc = %s, want ok without dial_attempts", result.Stdout)
	}
}

func TestCompiledRunRetryDialNeverRetriesAuthFailure(t *testing.T) {
	h := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: "the-right-one"})
	h.TrustSSHHost(t, server)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("badauth", "wrong")}})

	result := h.Run(t, "sshctl", nil, "--offline", "--json", "run", "badauth", "--retry-dial", "3:10ms", "--argv", "true")
	doc := waitRetryJSON(t, result)
	if doc["error"] != "auth_failed" {
		t.Fatalf("doc = %s, want auth_failed", result.Stdout)
	}
	if server.AcceptedConnections() != 1 || server.AuthAttempts() != 1 {
		t.Fatalf("accepted=%d auth attempts=%d, want exactly 1 of each", server.AcceptedConnections(), server.AuthAttempts())
	}
}

func TestCompiledRunRetryDialNeverRetriesHostKeyMismatch(t *testing.T) {
	h := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: waitRetryPassword})
	other := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: waitRetryPassword})
	waitRetryTrustWrongKey(t, h, server, other)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("mismatch", waitRetryPassword)}})

	result := h.Run(t, "sshctl", nil, "--offline", "--json", "run", "mismatch", "--retry-dial", "3:10ms", "--argv", "true")
	doc := waitRetryJSON(t, result)
	if !strings.HasPrefix(doc["error"].(string), "host_key_") {
		t.Fatalf("doc = %s, want host_key_*", result.Stdout)
	}
	if server.AcceptedConnections() != 1 || server.AuthAttempts() != 0 {
		t.Fatalf("accepted=%d auth attempts=%d, want 1 connection and no auth", server.AcceptedConnections(), server.AuthAttempts())
	}
}

func TestCompiledRunRetryDialNeverRetriesConnectionLost(t *testing.T) {
	h := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: waitRetryPassword, DropAfterExec: true})
	h.TrustSSHHost(t, server)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("lost", waitRetryPassword)}})

	result := h.Run(t, "sshctl", nil, "--offline", "--json", "run", "lost", "--retry-dial", "3:10ms", "--argv", "true")
	doc := waitRetryJSON(t, result)
	if doc["error"] != "connection_lost" {
		t.Fatalf("doc = %s, want connection_lost", result.Stdout)
	}
	if server.ConnectionCount() != 1 || len(server.Commands()) != 1 {
		t.Fatalf("connections=%d commands=%v, want the command sent exactly once", server.ConnectionCount(), server.Commands())
	}
}

func TestCompiledRunRetryDialRejectsLargeCount(t *testing.T) {
	h := newCompiledCLIHarness(t)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{{Name: "x", Host: "127.0.0.1", Port: 1, User: "u", Password: "p"}}})
	result := h.Run(t, "sshctl", nil, "--offline", "--json", "run", "x", "--retry-dial", "11", "--argv", "true")
	if result.ProcessExit != 2 || !strings.Contains(result.Stdout+result.Stderr, "10") {
		t.Fatalf("exit=%d stdout=%q stderr=%q, want usage error naming the cap of 10", result.ProcessExit, result.Stdout, result.Stderr)
	}
}

// A failure after a successful authentication (session open times out) must
// never be retried: that would log in again.
func TestCompiledWaitAndRetryDialNeverRetryAfterSuccessfulAuth(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"wait", []string{"wait", "sessfail", "--timeout", "10s", "--interval", "1s"}},
		{"run", []string{"run", "sessfail", "--retry-dial", "3:10ms", "--argv", "true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCompiledCLIHarness(t)
			server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
				Password: waitRetryPassword, RejectSessions: true, RejectSessionsMessage: "i/o timeout",
			})
			h.TrustSSHHost(t, server)
			h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("sessfail", waitRetryPassword)}})

			args := append([]string{"--offline", "--json"}, tc.args...)
			result := h.Run(t, "sshctl", nil, args...)
			doc := waitRetryJSON(t, result)
			if doc["ok"] != false || doc["error"] == "wait_timeout" {
				t.Fatalf("doc = %s, want the session failure reported, not retried", result.Stdout)
			}
			if server.AuthAttempts() != 1 || server.AcceptedConnections() != 1 {
				t.Fatalf("auth attempts=%d accepted=%d, want exactly 1 of each", server.AuthAttempts(), server.AcceptedConnections())
			}
		})
	}
}

func TestCompiledWaitReadyAfterDroppedConnections(t *testing.T) {
	h := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: waitRetryPassword, DropFirstConnections: 2})
	h.TrustSSHHost(t, server)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("boot", waitRetryPassword)}})

	result := h.Run(t, "sshctl", nil, "--offline", "--json", "wait", "boot", "--timeout", "12s", "--interval", "1s")
	doc := waitRetryJSON(t, result)
	if result.ProcessExit != 0 || doc["ok"] != true || doc["alias"] != "boot" || doc["attempts"] != float64(3) {
		t.Fatalf("exit=%d doc=%s stderr=%q, want ready on attempt 3", result.ProcessExit, result.Stdout, result.Stderr)
	}
	// exactly one connection per iteration: no separate banner probe
	if got := server.AcceptedConnections(); got != 3 {
		t.Fatalf("accepted connections = %d, want 3 (one per attempt)", got)
	}
	if server.AuthAttempts() != 1 {
		t.Fatalf("auth attempts = %d, want exactly 1", server.AuthAttempts())
	}
}

func TestCompiledWaitReadyAfterRefusedPort(t *testing.T) {
	h := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: waitRetryPassword, ListenAddress: waitRetryFreeAddress(t), DeferListen: true,
	})
	h.TrustSSHHost(t, server)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("boot", waitRetryPassword)}})
	time.AfterFunc(300*time.Millisecond, func() {
		if err := server.StartListening(); err != nil {
			t.Errorf("start listening: %v", err)
		}
	})

	result := h.Run(t, "sshctl", nil, "--offline", "--json", "wait", "boot", "--timeout", "12s", "--interval", "1s")
	doc := waitRetryJSON(t, result)
	if result.ProcessExit != 0 || doc["ok"] != true || server.AuthAttempts() != 1 || server.AcceptedConnections() != 1 {
		t.Fatalf("exit=%d doc=%s auth=%d accepted=%d, want ready with one connection and one auth",
			result.ProcessExit, result.Stdout, server.AuthAttempts(), server.AcceptedConnections())
	}
}

func TestCompiledWaitAndRetryDialNeverRetryDropDuringAuth(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"wait", []string{"wait", "dropauth", "--timeout", "10s", "--interval", "1s"}},
		{"run", []string{"run", "dropauth", "--retry-dial", "3:10ms", "--argv", "true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCompiledCLIHarness(t)
			server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: waitRetryPassword, DropDuringAuth: true})
			h.TrustSSHHost(t, server)
			h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("dropauth", waitRetryPassword)}})

			args := append([]string{"--offline", "--json"}, tc.args...)
			result := h.Run(t, "sshctl", nil, args...)
			doc := waitRetryJSON(t, result)
			if doc["ok"] != false || doc["error"] == "wait_timeout" {
				t.Fatalf("doc = %s, want the transport failure reported, not retried", result.Stdout)
			}
			if server.AuthAttempts() != 1 || server.AcceptedConnections() != 1 {
				t.Fatalf("auth attempts=%d accepted=%d, want exactly 1 of each", server.AuthAttempts(), server.AcceptedConnections())
			}
		})
	}
}

func TestCompiledWaitStopsAfterOneAuthFailure(t *testing.T) {
	h := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: "the-right-one"})
	h.TrustSSHHost(t, server)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("badauth", "wrong")}})

	start := time.Now()
	result := h.Run(t, "sshctl", nil, "--offline", "--json", "wait", "badauth", "--timeout", "10s", "--interval", "1s")
	doc := waitRetryJSON(t, result)
	if doc["error"] != "auth_failed" || doc["ok"] != false {
		t.Fatalf("doc = %s, want auth_failed", result.Stdout)
	}
	if got := server.AuthAttempts(); got != 1 || server.AcceptedConnections() != 1 {
		t.Fatalf("auth attempts = %d accepted = %d, want exactly 1 of each", got, server.AcceptedConnections())
	}
	if time.Since(start) > 8*time.Second {
		t.Fatalf("wait kept going after a non-transport failure: %s", time.Since(start))
	}
}

func TestCompiledWaitStopsImmediatelyOnHostKeyProblems(t *testing.T) {
	h := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: waitRetryPassword})
	other := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: waitRetryPassword})
	waitRetryTrustWrongKey(t, h, server, other)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("mismatch", waitRetryPassword)}})

	result := h.Run(t, "sshctl", nil, "--offline", "--json", "wait", "mismatch", "--timeout", "10s", "--interval", "1s")
	doc := waitRetryJSON(t, result)
	if !strings.HasPrefix(doc["error"].(string), "host_key_") {
		t.Fatalf("doc = %s, want host_key_*", result.Stdout)
	}
	if server.AuthAttempts() != 0 {
		t.Fatalf("auth attempts = %d, want none before host key verification", server.AuthAttempts())
	}
	if got := server.AcceptedConnections(); got != 1 {
		t.Fatalf("accepted connections = %d, want exactly 1", got)
	}

	// unknown host key (no known_hosts entry at all)
	h2 := newCompiledCLIHarness(t)
	unknown := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: waitRetryPassword})
	h2.SaveVault(t, &config.Vault{Connections: []config.Connection{unknown.Connection("unknown", waitRetryPassword)}})
	result = h2.Run(t, "sshctl", nil, "--offline", "--json", "wait", "unknown", "--timeout", "10s", "--interval", "1s")
	doc = waitRetryJSON(t, result)
	if doc["error"] != "host_key_unknown" || unknown.AuthAttempts() != 0 || unknown.AcceptedConnections() != 1 {
		t.Fatalf("doc = %s auth=%d accepted=%d, want host_key_unknown, no auth, one connection", result.Stdout, unknown.AuthAttempts(), unknown.AcceptedConnections())
	}
}

func TestCompiledWaitStopsImmediatelyWithoutCredentials(t *testing.T) {
	h := newCompiledCLIHarness(t)
	refused := newCompiledRefusedTCPPort(t)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{{Name: "nocred", Host: refused.host, Port: refused.port, User: "u"}}})

	start := time.Now()
	result := h.Run(t, "sshctl", nil, "--offline", "--json", "wait", "nocred", "--timeout", "10s", "--interval", "1s")
	doc := waitRetryJSON(t, result)
	if doc["error"] != "no_auth_configured" {
		t.Fatalf("doc = %s, want a credentials failure", result.Stdout)
	}
	if time.Since(start) > 6*time.Second {
		t.Fatalf("wait did not stop immediately: %s", time.Since(start))
	}
}

func TestCompiledWaitTimeoutCarriesLastCauseAndStaysBounded(t *testing.T) {
	h := newCompiledCLIHarness(t)
	refused := newCompiledRefusedTCPPort(t)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{{Name: "down", Host: refused.host, Port: refused.port, User: "u", Password: "p"}}})

	start := time.Now()
	result := h.Run(t, "sshctl", nil, "--offline", "--json", "wait", "down", "--timeout", "3s", "--interval", "1s")
	elapsed := time.Since(start)
	doc := waitRetryJSON(t, result)
	if doc["error"] != "wait_timeout" || doc["stage"] != "wait" || doc["exit"] != float64(1) || result.ProcessExit != 1 {
		t.Fatalf("exit=%d doc=%s, want wait_timeout stage=wait exit=1", result.ProcessExit, result.Stdout)
	}
	if message, _ := doc["message"].(string); !strings.Contains(message, "dial_refused") {
		t.Fatalf("message = %q, want the last observed cause dial_refused", message)
	}
	if elapsed > 7*time.Second {
		t.Fatalf("wait overshot its 3s timeout: %s", elapsed)
	}
}

func TestCompiledWaitRejectsIntervalBelowFloor(t *testing.T) {
	h := newCompiledCLIHarness(t)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{{Name: "x", Host: "127.0.0.1", Port: 1, User: "u", Password: "p"}}})
	result := h.Run(t, "sshctl", nil, "--offline", "--json", "wait", "x", "--interval", "500ms")
	doc := waitRetryJSON(t, result)
	if result.ProcessExit != 2 || doc["error"] != "invalid_arguments" || !strings.Contains(doc["message"].(string), "1s") {
		t.Fatalf("exit=%d doc=%s, want invalid_arguments naming the 1s floor", result.ProcessExit, result.Stdout)
	}
}

func TestCompiledWaitUntilTCPKeepsPureTCPSemantics(t *testing.T) {
	h := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: "the-right-one"})
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("tcp", "wrong")}})

	result := h.Run(t, "sshctl", nil, "--offline", "--json", "wait", "tcp", "--until", "tcp", "--timeout", "5s", "--interval", "1s")
	doc := waitRetryJSON(t, result)
	// A pure TCP probe connects and closes at once; the fixture's accept loop
	// may count it only after the CLI has exited.
	for deadline := time.Now().Add(3 * time.Second); server.AcceptedConnections() < 1 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if result.ProcessExit != 0 || doc["ok"] != true || server.AuthAttempts() != 0 || server.AcceptedConnections() != 1 {
		t.Fatalf("exit=%d doc=%s auth=%d accepted=%d, want ready via one TCP connection and no auth", result.ProcessExit, result.Stdout, server.AuthAttempts(), server.AcceptedConnections())
	}
}

// A handshake that stalls AFTER the host key arrived (server hangs mid-auth)
// hits the handshake deadline as handshake_failed, but credentials may have
// been sent, so it must not be retried.
func TestCompiledWaitAndRetryDialNeverRetryHandshakeStalledDuringAuth(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"wait", []string{"wait", "hang", "--timeout", "12s", "--interval", "1s"}},
		{"run", []string{"run", "hang", "--retry-dial", "3:10ms", "--argv", "true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCompiledCLIHarness(t)
			server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: waitRetryPassword, HangDuringAuth: true})
			h.TrustSSHHost(t, server)
			h.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("hang", waitRetryPassword)}})

			args := append([]string{"--offline", "--json"}, tc.args...)
			result := h.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_CONNECT_TIMEOUT": "1s"}, args...)
			doc := waitRetryJSON(t, result)
			if doc["ok"] != false || doc["error"] != "handshake_failed" {
				t.Fatalf("doc = %s, want handshake_failed, not retried", result.Stdout)
			}
			if attempts, present := doc["dial_attempts"]; present && attempts != float64(1) {
				t.Fatalf("dial_attempts = %v, want absent or 1", attempts)
			}
			if server.AuthAttempts() != 1 || server.AcceptedConnections() != 1 {
				t.Fatalf("auth attempts=%d accepted=%d, want exactly 1 of each", server.AuthAttempts(), server.AcceptedConnections())
			}
		})
	}
}

// A server that accepts TCP and never speaks SSH stalls before the host key:
// nothing was sent, so run --retry-dial retries it.
func TestCompiledRunRetryDialRetriesHandshakeStalledBeforeHostKey(t *testing.T) {
	h := newCompiledCLIHarness(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	done := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() { <-done; _ = conn.Close() }()
		}
	}()
	t.Cleanup(func() { close(done); _ = listener.Close() })
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	h.SaveVault(t, &config.Vault{Connections: []config.Connection{{Name: "mute", Host: host, Port: port, User: "u", Password: "p"}}})

	result := h.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_CONNECT_TIMEOUT": "500ms"},
		"--offline", "--json", "run", "mute", "--retry-dial", "2:10ms", "--argv", "true")
	doc := waitRetryJSON(t, result)
	if doc["error"] != "handshake_failed" || doc["dial_attempts"] != float64(3) || accepted.Load() != 3 {
		t.Fatalf("doc = %s accepted=%d, want handshake_failed after 3 attempts", result.Stdout, accepted.Load())
	}
}

// newDroppingJumpHarness builds jump -> target where the chosen hop drops the
// connection as soon as it sees a credential.
func newDroppingJumpHarness(t *testing.T, dropTarget bool) (h *compiledCLIHarness, jump, target *compiledSSHFixture) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake remote hosts address the local file system with POSIX paths")
	}
	h = newCompiledCLIHarness(t)
	jump = newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: proxyJumpPassword, AllowForward: true, DropDuringAuth: !dropTarget})
	authorized, privatePEM := newJumpKey(t)
	target = newCompiledSSHFixture(t, compiledSSHFixtureOptions{AuthorizedKey: authorized, DropDuringAuth: dropTarget})
	h.TrustSSHHost(t, jump)
	h.TrustSSHHost(t, target)
	targetConnection := target.Connection("target", "")
	targetConnection.KeyName = "target-key"
	targetConnection.ProxyJump = "jump"
	h.SaveVault(t, &config.Vault{
		Connections: []config.Connection{jump.Connection("jump", proxyJumpPassword), targetConnection},
		Keys:        []config.SSHKey{{Name: "target-key", PrivateKey: privatePEM}},
	})
	return h, jump, target
}

// A failure after any hop's host key arrived (a hop dropping the connection
// mid-authentication) must never be retried through a jump chain, or a hop
// would see a second login attempt.
func TestCompiledWaitAndRetryDialNeverRetryDropDuringAuthThroughJump(t *testing.T) {
	for _, dropTarget := range []bool{true, false} {
		for _, tc := range []struct {
			name string
			args []string
		}{
			{"wait", []string{"wait", "target", "--timeout", "10s", "--interval", "1s"}},
			{"run", []string{"run", "target", "--retry-dial", "3:10ms", "--argv", "true"}},
		} {
			name := tc.name + "/drop-jump"
			if dropTarget {
				name = tc.name + "/drop-target"
			}
			t.Run(name, func(t *testing.T) {
				h, jump, target := newDroppingJumpHarness(t, dropTarget)
				args := append([]string{"--offline", "--json"}, tc.args...)
				result := h.Run(t, "sshctl", nil, args...)
				doc := waitRetryJSON(t, result)
				if doc["ok"] != false || doc["error"] == "wait_timeout" {
					t.Fatalf("doc = %s, want the failure reported, not retried", result.Stdout)
				}
				if dropTarget {
					if target.AuthAttempts() != 1 || jump.ConnectionCount() != 1 {
						t.Fatalf("target auth attempts=%d jump connections=%d, want exactly 1 of each", target.AuthAttempts(), jump.ConnectionCount())
					}
				} else if jump.AuthAttempts() != 1 || jump.AcceptedConnections() != 1 || target.AcceptedConnections() != 0 {
					t.Fatalf("jump auth=%d accepted=%d target accepted=%d, want 1/1/0", jump.AuthAttempts(), jump.AcceptedConnections(), target.AcceptedConnections())
				}
				if attempts, present := doc["dial_attempts"]; present && attempts != float64(1) {
					t.Fatalf("dial_attempts = %v, want absent or 1", attempts)
				}
			})
		}
	}
}

func TestCompiledWaitThroughJumpReadyAndTCPRejected(t *testing.T) {
	h := newJumpHarness(t, true, true)
	result := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "wait", "target", "--timeout", "10s", "--interval", "1s")
	doc := waitRetryJSON(t, result)
	if result.ProcessExit != 0 || doc["ok"] != true || doc["attempts"] != float64(1) {
		t.Fatalf("exit=%d doc=%s, want ready through the jump on attempt 1", result.ProcessExit, result.Stdout)
	}
	if h.jump.AuthAttempts() != 1 || h.target.AuthAttempts() != 1 {
		t.Fatalf("auth attempts jump=%d target=%d, want 1 each", h.jump.AuthAttempts(), h.target.AuthAttempts())
	}
	tcp := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "wait", "target", "--until", "tcp")
	if tcp.ProcessExit != 2 || waitRetryJSON(t, tcp)["error"] != "invalid_arguments" {
		t.Fatalf("--until tcp on a jump alias = exit %d %s, want invalid_arguments", tcp.ProcessExit, tcp.Stdout)
	}
}

// startWhenForwarded binds the (deferred) target once the jump host has been
// asked to forward to it at least n times, i.e. after n observed refused
// attempts: a state-based gate instead of a wall-clock one.
func startWhenForwarded(t *testing.T, jump, target *compiledSSHFixture, n int64) {
	t.Helper()
	go func() {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if jump.ForwardAttempts() >= n {
				if err := target.StartListening(); err != nil {
					t.Errorf("start target: %v", err)
				}
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
}

func newDownTargetJumpHarness(t *testing.T) (h *compiledCLIHarness, jump, target *compiledSSHFixture) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake remote hosts address the local file system with POSIX paths")
	}
	h = newCompiledCLIHarness(t)
	jump = newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: proxyJumpPassword, AllowForward: true})
	authorized, privatePEM := newJumpKey(t)
	target = newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		AuthorizedKey: authorized, ListenAddress: waitRetryFreeAddress(t), DeferListen: true,
		RunCommandContains: "hostname", RunStdoutFragments: []string{"target-host\n"},
	})
	h.TrustSSHHost(t, jump)
	h.TrustSSHHost(t, target)
	targetConnection := target.Connection("target", "")
	targetConnection.KeyName = "target-key"
	targetConnection.ProxyJump = "jump"
	h.SaveVault(t, &config.Vault{
		Connections: []config.Connection{jump.Connection("jump", proxyJumpPassword), targetConnection},
		Keys:        []config.SSHKey{{Name: "target-key", PrivateKey: privatePEM}},
	})
	return h, jump, target
}

// A target that is merely down behind a jump is "not reachable yet": the
// failure is before the TARGET's key exchange, so wait and --retry-dial keep
// going, and each retry only logs in to the jump successfully.
func TestCompiledWaitAndRetryDialRetryDownTargetBehindJump(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		gate int64
	}{
		{"wait", []string{"wait", "target", "--timeout", "12s", "--interval", "1s"}, 1},
		{"run", []string{"run", "target", "--retry-dial", "5:50ms", "--argv", "hostname"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, jump, target := newDownTargetJumpHarness(t)
			startWhenForwarded(t, jump, target, tc.gate)
			args := append([]string{"--offline", "--json"}, tc.args...)
			result := h.Run(t, "sshctl", nil, args...)
			doc := waitRetryJSON(t, result)
			if result.ProcessExit != 0 || doc["ok"] != true {
				t.Fatalf("exit=%d doc=%s, want ok once the target is up", result.ProcessExit, result.Stdout)
			}
			if target.AuthAttempts() != 1 || target.RejectedAuth() != 0 || jump.RejectedAuth() != 0 {
				t.Fatalf("target auth=%d rejected target=%d jump=%d, want 1 successful target login and no failed auth",
					target.AuthAttempts(), target.RejectedAuth(), jump.RejectedAuth())
			}
			if jump.AuthAttempts() < 2 || jump.ForwardAttempts() < tc.gate+1 {
				t.Fatalf("jump auth=%d forward attempts=%d, want the jump re-authenticated for the retry", jump.AuthAttempts(), jump.ForwardAttempts())
			}
		})
	}
}

// An abandoned chain dial must be torn down: a jump whose host key arrives
// after the attempt budget never receives credentials.
func TestCompiledWaitThroughJumpAbandonedDialSendsNoCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake remote hosts address the local file system with POSIX paths")
	}
	h := newCompiledCLIHarness(t)
	jump := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: proxyJumpPassword, AllowForward: true, DelayHandshake: 6500 * time.Millisecond})
	authorized, privatePEM := newJumpKey(t)
	target := newCompiledSSHFixture(t, compiledSSHFixtureOptions{AuthorizedKey: authorized})
	h.TrustSSHHost(t, jump)
	h.TrustSSHHost(t, target)
	targetConnection := target.Connection("target", "")
	targetConnection.KeyName = "target-key"
	targetConnection.ProxyJump = "jump"
	h.SaveVault(t, &config.Vault{
		Connections: []config.Connection{jump.Connection("jump", proxyJumpPassword), targetConnection},
		Keys:        []config.SSHKey{{Name: "target-key", PrivateKey: privatePEM}},
	})

	result := h.Run(t, "sshctl", nil, "--offline", "--json", "wait", "target", "--timeout", "7s", "--interval", "1s")
	doc := waitRetryJSON(t, result)
	if doc["error"] != "wait_timeout" {
		t.Fatalf("doc = %s, want wait_timeout", result.Stdout)
	}
	if jump.AuthAttempts() != 0 || target.AuthAttempts() != 0 {
		t.Fatalf("auth attempts jump=%d target=%d, want none after the dials were abandoned", jump.AuthAttempts(), target.AuthAttempts())
	}
}
