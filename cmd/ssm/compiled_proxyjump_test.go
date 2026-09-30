package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
)

// Issue #86: ProxyJump aliases. The fixtures are in-process fake SSH servers:
// a jump fixture relays direct-tcpip channels to a target fixture, and every
// hop is verified against the isolated known_hosts of the compiled CLI.

const proxyJumpPassword = "PROXYJUMP86_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary

type jumpHarness struct {
	cli          *compiledCLIHarness
	jump, target *compiledSSHFixture
}

func newJumpHarness(t *testing.T, trustJump, trustTarget bool) jumpHarness {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake remote hosts address the local file system with POSIX paths")
	}
	cli := newCompiledCLIHarness(t)
	jump := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: proxyJumpPassword, AllowForward: true})
	target := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: proxyJumpPassword, RunCommandContains: "hostname", RunStdoutFragments: []string{"target-host\nLinux 6.1\n"},
	})
	if trustJump {
		cli.TrustSSHHost(t, jump)
	}
	if trustTarget {
		cli.TrustSSHHost(t, target)
	}
	targetConnection := target.Connection("target", proxyJumpPassword)
	targetConnection.ProxyJump = "jump"
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{jump.Connection("jump", proxyJumpPassword), targetConnection}})
	return jumpHarness{cli: cli, jump: jump, target: target}
}

func proxyJumpFailure(t *testing.T, result compiledCLIResult, wantExit int, wantVia string) map[string]any {
	t.Helper()
	got := decodeExactlyOneJSONObject(t, result.Stdout)
	if result.ProcessExit != wantExit || got["ok"] != false || got["error"] != "host_key_unknown" || got["via"] != wantVia {
		t.Fatalf("failure = exit %d %v, want exit=%d error=host_key_unknown via=%s", result.ProcessExit, got, wantExit, wantVia)
	}
	if strings.Contains(result.Stdout+result.Stderr, proxyJumpPassword) {
		t.Fatalf("credential canary leaked: %s", compiledOutputIdentity(result))
	}
	return got
}

func TestCompiledProxyJumpRunPutGetCheckAndHostKeyInspect(t *testing.T) {
	h := newJumpHarness(t, true, true)

	run := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "target", "--argv", "hostname")
	got := decodeExactlyOneJSONObject(t, run.Stdout)
	if run.ProcessExit != 0 || got["ok"] != true || !strings.Contains(stringField(got, "stdout"), "target-host") {
		t.Fatalf("run through jump = exit %d %s", run.ProcessExit, run.Stdout)
	}
	if forwards := h.jump.Forwards(); len(forwards) != 1 || forwards[0] != h.target.Address() {
		t.Fatalf("jump forwards = %v, want exactly the target %s", forwards, h.target.Address())
	}
	if h.target.ConnectionCount() != 1 || h.jump.ConnectionCount() != 1 {
		t.Fatalf("connections jump=%d target=%d, want 1 each", h.jump.ConnectionCount(), h.target.ConnectionCount())
	}

	payload := bytes.Repeat([]byte("through-the-jump\n"), 1000)
	local := filepath.Join(h.cli.temp, "artifact.bin")
	issue80WriteFile(t, local, payload)
	remote := filepath.Join(t.TempDir(), "sub", "artifact.bin")
	put := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "target", local, remote, "--sha256")
	if got := decodeExactlyOneJSONObject(t, put.Stdout); put.ProcessExit != 0 || got["ok"] != true || got["integrity"] != "sha256_verified" {
		t.Fatalf("put through jump = exit %d %s", put.ProcessExit, put.Stdout)
	}
	if written, err := os.ReadFile(remote); err != nil || !bytes.Equal(written, payload) { //nolint:gosec // test-owned fixture path
		t.Fatalf("uploaded bytes differ: %v", err)
	}
	fetched := filepath.Join(h.cli.temp, "fetched.bin")
	get := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", "target", remote, fetched, "--sha256")
	if got := decodeExactlyOneJSONObject(t, get.Stdout); get.ProcessExit != 0 || got["ok"] != true || got["integrity"] != "sha256_verified" {
		t.Fatalf("get through jump = exit %d %s", get.ProcessExit, get.Stdout)
	}
	if downloaded, err := os.ReadFile(fetched); err != nil || !bytes.Equal(downloaded, payload) { //nolint:gosec // test-owned fixture path
		t.Fatalf("downloaded bytes differ: %v", err)
	}

	check := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "check", "target")
	if got := decodeExactlyOneJSONObject(t, check.Stdout); check.ProcessExit != 0 || got["ok"] != true || got["hostname"] != "target-host" {
		t.Fatalf("check through jump = exit %d %s", check.ProcessExit, check.Stdout)
	}
	doctor := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "doctor", "target")
	if got := decodeExactlyOneJSONObject(t, doctor.Stdout); doctor.ProcessExit != 0 || got["ok"] != true {
		t.Fatalf("doctor through jump = exit %d %s", doctor.ProcessExit, doctor.Stdout)
	}

	inspect := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "inspect", "target")
	got = decodeExactlyOneJSONObject(t, inspect.Stdout)
	wantFingerprint := gossh.FingerprintSHA256(h.target.signer.PublicKey())
	if inspect.ProcessExit != 0 || got["status"] != "trusted" || got["fingerprint"] != wantFingerprint || got["address"] != h.target.Address() {
		t.Fatalf("host-key inspect through jump = exit %d %s, want the target's key %s", inspect.ProcessExit, inspect.Stdout, wantFingerprint)
	}
	for _, forwarded := range h.jump.Forwards() {
		if forwarded != h.target.Address() {
			t.Fatalf("jump relayed %s, want only the target", forwarded)
		}
	}
}

func stringField(document map[string]any, name string) string {
	value, _ := document[name].(string)
	return value
}

func (h *compiledCLIHarness) mustSSHDirText(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.home, ".ssh", "known_hosts")) //nolint:gosec // test-owned fixture path
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCompiledProxyJumpHostKeyAcceptRecordsOnlyTheTarget(t *testing.T) {
	h := newJumpHarness(t, true, false)
	fingerprint := gossh.FingerprintSHA256(h.target.signer.PublicKey())

	inspect := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "inspect", "target")
	if got := decodeExactlyOneJSONObject(t, inspect.Stdout); inspect.ProcessExit != 0 || got["status"] != "new" || got["fingerprint"] != fingerprint {
		t.Fatalf("inspect = exit %d %s", inspect.ProcessExit, inspect.Stdout)
	}
	accept := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "accept", "target", "--fingerprint", fingerprint, "--yes")
	if got := decodeExactlyOneJSONObject(t, accept.Stdout); accept.ProcessExit != 0 || got["accepted"] != true || got["status"] != "trusted" {
		t.Fatalf("accept = exit %d %s", accept.ProcessExit, accept.Stdout)
	}
	if !strings.Contains(h.cli.mustSSHDirText(t), strings.Fields(string(gossh.MarshalAuthorizedKey(h.target.signer.PublicKey())))[1]) {
		t.Fatal("known_hosts does not hold the target key")
	}
	run := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "target", "--argv", "hostname")
	if got := decodeExactlyOneJSONObject(t, run.Stdout); run.ProcessExit != 0 || got["ok"] != true {
		t.Fatalf("run after accept = exit %d %s", run.ProcessExit, run.Stdout)
	}
}

func TestCompiledProxyJumpUntrustedJumpKeyFailsBeforeAuthenticatingAnywhere(t *testing.T) {
	h := newJumpHarness(t, false, true)
	for name, args := range map[string][]string{
		"run": {"run", "target", "--argv", "hostname"},
		"put": {"put", "target", filepath.Join(h.cli.temp, "src"), "/remote/dest"},
		"get": {"get", "target", "/remote/src", filepath.Join(h.cli.temp, "dest")},
	} {
		t.Run(name, func(t *testing.T) {
			issue80WriteFile(t, filepath.Join(h.cli.temp, "src"), []byte("data"))
			result := h.cli.Run(t, "sshctl", nil, append([]string{"--offline", "--json"}, args...)...)
			got := proxyJumpFailure(t, result, 255, "jump")
			if name == "run" && got["stage"] != "dial" {
				t.Fatalf("stage = %v, want dial: %v", got["stage"], got)
			}
			if hint, _ := got["hint"].(string); !strings.Contains(hint, "host-key inspect jump") {
				t.Fatalf("hint = %q, want it to point at the jump alias", hint)
			}
		})
	}
	if h.jump.AuthAttempts() != 0 || h.target.AuthAttempts() != 0 || len(h.jump.Forwards()) != 0 || h.target.ConnectionCount() != 0 {
		t.Fatalf("untrusted jump: jump auth=%d target auth=%d forwards=%v target connections=%d, want none",
			h.jump.AuthAttempts(), h.target.AuthAttempts(), h.jump.Forwards(), h.target.ConnectionCount())
	}

	inspect := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "host-key", "inspect", "target")
	got := proxyJumpFailure(t, inspect, 1, "jump")
	if got["stage"] != "host_key" {
		t.Fatalf("host-key inspect stage = %v: %v", got["stage"], got)
	}
	if h.jump.AuthAttempts() != 0 || h.target.ConnectionCount() != 0 {
		t.Fatal("host-key inspect contacted past an untrusted jump host")
	}

	human := h.cli.Run(t, "sshctl", nil, "--offline", "run", "target", "--argv", "hostname")
	if human.ProcessExit != 255 || !strings.Contains(human.Stderr, "via jump") {
		t.Fatalf("human failure = exit %d stderr=%q, want the failing hop named", human.ProcessExit, human.Stderr)
	}
}

func TestCompiledProxyJumpUntrustedTargetKeyNamesTheTarget(t *testing.T) {
	h := newJumpHarness(t, true, false)
	result := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "target", "--argv", "hostname")
	got := proxyJumpFailure(t, result, 255, "target")
	if hint, _ := got["hint"].(string); !strings.Contains(hint, "host-key inspect target") {
		t.Fatalf("hint = %q", hint)
	}
	if h.target.AuthAttempts() != 0 {
		t.Fatalf("target saw %d authentication attempts before its key was trusted", h.target.AuthAttempts())
	}
	if h.jump.AuthAttempts() != 1 || len(h.jump.Forwards()) != 1 {
		t.Fatalf("jump auth=%d forwards=%v, want the jump hop to have completed", h.jump.AuthAttempts(), h.jump.Forwards())
	}
}

func TestCompiledProxyJumpTwoLevelChain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake remote hosts address the local file system with POSIX paths")
	}
	cli := newCompiledCLIHarness(t)
	a := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: proxyJumpPassword, AllowForward: true})
	b := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: proxyJumpPassword, AllowForward: true})
	c := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: proxyJumpPassword, RunCommandContains: "hostname", RunStdoutFragments: []string{"host-c\n"}})
	for _, server := range []*compiledSSHFixture{a, b, c} {
		cli.TrustSSHHost(t, server)
	}
	second, third := b.Connection("b", proxyJumpPassword), c.Connection("c", proxyJumpPassword)
	second.ProxyJump = "a"
	third.ProxyJump = "b"
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{a.Connection("a", proxyJumpPassword), second, third}})

	run := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "c", "--argv", "hostname")
	if got := decodeExactlyOneJSONObject(t, run.Stdout); run.ProcessExit != 0 || got["ok"] != true || !strings.Contains(stringField(got, "stdout"), "host-c") {
		t.Fatalf("run through A->B->C = exit %d %s", run.ProcessExit, run.Stdout)
	}
	if forwards := a.Forwards(); len(forwards) != 1 || forwards[0] != b.Address() {
		t.Fatalf("A forwards = %v, want only B %s", forwards, b.Address())
	}
	if forwards := b.Forwards(); len(forwards) != 1 || forwards[0] != c.Address() {
		t.Fatalf("B forwards = %v, want only C %s", forwards, c.Address())
	}
	if len(c.Forwards()) != 0 {
		t.Fatal("the target forwarded channels")
	}

	// Each hop authenticates on its own: an untrusted middle hop stops the
	// chain there and names it.
	cli2 := newCompiledCLIHarness(t)
	for _, server := range []*compiledSSHFixture{a, c} {
		cli2.TrustSSHHost(t, server)
	}
	cli2.SaveVault(t, &config.Vault{Connections: []config.Connection{a.Connection("a", proxyJumpPassword), second, third}})
	beforeC := c.ConnectionCount()
	bad := cli2.Run(t, "sshctl", nil, "--offline", "--json", "run", "c", "--argv", "hostname")
	proxyJumpFailure(t, bad, 255, "b")
	if c.ConnectionCount() != beforeC || c.AuthAttempts() != 1 {
		t.Fatalf("target connections %d->%d auth attempts %d: the untrusted middle hop must stop the chain", beforeC, c.ConnectionCount(), c.AuthAttempts())
	}
}

func TestCompiledProxyJumpRejectsInvalidChainsBeforeConnecting(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: proxyJumpPassword, AllowForward: true})
	cli.TrustSSHHost(t, server)
	link := func(name, jump string) config.Connection {
		c := server.Connection(name, proxyJumpPassword)
		c.ProxyJump = jump
		return c
	}
	connections := []config.Connection{
		link("loop-a", "loop-b"), link("loop-b", "loop-a"), link("self", "self"),
		link("orphan", "no-such-jump"),
		link("h0", ""), link("h1", "h0"), link("h2", "h1"), link("h3", "h2"), link("h4", "h3"), link("h5", "h4"), link("h6", "h5"),
		link("h5-ok", "h4"),
	}
	cli.SaveVault(t, &config.Vault{Connections: connections})

	for _, tt := range []struct{ alias, via string }{
		{"loop-a", "loop-a"}, {"self", "self"}, {"orphan", "no-such-jump"}, {"h6", "h5"},
	} {
		t.Run(tt.alias, func(t *testing.T) {
			result := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", tt.alias, "--argv", "hostname")
			got := decodeExactlyOneJSONObject(t, result.Stdout)
			if result.ProcessExit != 2 || got["ok"] != false || got["error"] != "proxy_jump_invalid" || got["stage"] != "validate" {
				t.Fatalf("run %s = exit %d %s, want proxy_jump_invalid/validate exit 2", tt.alias, result.ProcessExit, result.Stdout)
			}
			if hint, _ := got["hint"].(string); hint == "" {
				t.Fatal("no hint")
			}
			if message, _ := got["message"].(string); !strings.Contains(message, tt.via) {
				t.Fatalf("message %q does not name %s", message, tt.via)
			}
		})
	}
	if server.ConnectionCount() != 0 {
		t.Fatalf("an invalid chain opened %d connections", server.ConnectionCount())
	}
	// Five jump hosts is the limit and is accepted.
	ok := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "h5-ok", "--argv", "hostname")
	if got := decodeExactlyOneJSONObject(t, ok.Stdout); got["error"] == "proxy_jump_invalid" {
		t.Fatalf("a chain at the depth limit was rejected: %s", ok.Stdout)
	}
}

func TestCompiledHostProxyJumpField(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	passwordPath := filepath.Join(cli.temp, "host.pass")
	issue80WriteFile(t, passwordPath, []byte("proxy-jump-host-credential\n"))
	show := func(t *testing.T) map[string]any {
		t.Helper()
		return decodeExactlyOneJSONObject(t, cli.Run(t, "sshctl", nil, "--json", "host", "show", "inner", "--offline").Stdout)
	}
	for _, alias := range []string{"bastion", "inner"} {
		add := cli.Run(t, "sshctl", nil, "--json", "host", "add", alias, "--host", "192.0.2.86", "--user", "runner", "--password-file", passwordPath, "--offline")
		if got := decodeExactlyOneJSONObject(t, add.Stdout); add.ProcessExit != 0 || got["ok"] != true {
			t.Fatalf("host add %s = %s", alias, compiledOutputIdentity(add))
		}
	}
	set := cli.Run(t, "sshctl", nil, "--json", "host", "update", "inner", "--proxy-jump", "bastion", "--offline")
	if got := decodeExactlyOneJSONObject(t, set.Stdout); set.ProcessExit != 0 || got["ok"] != true {
		t.Fatalf("host update --proxy-jump = %s", compiledOutputIdentity(set))
	}
	if got := show(t); got["proxy_jump"] != "bastion" {
		t.Fatalf("host show after set = %v", got)
	}
	unrelated := cli.Run(t, "sshctl", nil, "--json", "host", "update", "inner", "--group", "lab", "--offline")
	if unrelated.ProcessExit != 0 {
		t.Fatalf("unrelated update = %s", compiledOutputIdentity(unrelated))
	}
	if got := show(t); got["proxy_jump"] != "bastion" {
		t.Fatalf("an unrelated update must keep proxy_jump: %v", got)
	}
	self := cli.Run(t, "sshctl", nil, "--json", "host", "update", "inner", "--proxy-jump", "inner", "--offline")
	if got := decodeExactlyOneJSONObject(t, self.Stdout); self.ProcessExit == 0 || got["ok"] != false {
		t.Fatalf("a self-referencing proxy jump was accepted: %s", self.Stdout)
	}
	clear := cli.Run(t, "sshctl", nil, "--json", "host", "update", "inner", "--proxy-jump", "", "--offline")
	if got := decodeExactlyOneJSONObject(t, clear.Stdout); clear.ProcessExit != 0 || got["ok"] != true {
		t.Fatalf("host update --proxy-jump '' = %s", compiledOutputIdentity(clear))
	}
	if got := show(t); got["proxy_jump"] != nil {
		t.Fatalf("an empty value must clear proxy_jump: %v", got)
	}

	request, err := json.Marshal(map[string]any{
		"version": 1, "op": "host.update", "alias": "inner",
		"host": map[string]any{"proxy_jump": "bastion", "offline": true, "verify": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	viaRequest := cli.Run(t, "sshctl", request, "request", "-")
	if got := decodeExactlyOneJSONObject(t, viaRequest.Stdout); viaRequest.ProcessExit != 0 || got["ok"] != true {
		t.Fatalf("request host.update proxy_jump = %s", compiledOutputIdentity(viaRequest))
	}
	if got := show(t); got["proxy_jump"] != "bastion" {
		t.Fatalf("host show after request = %v", got)
	}
}
