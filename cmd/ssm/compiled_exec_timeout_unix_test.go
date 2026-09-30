//go:build unix

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ssm/internal/config"
)

func decodeJSONLines(t *testing.T, stdout string) []map[string]any {
	t.Helper()
	var documents []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var document map[string]any
		if err := json.Unmarshal([]byte(line), &document); err != nil {
			t.Fatalf("stream line %q is not JSON: %v", line, err)
		}
		documents = append(documents, document)
	}
	return documents
}

func assertExecTimeoutDocument(t *testing.T, document map[string]any) {
	t.Helper()
	if document["ok"] != false || document["error"] != "exec_timeout" || document["stage"] != "remote_execution" ||
		document["exit"] != float64(124) || document["timed_out"] != true {
		t.Fatalf("exec timeout document = %v", document)
	}
	if _, present := document["outcome"]; present {
		t.Fatalf("exec_timeout must not carry outcome: %v", document)
	}
	if hint, _ := document["hint"].(string); !strings.Contains(hint, "--exec-timeout") {
		t.Fatalf("exec_timeout hint = %q", hint)
	}
}

func TestCompiledExecTimeoutJSONSignalsRemoteAndKeepsOutput(t *testing.T) {
	cli, fixture := newCompiledExecRunHarness(t, "exec-json")
	started := time.Now()
	result := runCompiledWithin(t, 40*time.Second, func() compiledCLIResult {
		return cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "exec-json", "--exec-timeout", "2s",
			"--argv", "sh", "-c", "echo partial-out; echo partial-err >&2; sleep 30")
	})
	elapsed := time.Since(started)
	if elapsed < 2*time.Second || elapsed > 12*time.Second {
		t.Fatalf("exec timeout returned after %s, want about 2s plus grace", elapsed)
	}
	if result.ProcessExit != 124 || result.Stderr != "" {
		t.Fatalf("exit=%d stderr=%q stdout=%q, want exit 124 and empty stderr", result.ProcessExit, result.Stderr, result.Stdout)
	}
	document := decodeExactlyOneJSONObject(t, result.Stdout)
	assertExecTimeoutDocument(t, document)
	if document["stdout"] != "partial-out\n" || document["stderr"] != "partial-err\n" {
		t.Fatalf("exec timeout dropped received output: %v", document)
	}
	if signals := fixture.Signals(); strings.Join(signals, ",") != "TERM" {
		t.Fatalf("remote signals = %q, want TERM", signals)
	}
	if strings.Contains(result.Stdout, "connection_lost") {
		t.Fatalf("self-inflicted close reported as connection_lost: %s", result.Stdout)
	}
}

func TestCompiledExecTimeoutClosesSessionWhenRemoteIgnoresTerm(t *testing.T) {
	cli, fixture := newCompiledExecRunHarness(t, "exec-ignore")
	started := time.Now()
	result := runCompiledWithin(t, 40*time.Second, func() compiledCLIResult {
		return cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "exec-ignore", "--exec-timeout", "1s",
			"--argv", "sh", "-c", "trap '' TERM; echo ready; while :; do sleep 0.2; done")
	})
	elapsed := time.Since(started)
	// 1s timeout, then the 5s grace before the session is closed.
	if elapsed < 5*time.Second || elapsed > 20*time.Second {
		t.Fatalf("stubborn command returned after %s, want about timeout plus grace", elapsed)
	}
	document := decodeExactlyOneJSONObject(t, result.Stdout)
	assertExecTimeoutDocument(t, document)
	if document["stdout"] != "ready\n" {
		t.Fatalf("stdout = %v", document["stdout"])
	}
	if signals := fixture.Signals(); strings.Join(signals, ",") != "TERM" {
		t.Fatalf("remote signals = %q, want a single TERM", signals)
	}
}

func TestCompiledExecTimeoutReportsTimeoutWhenRemoteTrapsTermAndExitsZero(t *testing.T) {
	cli, fixture := newCompiledExecRunHarness(t, "exec-trap")
	result := runCompiledWithin(t, 40*time.Second, func() compiledCLIResult {
		return cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "exec-trap", "--exec-timeout", "1s",
			"trap 'echo got-term; exit 0' TERM; echo ready; while :; do sleep 0.1; done")
	})
	if result.ProcessExit != 124 {
		t.Fatalf("exit=%d stdout=%q stderr=%q, want 124", result.ProcessExit, result.Stdout, result.Stderr)
	}
	document := decodeExactlyOneJSONObject(t, result.Stdout)
	assertExecTimeoutDocument(t, document)
	if out, _ := document["stdout"].(string); !strings.Contains(out, "ready") {
		t.Fatalf("stdout = %v", document["stdout"])
	}
	if signals := fixture.Signals(); strings.Join(signals, ",") != "TERM" {
		t.Fatalf("remote signals = %q, want TERM", signals)
	}
}

func TestCompiledExecTimeoutHumanKeepsStreamedOutputAndClassifies(t *testing.T) {
	cli, fixture := newCompiledExecRunHarness(t, "exec-human")
	result := runCompiledWithin(t, 40*time.Second, func() compiledCLIResult {
		return cli.Run(t, "sshctl", nil, "--offline", "run", "exec-human", "--exec-timeout", "1s",
			"--argv", "sh", "-c", "echo streamed-before-timeout; sleep 30")
	})
	if result.ProcessExit != 124 || result.Stdout != "streamed-before-timeout\n" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", result.ProcessExit, result.Stdout, result.Stderr)
	}
	if !strings.HasPrefix(result.Stderr, "ssm: error=exec_timeout stage=remote_execution alias=exec-human") ||
		!strings.Contains(result.Stderr, "ssm: hint=") || strings.Contains(result.Stderr, "connection_lost") {
		t.Fatalf("human stderr = %q", result.Stderr)
	}
	if signals := fixture.Signals(); strings.Join(signals, ",") != "TERM" {
		t.Fatalf("remote signals = %q, want TERM", signals)
	}
}

func TestCompiledExecTimeoutDoesNotAffectCommandThatFinishes(t *testing.T) {
	cli, fixture := newCompiledExecRunHarness(t, "exec-fast")
	result := cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "exec-fast", "--exec-timeout", "30s", "--argv", "echo", "fine")
	document := decodeExactlyOneJSONObject(t, result.Stdout)
	if result.ProcessExit != 0 || document["ok"] != true || document["stdout"] != "fine\n" {
		t.Fatalf("exit=%d document=%v", result.ProcessExit, document)
	}
	if _, present := document["timed_out"]; present {
		t.Fatalf("successful run carries timed_out: %v", document)
	}
	if len(fixture.Signals()) != 0 {
		t.Fatalf("signals = %q, want none", fixture.Signals())
	}
}

func TestCompiledExecTimeoutStreamContinuesOnSameConnection(t *testing.T) {
	cli, fixture := newCompiledExecRunHarness(t, "exec-stream")
	input := []byte("[\"sh\",\"-c\",\"echo first; sleep 30\"]\n[\"echo\",\"after\"]\n")
	result := runCompiledWithin(t, 40*time.Second, func() compiledCLIResult {
		return cli.Run(t, "sshctl", input, "--offline", "run", "exec-stream", "--stream", "--exec-timeout", "1s")
	})
	documents := decodeJSONLines(t, result.Stdout)
	if len(documents) != 2 {
		t.Fatalf("stream results = %d, want 2: %q stderr=%q", len(documents), result.Stdout, result.Stderr)
	}
	assertExecTimeoutDocument(t, documents[0])
	if documents[0]["stdout"] != "first\n" {
		t.Fatalf("timed-out stream line dropped output: %v", documents[0])
	}
	if documents[1]["ok"] != true || documents[1]["stdout"] != "after\n" {
		t.Fatalf("stream line after a timeout = %v", documents[1])
	}
	if signals := fixture.Signals(); strings.Join(signals, ",") != "TERM" {
		t.Fatalf("remote signals = %q, want TERM", signals)
	}
}

func TestCompiledExecTimeoutMapReportsEachHost(t *testing.T) {
	cli, fixture := newCompiledExecRunHarness(t, "exec-map-a")
	// Two aliases on one endpoint share the pooled connection, so this also
	// proves closing one timed-out session leaves the other job intact.
	second := fixture.Connection("exec-map-b")
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{fixture.Connection("exec-map-a"), second}})
	machine := runCompiledWithin(t, 40*time.Second, func() compiledCLIResult {
		return cli.Run(t, "sshctl", nil, "--offline", "--json", "map", "exec-map-a,exec-map-b", "--exec-timeout", "1s",
			"--argv", "sh", "-c", "echo mapped; sleep 30")
	})
	if machine.ProcessExit != 124 {
		t.Fatalf("map exit=%d stdout=%q stderr=%q", machine.ProcessExit, machine.Stdout, machine.Stderr)
	}
	var results []map[string]any
	if err := json.Unmarshal([]byte(machine.Stdout), &results); err != nil || len(results) != 2 {
		t.Fatalf("map results err=%v stdout=%q", err, machine.Stdout)
	}
	for _, result := range results {
		assertExecTimeoutDocument(t, result)
		if result["stdout"] != "mapped\n" {
			t.Fatalf("map result dropped output: %v", result)
		}
	}
	human := runCompiledWithin(t, 40*time.Second, func() compiledCLIResult {
		return cli.Run(t, "sshctl", nil, "--offline", "map", "exec-map-a,exec-map-b", "--exec-timeout", "1s",
			"--argv", "sh", "-c", "echo mapped; sleep 30")
	})
	if human.ProcessExit != 124 || !strings.Contains(human.Stdout, "\terror=exec_timeout") || strings.Contains(human.Stdout, "connection_lost") {
		t.Fatalf("human map exit=%d stdout=%q stderr=%q", human.ProcessExit, human.Stdout, human.Stderr)
	}
}

func TestCompiledExecTimeoutRequestField(t *testing.T) {
	cli, _ := newCompiledExecRunHarness(t, "exec-request")
	body := []byte(`{"version":1,"op":"run","alias":"exec-request","argv":["sleep","30"],"exec_timeout":"1s"}`)
	result := runCompiledWithin(t, 40*time.Second, func() compiledCLIResult {
		return cli.Run(t, "sshctl", body, "--offline", "request", "-")
	})
	assertExecTimeoutDocument(t, decodeExactlyOneJSONObject(t, result.Stdout))
	if result.ProcessExit != 124 {
		t.Fatalf("request exit=%d", result.ProcessExit)
	}

	invalid := cli.Run(t, "sshctl", []byte(`{"version":1,"op":"run","alias":"exec-request","argv":["true"],"exec_timeout":"soon"}`), "--offline", "request", "-")
	document := decodeExactlyOneJSONObject(t, invalid.Stdout)
	if invalid.ProcessExit != 2 || document["error"] != "invalid_request" {
		t.Fatalf("invalid exec_timeout exit=%d document=%v", invalid.ProcessExit, document)
	}
	put := cli.Run(t, "sshctl", []byte(`{"version":1,"op":"put","alias":"exec-request","local_path":"a","remote_path":"b","exec_timeout":"5s"}`), "--offline", "request", "-")
	if put.ProcessExit != 2 || decodeExactlyOneJSONObject(t, put.Stdout)["error"] != "invalid_request" {
		t.Fatalf("put with exec_timeout exit=%d stdout=%q", put.ProcessExit, put.Stdout)
	}
}

// silentProxy forwards TCP to target until blackhole is set, then keeps
// reading and discarding in both directions without closing anything, like a
// NAT entry that expired or a path that drops packets.
type silentProxy struct {
	listener  net.Listener
	blackhole atomic.Bool
	wg        sync.WaitGroup
}

func newSilentProxy(t *testing.T, target string) *silentProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &silentProxy{listener: listener}
	t.Cleanup(func() {
		_ = listener.Close()
		proxy.wg.Wait()
	})
	proxy.wg.Add(1)
	go func() {
		defer proxy.wg.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			upstream, err := net.Dial("tcp", target)
			if err != nil {
				_ = client.Close()
				continue
			}
			proxy.wg.Add(2)
			var once sync.Once
			closeBoth := func() { _ = client.Close(); _ = upstream.Close() }
			pipe := func(from, to net.Conn) {
				defer proxy.wg.Done()
				defer once.Do(closeBoth)
				buffer := make([]byte, 32<<10)
				for {
					n, err := from.Read(buffer)
					if n > 0 && !proxy.blackhole.Load() {
						if _, werr := to.Write(buffer[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}
			go pipe(client, upstream)
			go pipe(upstream, client)
		}
	}()
	return proxy
}

func newKeepaliveHarness(t *testing.T, alias string) (*compiledCLIHarness, *silentProxy) {
	t.Helper()
	cli, fixture := newCompiledExecRunHarness(t, alias)
	proxy := newSilentProxy(t, fixture.listener.Addr().String())
	trustCompiledExecSSHAddress(t, cli, proxy.listener.Addr().String(), fixture.signer)
	host, portText, _ := net.SplitHostPort(proxy.listener.Addr().String())
	port := 0
	for _, r := range portText {
		port = port*10 + int(r-'0')
	}
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{Name: alias, Host: host, Port: port, User: "fixture", Password: fixture.password}}})
	return cli, proxy
}

func TestCompiledKeepaliveDetectsSilentlyDroppedConnectionAsConnectionLost(t *testing.T) {
	cli, proxy := newKeepaliveHarness(t, "keepalive-human")
	cmd, stdout, stderr := cli.startCompiledCLI(t, map[string]string{"SSM_KEEPALIVE": "200ms"},
		"--offline", "run", "keepalive-human", "--argv", "sh", "-c", "echo started; sleep 30")
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "started\n" {
		t.Fatalf("first line = %q, %v; stderr=%q", line, err, stderr.String())
	}
	proxy.blackhole.Store(true)
	dropped := time.Now()
	exited := make(chan error, 1)
	go func() {
		_, _ = io.ReadAll(reader)
		exited <- cmd.Wait()
	}()
	select {
	case <-exited:
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("sshctl kept waiting on a silently dropped connection")
	}
	if elapsed := time.Since(dropped); elapsed > 10*time.Second {
		t.Fatalf("keepalive took %s to notice", elapsed)
	}
	if code := cmd.ProcessState.ExitCode(); code != 255 {
		t.Fatalf("exit=%d, want 255; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "error=connection_lost") || !strings.Contains(stderr.String(), "outcome=unknown") {
		t.Fatalf("stderr = %q, want connection_lost", stderr.String())
	}
}

func TestCompiledKeepaliveJSONResultIsConnectionLost(t *testing.T) {
	cli, proxy := newKeepaliveHarness(t, "keepalive-json")
	go func() {
		time.Sleep(1500 * time.Millisecond)
		proxy.blackhole.Store(true)
	}()
	started := time.Now()
	result := runCompiledWithin(t, 30*time.Second, func() compiledCLIResult {
		return cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_KEEPALIVE": "200ms"},
			"--offline", "--json", "run", "keepalive-json", "--argv", "sleep", "30")
	})
	if elapsed := time.Since(started); elapsed > 15*time.Second {
		t.Fatalf("keepalive took %s", elapsed)
	}
	document := decodeExactlyOneJSONObject(t, result.Stdout)
	if result.ProcessExit != 255 || document["error"] != "connection_lost" || document["outcome"] != "unknown" ||
		document["stage"] != "remote_execution" {
		t.Fatalf("exit=%d document=%v", result.ProcessExit, document)
	}
}

func TestCompiledKeepaliveDisabledDoesNotDropIdleConnection(t *testing.T) {
	cli, _ := newKeepaliveHarness(t, "keepalive-off")
	// With keepalive off and a healthy path, a command that outlives several
	// would-be intervals must still finish normally.
	result := runCompiledWithin(t, 30*time.Second, func() compiledCLIResult {
		return cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_KEEPALIVE": "0"},
			"--offline", "--json", "run", "keepalive-off", "--argv", "sh", "-c", "sleep 1; echo done")
	})
	document := decodeExactlyOneJSONObject(t, result.Stdout)
	if result.ProcessExit != 0 || document["ok"] != true || document["stdout"] != "done\n" {
		t.Fatalf("exit=%d document=%v", result.ProcessExit, document)
	}
}
