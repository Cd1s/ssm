package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/config"
)

const transportErrorsPassword = "TRANSPORT_ERRORS_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary

type transportErrorsHarness struct {
	cli       *compiledCLIHarness
	lost      *compiledSSHFixture
	handshake *compiledSSHFixture
	healthy   *compiledSSHFixture
}

// newTransportErrorsHarness starts three fake servers: one that drops the TCP
// connection while the command runs, one that hangs up during the SSH
// handshake, and one that runs the command normally.
func newTransportErrorsHarness(t *testing.T) transportErrorsHarness {
	t.Helper()
	cli := newCompiledCLIHarness(t)
	h := transportErrorsHarness{
		cli:       cli,
		lost:      newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: transportErrorsPassword, DropAfterExec: true}),
		handshake: newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: transportErrorsPassword, DropDuringHandshake: true}),
		healthy: newCompiledSSHFixture(t, compiledSSHFixtureOptions{
			Password: transportErrorsPassword, RunCommandContains: "transport-ok", RunStdoutFragments: []string{"fine\n"},
		}),
	}
	for _, server := range []*compiledSSHFixture{h.lost, h.handshake, h.healthy} {
		cli.TrustSSHHost(t, server)
	}
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{
		h.healthy.Connection("a-ok", transportErrorsPassword),
		h.lost.Connection("b-lost", transportErrorsPassword),
		h.handshake.Connection("c-handshake", transportErrorsPassword),
	}})
	return h
}

func TestCompiledRunClassifiesConnectionLostDuringExecution(t *testing.T) {
	h := newTransportErrorsHarness(t)

	machine := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "b-lost", "--argv", "transport-ok")
	if machine.ProcessExit != 255 || machine.Stderr != "" {
		t.Fatalf("json run exit=%d stderr=%q stdout=%q, want exit 255 and empty stderr", machine.ProcessExit, machine.Stderr, machine.Stdout)
	}
	document := decodeExactlyOneJSONObject(t, machine.Stdout)
	if document["ok"] != false || document["error"] != "connection_lost" || document["outcome"] != "unknown" ||
		document["stage"] != "remote_execution" || document["exit"] != float64(255) || document["alias"] != "b-lost" {
		t.Fatalf("json run document = %s", machine.Stdout)
	}
	if hint, _ := document["hint"].(string); !strings.Contains(hint, "do not retry blindly") {
		t.Fatalf("connection_lost hint = %q", hint)
	}

	human := h.cli.Run(t, "sshctl", nil, "--offline", "run", "b-lost", "--argv", "transport-ok")
	wantPrefix := "ssm: error=connection_lost stage=remote_execution outcome=unknown alias=b-lost address=" + h.lost.Address() + "\n"
	if human.ProcessExit != 255 || human.Stdout != "" || !strings.HasPrefix(human.Stderr, wantPrefix) ||
		!strings.Contains(human.Stderr, "ssm: hint=") {
		t.Fatalf("human run exit=%d stdout=%q stderr=%q, want exit 255 with prefix %q", human.ProcessExit, human.Stdout, human.Stderr, wantPrefix)
	}
	if strings.Contains(human.Stderr, "error=internal") || strings.Contains(machine.Stdout, `"internal"`) {
		t.Fatal("connection loss must not be reported as internal")
	}
}

func TestCompiledRunClassifiesHandshakeFailure(t *testing.T) {
	h := newTransportErrorsHarness(t)

	machine := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "run", "c-handshake", "--argv", "transport-ok")
	if machine.ProcessExit != 255 || machine.Stderr != "" {
		t.Fatalf("json run exit=%d stderr=%q stdout=%q, want exit 255 and empty stderr", machine.ProcessExit, machine.Stderr, machine.Stdout)
	}
	document := decodeExactlyOneJSONObject(t, machine.Stdout)
	if document["ok"] != false || document["error"] != "handshake_failed" || document["stage"] != "handshake" ||
		document["exit"] != float64(255) || document["alias"] != "c-handshake" {
		t.Fatalf("json run document = %s", machine.Stdout)
	}
	if _, present := document["outcome"]; present {
		t.Fatalf("handshake_failed must not carry outcome: %s", machine.Stdout)
	}

	human := h.cli.Run(t, "sshctl", nil, "--offline", "run", "c-handshake", "--argv", "transport-ok")
	wantPrefix := "ssm: error=handshake_failed stage=handshake alias=c-handshake address=" + h.handshake.Address() + "\n"
	if human.ProcessExit != 255 || human.Stdout != "" || !strings.HasPrefix(human.Stderr, wantPrefix) {
		t.Fatalf("human run exit=%d stdout=%q stderr=%q, want exit 255 with prefix %q", human.ProcessExit, human.Stdout, human.Stderr, wantPrefix)
	}
	if strings.Contains(human.Stderr, "outcome=") {
		t.Fatalf("handshake_failed human output carries outcome: %q", human.Stderr)
	}
}

func TestCompiledMapClassifiesEachResultIndependently(t *testing.T) {
	h := newTransportErrorsHarness(t)

	machine := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "map", "a-ok,b-lost,c-handshake", "--argv", "transport-ok")
	if machine.ProcessExit != 255 || machine.Stderr != "" {
		t.Fatalf("json map exit=%d stderr=%q stdout=%q, want exit 255", machine.ProcessExit, machine.Stderr, machine.Stdout)
	}
	var results []map[string]any
	if err := json.Unmarshal([]byte(machine.Stdout), &results); err != nil || len(results) != 3 {
		t.Fatalf("json map results err=%v len=%d stdout=%q", err, len(results), machine.Stdout)
	}
	byAlias := map[string]map[string]any{}
	for _, result := range results {
		alias, _ := result["alias"].(string)
		byAlias[alias] = result
	}
	if ok := byAlias["a-ok"]; ok["ok"] != true || ok["error"] != nil || ok["outcome"] != nil {
		t.Fatalf("healthy map result = %v", ok)
	}
	lost := byAlias["b-lost"]
	if lost["ok"] != false || lost["error"] != "connection_lost" || lost["outcome"] != "unknown" ||
		lost["stage"] != "remote_execution" || lost["exit"] != float64(255) {
		t.Fatalf("lost map result = %v", lost)
	}
	handshake := byAlias["c-handshake"]
	if handshake["ok"] != false || handshake["error"] != "handshake_failed" || handshake["stage"] != "handshake" ||
		handshake["exit"] != float64(255) || handshake["outcome"] != nil {
		t.Fatalf("handshake map result = %v", handshake)
	}

	human := h.cli.Run(t, "sshctl", nil, "--offline", "map", "a-ok,b-lost,c-handshake", "--argv", "transport-ok")
	if human.ProcessExit != 255 {
		t.Fatalf("human map exit=%d stdout=%q stderr=%q, want 255", human.ProcessExit, human.Stdout, human.Stderr)
	}
	for _, want := range []string{"b-lost\tfail\texit=255", "\terror=connection_lost\toutcome=unknown", "c-handshake\tfail\texit=255", "\terror=handshake_failed\n", "summary\tok=1\tfail=2\ttotal=3"} {
		if !strings.Contains(human.Stdout, want) {
			t.Fatalf("human map stdout missing %q:\n%s", want, human.Stdout)
		}
	}
	if strings.Contains(human.Stdout, "error=internal") {
		t.Fatalf("human map reported internal:\n%s", human.Stdout)
	}
}

func TestCompiledPutClassifiesConnectionLostMidTransfer(t *testing.T) {
	h := newTransportErrorsHarness(t)
	source := filepath.Join(h.cli.temp, "put-source")
	if err := os.WriteFile(source, []byte("payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	machine := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "b-lost", source, "/remote/dest")
	if machine.ProcessExit != 255 || machine.Stderr != "" {
		t.Fatalf("json put exit=%d stderr=%q stdout=%q, want exit 255", machine.ProcessExit, machine.Stderr, machine.Stdout)
	}
	document := decodeExactlyOneJSONObject(t, machine.Stdout)
	if document["ok"] != false || document["error"] != "connection_lost" || document["outcome"] != "unknown" ||
		document["stage"] != "remote_execution" || document["exit"] != float64(255) || document["direction"] != "put" {
		t.Fatalf("json put document = %s", machine.Stdout)
	}

	human := h.cli.Run(t, "sshctl", nil, "--offline", "put", "b-lost", source, "/remote/dest")
	want := "ssm: error=connection_lost stage=remote_execution outcome=unknown alias=b-lost address=" + h.lost.Address() + "\n"
	if human.ProcessExit != 255 || human.Stdout != "" || !strings.HasPrefix(human.Stderr, want) {
		t.Fatalf("human put exit=%d stdout=%q stderr=%q, want exit 255 with prefix %q", human.ProcessExit, human.Stdout, human.Stderr, want)
	}
}

func TestCompiledGetClassifiesConnectionLostMidTransfer(t *testing.T) {
	h := newTransportErrorsHarness(t)
	destination := filepath.Join(h.cli.temp, "get-destination")

	machine := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "get", "b-lost", "/remote/source", destination)
	if machine.ProcessExit != 255 || machine.Stderr != "" {
		t.Fatalf("json get exit=%d stderr=%q stdout=%q, want exit 255", machine.ProcessExit, machine.Stderr, machine.Stdout)
	}
	document := decodeExactlyOneJSONObject(t, machine.Stdout)
	if document["ok"] != false || document["error"] != "connection_lost" || document["outcome"] != "unknown" ||
		document["stage"] != "remote_execution" || document["exit"] != float64(255) || document["direction"] != "get" {
		t.Fatalf("json get document = %s", machine.Stdout)
	}

	human := h.cli.Run(t, "sshctl", nil, "--offline", "get", "b-lost", "/remote/source", destination)
	want := "ssm: error=connection_lost stage=remote_execution outcome=unknown alias=b-lost address=" + h.lost.Address() + "\n"
	if human.ProcessExit != 255 || human.Stdout != "" || !strings.HasPrefix(human.Stderr, want) {
		t.Fatalf("human get exit=%d stdout=%q stderr=%q, want exit 255 with prefix %q", human.ProcessExit, human.Stdout, human.Stderr, want)
	}
}

// A --timeout abort is sshctl closing its own session; the EOF that follows
// must not be reclassified as connection_lost.
func TestCompiledPutTimeoutStaysTransferTimeout(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: transportErrorsPassword, HangAfterExec: true})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("hang", transportErrorsPassword)}})
	source := filepath.Join(cli.temp, "put-source")
	if err := os.WriteFile(source, []byte("payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	machine := cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "hang", source, "/remote/dest", "--timeout", "1s")
	if machine.ProcessExit != 1 || machine.Stderr != "" {
		t.Fatalf("json put exit=%d stderr=%q stdout=%q, want exit 1", machine.ProcessExit, machine.Stderr, machine.Stdout)
	}
	document := decodeExactlyOneJSONObject(t, machine.Stdout)
	if document["error"] != "transfer_timeout" || document["stage"] != "timeout" || document["exit"] != float64(1) || document["direction"] != "put" {
		t.Fatalf("json put document = %s", machine.Stdout)
	}
	if _, present := document["outcome"]; present {
		t.Fatalf("transfer_timeout must not carry outcome: %s", machine.Stdout)
	}

	human := cli.Run(t, "sshctl", nil, "--offline", "put", "hang", source, "/remote/dest", "--timeout", "1s")
	if human.ProcessExit != 1 || human.Stdout != "" || !strings.Contains(human.Stderr, "error=transfer_timeout") || strings.Contains(human.Stderr, "connection_lost") {
		t.Fatalf("human put exit=%d stdout=%q stderr=%q, want exit 1 transfer_timeout", human.ProcessExit, human.Stdout, human.Stderr)
	}
}

func TestCompiledPutClassifiesHandshakeFailure(t *testing.T) {
	h := newTransportErrorsHarness(t)
	source := filepath.Join(h.cli.temp, "put-source")
	if err := os.WriteFile(source, []byte("payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	machine := h.cli.Run(t, "sshctl", nil, "--offline", "--json", "put", "c-handshake", source, "/remote/dest")
	if machine.ProcessExit != 255 || machine.Stderr != "" {
		t.Fatalf("json put exit=%d stderr=%q stdout=%q, want exit 255", machine.ProcessExit, machine.Stderr, machine.Stdout)
	}
	document := decodeExactlyOneJSONObject(t, machine.Stdout)
	if document["error"] != "handshake_failed" || document["stage"] != "handshake" || document["exit"] != float64(255) {
		t.Fatalf("json put document = %s", machine.Stdout)
	}
	if _, present := document["outcome"]; present {
		t.Fatalf("handshake_failed must not carry outcome: %s", machine.Stdout)
	}

	human := h.cli.Run(t, "sshctl", nil, "--offline", "put", "c-handshake", source, "/remote/dest")
	want := "ssm: error=handshake_failed stage=handshake alias=c-handshake address=" + h.handshake.Address() + "\n"
	if human.ProcessExit != 255 || human.Stdout != "" || !strings.HasPrefix(human.Stderr, want) {
		t.Fatalf("human put exit=%d stdout=%q stderr=%q, want exit 255 with prefix %q", human.ProcessExit, human.Stdout, human.Stderr, want)
	}
}
