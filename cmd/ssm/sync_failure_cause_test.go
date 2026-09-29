package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"ssm/internal/config"
)

const syncCauseMessagePrefix = "sync refresh failed: remote refresh did not commit: "

// TestCompiledSyncFailureCauseIsStableAndDistinct proves each refresh failure
// class reaches the public --json result as its own stable cause and that the
// hint is actionable for that class. Timeout is covered by the classifier unit
// tests because the transport timeout is a fixed 15 seconds.
func TestCompiledSyncFailureCauseIsStableAndDistinct(t *testing.T) {
	const token = "SYNC_CAUSE_TOKEN_CANARY" //nolint:gosec // test-only fake credential canary
	const offlineHint = " or retry explicitly with --offline"
	tests := []struct {
		name      string
		configure func(t *testing.T, cli *compiledCLIHarness)
		cause     string
		hint      string
	}{
		{
			name: "connection refused",
			configure: func(t *testing.T, cli *compiledCLIHarness) {
				refused := newCompiledRefusedTCPPort(t)
				cli.SaveCloud(t, "http://"+net.JoinHostPort(refused.host, strconv.Itoa(refused.port)), token)
			},
			cause: "connect_refused",
			hint:  "sync server refused the connection; check the service is running," + offlineHint,
		},
		{
			name: "unauthorized",
			configure: func(t *testing.T, cli *compiledCLIHarness) {
				sync := newCompiledSyncFixture(t)
				sync.SetStatus(t, http.MethodHead, http.StatusUnauthorized)
				cli.SaveCloud(t, sync.URL(), token)
			},
			cause: "auth",
			hint:  "sync token rejected; re-authenticate with ssm login, then retry",
		},
		{
			name: "forbidden",
			configure: func(t *testing.T, cli *compiledCLIHarness) {
				sync := newCompiledSyncFixture(t)
				sync.SetStatus(t, http.MethodHead, http.StatusForbidden)
				cli.SaveCloud(t, sync.URL(), token)
			},
			cause: "auth",
			hint:  "sync token rejected; re-authenticate with ssm login, then retry",
		},
		{
			name: "service unavailable",
			configure: func(t *testing.T, cli *compiledCLIHarness) {
				sync := newCompiledSyncFixture(t)
				sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)
				cli.SaveCloud(t, sync.URL(), token)
			},
			cause: "http_5xx",
			hint:  "sync server returned a 5xx error; retry later" + offlineHint,
		},
		{
			name: "untrusted tls certificate",
			configure: func(t *testing.T, cli *compiledCLIHarness) {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(server.Close)
				cli.SaveCloud(t, server.URL, token)
			},
			cause: "tls",
			hint:  "sync server certificate verification failed; fix the server certificate or trust chain," + offlineHint,
		},
		{
			name: "dns failure",
			configure: func(t *testing.T, cli *compiledCLIHarness) {
				cli.SaveCloud(t, "http://sync-cause.invalid", token)
			},
			cause: "dns",
			hint:  "sync server name did not resolve; check the configured server and DNS," + offlineHint,
		},
	}

	seen := map[string]string{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cli := newCompiledCLIHarness(t)
			cli.SaveVault(t, &config.Vault{})
			test.configure(t, cli)

			result := cli.Run(t, "sshctl", nil, "--json", "list")
			assertNoCompiledCanaryLeak(t, result, map[string]string{
				"token": token, "authorization": "Authorization", "bearer": "Bearer ",
			})
			assertCompiledMachineContract(t, result, compiledMachineContract{
				OK: false, Error: "sync_pull_failed", Stage: "sync_pull", JSONExit: 1, ProcessExit: 1,
				Cause: test.cause, Hint: test.hint,
			})
			document := decodeExactlyOneJSONObject(t, result.Stdout)
			message, _ := document["message"].(string)
			if !strings.HasPrefix(message, syncCauseMessagePrefix) || len(message) == len(syncCauseMessagePrefix) {
				t.Fatalf("message does not carry the underlying error; output=%s", compiledOutputIdentity(result))
			}
			if test.cause == "auth" && strings.Contains(test.hint, "--offline") {
				t.Fatalf("auth hint suggests --offline: %q", test.hint)
			}
			if strings.Contains(result.Stdout, "restart explicitly") {
				t.Fatalf("hint wording is not unified; output=%s", compiledOutputIdentity(result))
			}
			seen[test.name] = test.cause
		})
	}
	if t.Failed() {
		return
	}
	byCause := map[string]int{}
	for _, cause := range seen {
		byCause[cause]++
	}
	// Two auth statuses share a cause; every other class must be distinct.
	if len(byCause) != len(tests)-1 || byCause["auth"] != 2 {
		t.Fatalf("causes are not distinct per failure class: %v", seen)
	}
}

func TestCompiledSyncFailureCauseHumanLineAndStream(t *testing.T) {
	const token = "SYNC_CAUSE_HUMAN_TOKEN_CANARY" //nolint:gosec // test-only fake credential canary
	cli := newCompiledCLIHarness(t)
	cli.SaveVault(t, &config.Vault{})
	sync := newCompiledSyncFixture(t)
	sync.SetStatus(t, http.MethodHead, http.StatusUnauthorized)
	cli.SaveCloud(t, sync.URL(), token)

	human := cli.Run(t, "sshctl", nil, "list")
	assertNoCompiledCanaryLeak(t, human, map[string]string{"token": token, "authorization": "Authorization"})
	wantHuman := "ssm: error=sync_pull_failed stage=sync_pull cause=auth\n" +
		"Error: " + syncCauseMessagePrefix + "server error (401)\n" +
		"ssm: hint=sync token rejected; re-authenticate with ssm login, then retry\n"
	if human.ProcessExit != 1 || human.Stdout != "" || human.Stderr != wantHuman {
		t.Fatalf("human sync failure drifted; output=%s", compiledOutputIdentity(human))
	}

	stream := cli.RunWithHeldOpenStdin(t, "sshctl", "--json", "run", "unused", "--stream", "--refresh=30s")
	assertNoCompiledCanaryLeak(t, stream, map[string]string{"token": token, "authorization": "Authorization"})
	assertCompiledMachineContract(t, stream, compiledMachineContract{
		OK: false, Error: "sync_pull_failed", Stage: "sync_pull", JSONExit: 1, ProcessExit: 1,
		Cause: "auth", Hint: "sync token rejected; re-authenticate with ssm login, then retry",
		Cardinality: "one_line",
	})
}
