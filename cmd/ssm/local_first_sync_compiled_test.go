package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ssm/internal/config"
)

// The compiled harness runs every command in strict sync mode by default (the
// suite predates local_first). These tests select local_first explicitly and
// pin the clock through the sync fixture so scheduling is deterministic.

var localFirstClock = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

const localFirstFastRun = 2 * time.Second

type localFirstScenario struct {
	cli       *compiledCLIHarness
	ssh       *compiledSSHFixture
	sync      *compiledSyncFixture
	alias     string
	localBlob []byte
	env       map[string]string
}

// newLocalFirstScenario builds a vault with one reachable SSH host and a healthy
// sync endpoint whose remote identity equals the local vault.
func newLocalFirstScenario(t *testing.T) *localFirstScenario {
	t.Helper()
	cli := newCompiledCLIHarness(t)
	password := "LOCAL_FIRST_SSH_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{Password: password})
	cli.TrustSSHHost(t, server)
	cli.SaveVault(t, &config.Vault{Connections: []config.Connection{server.Connection("lf-host", password)}})
	sync := newCompiledSyncFixture(t)
	sync.SetClock(t, localFirstClock)
	blob := cli.VaultBlob(t)
	sync.SetRemote(t, blob, compiledOpaqueIdentity(blob))
	cli.SaveRemoteETag(t, compiledOpaqueIdentity(blob))
	cli.SaveCloud(t, sync.URL(), "LOCAL_FIRST_SYNC_TOKEN_CANARY")
	return &localFirstScenario{
		cli: cli, ssh: server, sync: sync, alias: "lf-host", localBlob: blob,
		env: map[string]string{
			"SSM_SYNC_MODE":               "local_first",
			"SSM_COMPILED_TEST_CLOCK_URL": sync.ClockURL(),
		},
	}
}

func (s *localFirstScenario) run(t *testing.T, args ...string) compiledCLIResult {
	t.Helper()
	return s.cli.RunWithEnv(t, "sshctl", nil, s.env, args...)
}

func (s *localFirstScenario) runWith(t *testing.T, extra map[string]string, args ...string) compiledCLIResult {
	t.Helper()
	env := map[string]string{}
	for key, value := range s.env {
		env[key] = value
	}
	for key, value := range extra {
		env[key] = value
	}
	return s.cli.RunWithEnv(t, "sshctl", nil, env, args...)
}

// runTrue runs the fast one-shot command and asserts it succeeded quickly.
func (s *localFirstScenario) runTrue(t *testing.T) map[string]any {
	t.Helper()
	started := time.Now()
	result := s.run(t, "--json", "run", s.alias, "--argv", "true")
	elapsed := time.Since(started)
	if result.ProcessExit != 0 {
		t.Fatalf("run failed while sync was unavailable; output=%s", compiledOutputIdentity(result))
	}
	value := decodeExactlyOneJSONObject(t, result.Stdout)
	if ok, _ := value["ok"].(bool); !ok {
		t.Fatalf("run result is not ok; output=%s", compiledOutputIdentity(result))
	}
	if elapsed >= localFirstFastRun {
		t.Fatalf("run took %s with sync unavailable, want < %s", elapsed, localFirstFastRun)
	}
	return value
}

func (s *localFirstScenario) syncRequests() int {
	return s.sync.MethodCount(http.MethodHead) + s.sync.MethodCount(http.MethodGet) + s.sync.MethodCount(http.MethodPut)
}

func (s *localFirstScenario) syncStatePath() string {
	return filepath.Join(s.cli.home, ".config", "ssm", "sync-state.json")
}

func (s *localFirstScenario) writeSyncState(t *testing.T, state map[string]any) {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	s.cli.writeConfigFile(t, "sync-state.json", data)
}

func (s *localFirstScenario) readSyncState(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(s.syncStatePath())
	if err != nil {
		return nil
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}
	return state
}

// waitForSyncState polls until the detached background process has recorded a
// state satisfying ready, then waits for that process to exit so TempDir
// cleanup cannot race a running executable.
func (s *localFirstScenario) waitForSyncState(t *testing.T, ready func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if state := s.readSyncState(t); state != nil && ready(state) {
			s.waitForBackgroundExit(t)
			return state
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("background sync did not record the expected state; last=%v", s.readSyncState(t))
	return nil
}

// waitForBackgroundExit returns once no compiled test executable is being
// executed: opening a running executable for writing fails on Windows and
// Linux until the process exits.
func (s *localFirstScenario) waitForBackgroundExit(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for _, path := range s.cli.paths {
		for {
			file, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // harness-owned copy of the compiled CLI
			if err == nil {
				_ = file.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("background sync process is still running: %v", err)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	// A process that has not yet been observed running is not distinguishable
	// from one that has exited; the state file is written last, so a short
	// settle covers process teardown on platforms without exec-file locking.
	time.Sleep(150 * time.Millisecond)
}

func (s *localFirstScenario) assertNoBackgroundActivity(t *testing.T, before map[string]any) {
	t.Helper()
	time.Sleep(400 * time.Millisecond)
	after := s.readSyncState(t)
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatalf("sync state changed although no background sync was due: before=%s after=%s", beforeJSON, afterJSON)
	}
}

func stateString(state map[string]any, key string) string {
	value, _ := state[key].(string)
	return value
}

func stateFailures(state map[string]any) float64 {
	value, _ := state["consecutive_failures"].(float64)
	return value
}

func stateError(state map[string]any) map[string]any {
	value, _ := state["last_error"].(map[string]any)
	return value
}

func rfc3339(at time.Time) string { return at.UTC().Format(time.RFC3339) }

func TestLocalFirstReadIsIndependentOfSyncEndpointInBackoff(t *testing.T) {
	const token = "LOCAL_FIRST_SYNC_TOKEN_CANARY" //nolint:gosec // test-only fake credential canary
	cases := []struct {
		name      string
		configure func(t *testing.T, s *localFirstScenario)
	}{
		{"connection refused", func(t *testing.T, s *localFirstScenario) {
			refused := newCompiledRefusedTCPPort(t)
			s.cli.SaveCloud(t, "http://"+net.JoinHostPort(refused.host, strconv.Itoa(refused.port)), token)
		}},
		{"service unavailable", func(t *testing.T, s *localFirstScenario) {
			s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)
		}},
		{"unauthorized", func(t *testing.T, s *localFirstScenario) {
			s.sync.SetStatus(t, http.MethodHead, http.StatusUnauthorized)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			s := newLocalFirstScenario(t)
			test.configure(t, s)
			s.writeSyncState(t, map[string]any{
				"consecutive_failures": 3,
				"next_attempt_at":      rfc3339(localFirstClock.Add(30 * time.Minute)),
				"last_error":           map[string]any{"cause": "http_5xx", "message": "server error (503)", "at": rfc3339(localFirstClock)},
			})
			before := s.readSyncState(t)
			s.runTrue(t)
			if got := s.syncRequests(); got != 0 {
				t.Fatalf("foreground/background sync requests = %d during backoff, want 0", got)
			}
			s.assertNoBackgroundActivity(t, before)
		})
	}
}

func TestLocalFirstHungEndpointNeverDelaysTheCommand(t *testing.T) {
	s := newLocalFirstScenario(t)
	release := make(chan struct{})
	var once sync.Once
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sync" {
			<-release
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	s.cli.SaveCloud(t, hung.URL, "LOCAL_FIRST_SYNC_TOKEN_CANARY")

	s.runTrue(t) // due: spawns the background process, which then blocks on the hung endpoint
	once.Do(func() { close(release) })
	state := s.waitForSyncState(t, func(state map[string]any) bool { return stateError(state) != nil })
	if got := stateError(state)["cause"]; got != "http_5xx" {
		t.Fatalf("hung endpoint cause = %v, want http_5xx", got)
	}
}

func TestLocalFirstDueSyncFailureIsRecordedInTheBackgroundWithBackoff(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)

	s.runTrue(t)
	state := s.waitForSyncState(t, func(state map[string]any) bool { return stateError(state) != nil })
	failure := stateError(state)
	if failure["cause"] != "http_5xx" || stateString(failure, "message") == "" || stateString(failure, "at") != rfc3339(localFirstClock) {
		t.Fatalf("last_error = %v, want cause http_5xx with message and at=%s", failure, rfc3339(localFirstClock))
	}
	serverAddress := strings.TrimPrefix(s.sync.URL(), "http://")
	if strings.Contains(stateString(failure, "message"), serverAddress) || strings.Contains(stateString(failure, "message"), "127.0.0.1") {
		t.Fatalf("last_error.message exposes the sync server address: %v", failure["message"])
	}
	if stateFailures(state) != 1 ||
		stateString(state, "next_attempt_at") != rfc3339(localFirstClock.Add(30*time.Second)) {
		t.Fatalf("failure count/backoff = %v/%v, want 1 and +30s", state["consecutive_failures"], state["next_attempt_at"])
	}
	if got := s.sync.MethodCount(http.MethodHead); got != 1 {
		t.Fatalf("HEAD requests after first due command = %d, want exactly 1 from the background process", got)
	}

	// Inside the backoff window no command retries.
	s.runTrue(t)
	time.Sleep(400 * time.Millisecond)
	if got := s.sync.MethodCount(http.MethodHead); got != 1 {
		t.Fatalf("HEAD requests during backoff = %d, want still 1", got)
	}
}

func TestLocalFirstBackoffGrowsExponentiallyAndIsCapped(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)
	for failures, want := range map[int]time.Duration{1: 30 * time.Second, 2: time.Minute, 5: 8 * time.Minute, 12: time.Hour} {
		s.writeSyncState(t, map[string]any{
			"consecutive_failures": failures - 1,
			"next_attempt_at":      rfc3339(localFirstClock.Add(-time.Second)),
		})
		s.runTrue(t)
		state := s.waitForSyncState(t, func(state map[string]any) bool {
			return stateFailures(state) == float64(failures)
		})
		if got := stateString(state, "next_attempt_at"); got != rfc3339(localFirstClock.Add(want)) {
			t.Fatalf("after %d failures next_attempt_at = %s, want +%s", failures, got, want)
		}
	}
}

func TestLocalFirstHealthyEndpointIsRateLimitedBySyncInterval(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.writeSyncState(t, map[string]any{
		"last_success_at": rfc3339(localFirstClock.Add(-time.Minute)),
		"next_attempt_at": rfc3339(localFirstClock.Add(9 * time.Minute)),
	})
	before := s.readSyncState(t)
	s.runTrue(t)
	if got := s.syncRequests(); got != 0 {
		t.Fatalf("sync requests inside sync_interval = %d, want 0", got)
	}
	s.assertNoBackgroundActivity(t, before)
}

func TestLocalFirstDueHealthySyncChecksOnceAndSchedulesNextAttempt(t *testing.T) {
	for _, test := range []struct {
		name     string
		settings string
		next     time.Duration
	}{
		{"default interval", "", 10 * time.Minute},
		{"configured interval", `{"sync_interval":"1h"}`, time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newLocalFirstScenario(t)
			if test.settings != "" {
				s.cli.writeConfigFile(t, "settings.json", []byte(test.settings))
			}
			s.writeSyncState(t, map[string]any{
				"consecutive_failures": 2,
				"next_attempt_at":      rfc3339(localFirstClock.Add(-time.Second)),
				"last_error":           map[string]any{"cause": "network", "message": "x", "at": rfc3339(localFirstClock.Add(-time.Hour))},
			})
			s.runTrue(t)
			state := s.waitForSyncState(t, func(state map[string]any) bool { return stateString(state, "last_success_at") != "" })
			if stateString(state, "last_success_at") != rfc3339(localFirstClock) ||
				stateString(state, "next_attempt_at") != rfc3339(localFirstClock.Add(test.next)) ||
				stateFailures(state) != 0 || stateError(state) != nil {
				t.Fatalf("success state = %v, want success now, next +%s, no failures or error", state, test.next)
			}
			if head, get, put := s.sync.MethodCount(http.MethodHead), s.sync.MethodCount(http.MethodGet), s.sync.MethodCount(http.MethodPut); head != 1 || get != 0 || put != 0 {
				t.Fatalf("requests HEAD/GET/PUT = %d/%d/%d, want 1/0/0 (pull only on change, never push)", head, get, put)
			}
		})
	}
}

func TestLocalFirstBackgroundPullsOnlyWhenRemoteChanged(t *testing.T) {
	s := newLocalFirstScenario(t)
	remoteVault := &config.Vault{Connections: []config.Connection{
		s.ssh.Connection("lf-host", "LOCAL_FIRST_SSH_PASSWORD_CANARY"), //nolint:gosec // test-only fake credential canary
		{Name: "pulled-in-background", Host: "192.0.2.90", Port: 22, User: "root", Password: "unused"},
	}}
	remoteBlob := encryptCompiledVault(t, s.cli, remoteVault)
	s.sync.SetRemote(t, remoteBlob, compiledOpaqueIdentity(remoteBlob))

	s.runTrue(t) // answers from the old local inventory, then starts the pull
	s.waitForSyncState(t, func(state map[string]any) bool { return stateString(state, "last_success_at") != "" })
	if !bytes.Equal(s.cli.VaultBlob(t), remoteBlob) {
		t.Fatal("background sync did not pull the changed remote vault")
	}
	listed := s.run(t, "--json", "list")
	if !strings.Contains(listed.Stdout, "pulled-in-background") {
		t.Fatalf("pulled inventory is not used by the next read; output=%s", compiledOutputIdentity(listed))
	}
	if put := s.sync.MethodCount(http.MethodPut); put != 0 {
		t.Fatalf("background sync published %d times, want 0", put)
	}
}

func TestLocalFirstBackgroundNeverOverwritesDivergedLocalState(t *testing.T) {
	s := newLocalFirstScenario(t)
	base := []byte("opaque base identity")
	s.cli.SaveRemoteETag(t, compiledOpaqueIdentity(base)) // cached remote != local: local is ahead
	remote := []byte("opaque changed remote")
	s.sync.SetRemote(t, remote, compiledOpaqueIdentity(remote))
	localBefore := s.cli.VaultBlob(t)

	s.runTrue(t)
	state := s.waitForSyncState(t, func(state map[string]any) bool { return stateError(state) != nil })
	if got := stateError(state)["cause"]; got != "conflict" {
		t.Fatalf("divergence cause = %v, want conflict", got)
	}
	if !bytes.Equal(s.cli.VaultBlob(t), localBefore) {
		t.Fatal("background sync overwrote diverged local vault")
	}
	if _, err := os.Stat(filepath.Join(s.cli.home, ".config", "ssm", "sync-conflict.json")); err != nil {
		t.Fatalf("divergence evidence was not preserved: %v", err)
	}
	if get, put := s.sync.MethodCount(http.MethodGet), s.sync.MethodCount(http.MethodPut); get != 0 || put != 0 {
		t.Fatalf("diverged background sync GET/PUT = %d/%d, want 0/0", get, put)
	}
}

func TestLocalFirstStatusReportsUnreachableWithoutFailing(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.cli.writeConfigFile(t, "settings.json", []byte(`{"last_pull":"`+rfc3339(localFirstClock.Add(-2*time.Hour))+`"}`))
	s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)

	s.runTrue(t)
	s.waitForSyncState(t, func(state map[string]any) bool { return stateError(state) != nil })
	requests := s.syncRequests()

	result := s.run(t, "--json", "status")
	if result.ProcessExit != 0 {
		t.Fatalf("status failed because sync is unreachable; output=%s", compiledOutputIdentity(result))
	}
	value := decodeExactlyOneJSONObject(t, result.Stdout)
	lastError, _ := value["last_sync_error"].(map[string]any)
	if value["ok"] != true || value["remote_state"] != "unreachable" ||
		lastError["cause"] != "http_5xx" || value["cache_age_seconds"] != float64(7200) ||
		stateString(value, "next_sync_attempt") == "" {
		t.Fatalf("status = %v", value)
	}
	if _, present := value["inventory_stale"]; present {
		t.Fatalf("a two hour old cache is not stale by default: %v", value)
	}
	if got := s.syncRequests(); got != requests {
		t.Fatalf("status made %d sync requests, want 0", got-requests)
	}
	human := s.run(t, "status")
	if human.ProcessExit != 0 || !strings.Contains(human.Stdout, "remote_state=unreachable") ||
		!strings.Contains(human.Stdout, "last_sync_error=http_5xx") {
		t.Fatalf("human status = %q", human.Stdout)
	}
}

func TestLocalFirstStatusReportsRemoteStateBeforeAnyCheck(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.writeSyncState(t, map[string]any{"next_attempt_at": rfc3339(localFirstClock.Add(time.Hour))})
	value := decodeExactlyOneJSONObject(t, s.run(t, "--json", "status").Stdout)
	if value["ok"] != true || value["remote_state"] != "not_checked" {
		t.Fatalf("status before any check = %v", value)
	}
	s.writeSyncState(t, map[string]any{
		"last_success_at": rfc3339(localFirstClock.Add(-time.Minute)),
		"next_attempt_at": rfc3339(localFirstClock.Add(time.Hour)),
	})
	value = decodeExactlyOneJSONObject(t, s.run(t, "--json", "status").Stdout)
	if value["remote_state"] != "checked" || value["last_successful_sync"] != rfc3339(localFirstClock.Add(-time.Minute)) {
		t.Fatalf("status after a successful check = %v", value)
	}
	s.cli.writeConfigFile(t, "settings.json", []byte(`{"auto_sync":false}`))
	value = decodeExactlyOneJSONObject(t, s.run(t, "--json", "status").Stdout)
	if value["remote_state"] != "auto_sync_disabled" {
		t.Fatalf("status with auto_sync=false = %v", value)
	}
	if got := s.syncRequests(); got != 0 {
		t.Fatalf("status made %d sync requests", got)
	}
}

func TestLocalFirstAutoSyncDisabledNeverSpawns(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.cli.writeConfigFile(t, "settings.json", []byte(`{"auto_sync":false}`))
	s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)
	s.runTrue(t)
	time.Sleep(400 * time.Millisecond)
	if got := s.syncRequests(); got != 0 || s.readSyncState(t) != nil {
		t.Fatalf("auto_sync=false started sync: requests=%d state=%v", got, s.readSyncState(t))
	}
}

func TestLocalFirstStaleInventoryIsVisibleWithoutBlocking(t *testing.T) {
	s := newLocalFirstScenario(t)
	old := rfc3339(localFirstClock.Add(-10 * 24 * time.Hour))
	s.cli.writeConfigFile(t, "settings.json", []byte(`{"last_pull":"`+old+`"}`))
	s.writeSyncState(t, map[string]any{"next_attempt_at": rfc3339(localFirstClock.Add(time.Hour))})

	run := s.runTrue(t)
	if run["inventory_stale"] != true {
		t.Fatalf("run result lacks inventory_stale=true: %v", run)
	}
	status := decodeExactlyOneJSONObject(t, s.run(t, "--json", "status").Stdout)
	if status["inventory_stale"] != true {
		t.Fatalf("status lacks inventory_stale=true: %v", status)
	}
	human := s.run(t, "list")
	if human.ProcessExit != 0 || !strings.Contains(human.Stderr, "warning: inventory cache is 10 days old") {
		t.Fatalf("human list lacks the stderr staleness warning; stderr=%q", human.Stderr)
	}
	if strings.Contains(human.Stdout, "warning") {
		t.Fatalf("staleness warning polluted stdout: %q", human.Stdout)
	}
	jsonList := s.run(t, "--json", "list")
	if jsonList.Stderr != "" {
		t.Fatalf("--json list wrote to stderr: %q", jsonList.Stderr)
	}

	s.cli.writeConfigFile(t, "settings.json", []byte(`{"last_pull":"`+old+`","stale_after":"30d"}`))
	if run := s.runTrue(t); run["inventory_stale"] != nil {
		t.Fatalf("stale_after=30d must not mark a ten day old cache stale: %v", run)
	}
}

func TestLocalFirstSuccessfulBackgroundCheckRefreshesCacheAge(t *testing.T) {
	s := newLocalFirstScenario(t)
	old := rfc3339(localFirstClock.Add(-10 * 24 * time.Hour))
	s.cli.writeConfigFile(t, "settings.json", []byte(`{"last_pull":"`+old+`"}`))
	s.writeSyncState(t, map[string]any{"next_attempt_at": rfc3339(localFirstClock.Add(-time.Second))})
	s.runTrue(t)
	s.waitForSyncState(t, func(state map[string]any) bool { return stateString(state, "last_success_at") != "" })
	status := decodeExactlyOneJSONObject(t, s.run(t, "--json", "status").Stdout)
	if _, stale := status["inventory_stale"]; stale {
		t.Fatalf("a cache confirmed by a successful check is not stale: %v", status)
	}
	if status["cache_age_seconds"] != nil {
		if age, _ := status["cache_age_seconds"].(float64); age != 0 {
			t.Fatalf("cache_age_seconds = %v, want 0 right after a confirmed check", age)
		}
	}
}

func TestLocalFirstWritesStayPendingWhileTheServiceIsDownAndPublishAfterRecovery(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)
	s.writeSyncState(t, map[string]any{"next_attempt_at": rfc3339(localFirstClock.Add(time.Hour))})
	password := filepath.Join(s.cli.temp, "new-host.password")
	if err := os.WriteFile(password, []byte("LOCAL_FIRST_NEW_HOST_PASSWORD_CANARY\n"), 0o600); err != nil { //nolint:gosec // test-only fake credential canary
		t.Fatal(err)
	}

	added := s.run(t, "--json", "host", "add", "offline-added", "--host", "192.0.2.77", "--user", "runner", "--password-file", password)
	value := assertCompiledJSONSuccess(t, added)
	id := compiledTransactionID(t, value, added)
	status := decodeExactlyOneJSONObject(t, s.run(t, "--json", "status").Stdout)
	if status["ok"] != true || status["pending_changes"] != true {
		t.Fatalf("local write is not pending while the service is down: %v", status)
	}
	if got := s.syncRequests(); got != 0 {
		t.Fatalf("local write made %d sync requests while backed off", got)
	}

	failed := s.run(t, "--json", "push", "--only", id)
	if failed.ProcessExit == 0 {
		t.Fatal("explicit push succeeded against an unavailable service")
	}
	state := s.readSyncState(t)
	if got := stateError(state); got == nil || got["cause"] != "http_5xx" {
		t.Fatalf("explicit push failure was not recorded: %v", state)
	}

	s.sync.SetStatus(t, http.MethodHead, http.StatusOK)
	published := s.run(t, "--json", "push", "--only", id)
	if published.ProcessExit != 0 {
		t.Fatalf("push after recovery failed; output=%s", compiledOutputIdentity(published))
	}
	if len(s.sync.UploadedBlob()) == 0 {
		t.Fatal("recovered push did not upload the vault")
	}
	state = s.readSyncState(t)
	if stateString(state, "last_success_at") != rfc3339(localFirstClock) || stateError(state) != nil {
		t.Fatalf("successful push was not recorded: %v", state)
	}
}

func TestLocalFirstExplicitSyncKeepsStrictSemanticsAndRecordsOutcome(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)
	failed := s.run(t, "--json", "sync")
	failure := decodeExactlyOneJSONObject(t, failed.Stdout)
	if failed.ProcessExit != 1 || failure["ok"] != false || failure["cause"] != "http_5xx" {
		t.Fatalf("explicit sync must fail strictly with its cause; output=%s", compiledOutputIdentity(failed))
	}
	if got := stateError(s.readSyncState(t)); got == nil || got["cause"] != "http_5xx" {
		t.Fatalf("explicit sync failure not recorded: %v", s.readSyncState(t))
	}

	s.sync.SetStatus(t, http.MethodHead, http.StatusOK)
	ok := s.run(t, "--json", "sync")
	if ok.ProcessExit != 0 {
		t.Fatalf("explicit sync failed against a healthy service; output=%s", compiledOutputIdentity(ok))
	}
	state := s.readSyncState(t)
	if stateString(state, "last_success_at") != rfc3339(localFirstClock) || stateError(state) != nil ||
		stateFailures(state) != 0 {
		t.Fatalf("explicit sync success not recorded: %v", state)
	}
}

func TestSyncModeStrictReproducesRefreshBeforeRead(t *testing.T) {
	for _, test := range []struct {
		name     string
		settings string
		env      string
	}{
		{"settings.json", `{"sync_mode":"strict"}`, ""},
		{"environment overrides settings", `{"sync_mode":"local_first"}`, "strict"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newLocalFirstScenario(t)
			s.cli.writeConfigFile(t, "settings.json", []byte(test.settings))
			s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)
			result := s.runWith(t, map[string]string{"SSM_SYNC_MODE": test.env}, "--json", "run", s.alias, "--argv", "true")
			assertCompiledMachineContract(t, result, compiledMachineContract{
				OK: false, Error: "sync_pull_failed", Stage: "sync_pull", JSONExit: 1, ProcessExit: 1,
				Cause: "http_5xx", Hint: "sync server returned a 5xx error; retry later or retry explicitly with --offline",
			})
			if got := s.sync.MethodCount(http.MethodHead); got != 1 {
				t.Fatalf("strict mode HEAD requests = %d, want 1 in the foreground", got)
			}
			if s.readSyncState(t) != nil {
				t.Fatalf("strict mode wrote sync-state.json: %v", s.readSyncState(t))
			}
		})
	}
}

func TestSyncModeDefaultsToLocalFirstWhenSettingsAreAbsentOrUnrecognized(t *testing.T) {
	for _, settings := range []string{"", `{}`, `{"sync_mode":"bogus"}`} {
		s := newLocalFirstScenario(t)
		if settings != "" {
			s.cli.writeConfigFile(t, "settings.json", []byte(settings))
		}
		s.writeSyncState(t, map[string]any{"next_attempt_at": rfc3339(localFirstClock.Add(time.Hour))})
		s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)
		s.runWith(t, map[string]string{"SSM_SYNC_MODE": ""}, "--json", "run", s.alias, "--argv", "true")
		if got := s.syncRequests(); got != 0 {
			t.Fatalf("settings %q: default mode made %d sync requests, want local_first", settings, got)
		}
	}
}

func TestLocalFirstOfflineFlagAndEnvironmentNeverSpawnBackgroundSync(t *testing.T) {
	for _, test := range []struct {
		name string
		env  map[string]string
		args []string
	}{
		{"--offline", nil, []string{"--offline", "--json", "run", "lf-host", "--argv", "true"}},
		{"SSM_OFFLINE=1", map[string]string{"SSM_OFFLINE": "1"}, []string{"--json", "run", "lf-host", "--argv", "true"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newLocalFirstScenario(t)
			s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)
			result := s.runWith(t, test.env, test.args...)
			if result.ProcessExit != 0 {
				t.Fatalf("offline run failed; output=%s", compiledOutputIdentity(result))
			}
			time.Sleep(400 * time.Millisecond)
			if got := s.syncRequests(); got != 0 || s.readSyncState(t) != nil {
				t.Fatalf("offline command started background sync: requests=%d state=%v", got, s.readSyncState(t))
			}
		})
	}
	t.Run("SSM_OFFLINE=1 is reported by status", func(t *testing.T) {
		s := newLocalFirstScenario(t)
		value := decodeExactlyOneJSONObject(t, s.runWith(t, map[string]string{"SSM_OFFLINE": "1"}, "--json", "status").Stdout)
		if value["offline"] != true || value["remote_state"] != "not_checked" {
			t.Fatalf("status = %v", value)
		}
	})
}

func TestLocalFirstStreamIsNotStoppedBySyncFailures(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)
	s.writeSyncState(t, map[string]any{"next_attempt_at": rfc3339(localFirstClock.Add(time.Hour))})
	result := s.cli.RunWithEnv(t, "sshctl", []byte("[\"true\"]\n[\"true\"]\n"), s.env,
		"--json", "run", s.alias, "--stream", "--refresh=30s")
	lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
	if result.ProcessExit != 0 || len(lines) != 2 {
		t.Fatalf("stream did not survive an unreachable sync service; output=%s", compiledOutputIdentity(result))
	}
	for _, line := range lines {
		var value map[string]any
		if err := json.Unmarshal([]byte(line), &value); err != nil || value["ok"] != true {
			t.Fatalf("stream line is not a successful run result: %q", line)
		}
	}
	if got := s.syncRequests(); got != 0 {
		t.Fatalf("stream made %d sync requests during backoff", got)
	}
}

func TestInvalidSyncModeIsReportedOnceAndRunsAsLocalFirst(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.cli.writeConfigFile(t, "settings.json", []byte(`{"sync_mode":"strikt"}`))
	s.writeSyncState(t, map[string]any{"next_attempt_at": rfc3339(localFirstClock.Add(time.Hour))})
	s.sync.SetStatus(t, http.MethodHead, http.StatusServiceUnavailable)
	noEnv := map[string]string{"SSM_SYNC_MODE": ""}
	const want = `ssm: warning: invalid settings.json sync_mode "strikt" (want local_first or strict); using local_first`

	human := s.runWith(t, noEnv, "list")
	if human.ProcessExit != 0 || strings.Count(human.Stderr, want) != 1 || strings.Contains(human.Stdout, "warning") {
		t.Fatalf("human read did not report the invalid mode exactly once on stderr; stderr=%q", human.Stderr)
	}
	status := s.runWith(t, noEnv, "--json", "status")
	if status.ProcessExit != 0 || strings.Count(status.Stderr, want) != 1 {
		t.Fatalf("status did not report the invalid mode; stderr=%q", status.Stderr)
	}
	decodeExactlyOneJSONObject(t, status.Stdout)
	if jsonRead := s.runWith(t, noEnv, "--json", "list"); jsonRead.Stderr != "" {
		t.Fatalf("--json read wrote to stderr: %q", jsonRead.Stderr)
	}
	if got := s.syncRequests(); got != 0 {
		t.Fatalf("invalid mode did not run as local_first: %d sync requests", got)
	}
}

func TestLocalFirstReportsAnInventoryThatWasNeverSynced(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.writeSyncState(t, map[string]any{"next_attempt_at": rfc3339(localFirstClock.Add(time.Hour))})
	const want = "ssm: warning: inventory has not been synced yet; run sshctl sync to pull the remote vault"

	human := s.run(t, "list")
	if human.ProcessExit != 0 || strings.Count(human.Stderr, want) != 1 || strings.Contains(human.Stdout, "warning") {
		t.Fatalf("human read did not report the unsynced inventory once on stderr; stderr=%q", human.Stderr)
	}
	if jsonRead := s.run(t, "--json", "list"); jsonRead.Stderr != "" {
		t.Fatalf("--json read wrote to stderr: %q", jsonRead.Stderr)
	}
	status := decodeExactlyOneJSONObject(t, s.run(t, "--json", "status").Stdout)
	if status["inventory_unsynced"] != true {
		t.Fatalf("status lacks inventory_unsynced=true: %v", status)
	}

	s.writeSyncState(t, map[string]any{
		"last_success_at": rfc3339(localFirstClock.Add(-time.Minute)),
		"next_attempt_at": rfc3339(localFirstClock.Add(time.Hour)),
	})
	if again := s.run(t, "list"); strings.Contains(again.Stderr, "has not been synced") {
		t.Fatalf("a confirmed sync must clear the warning; stderr=%q", again.Stderr)
	}
	if status := decodeExactlyOneJSONObject(t, s.run(t, "--json", "status").Stdout); status["inventory_unsynced"] != nil {
		t.Fatalf("status still reports inventory_unsynced: %v", status)
	}
}

// Run results carry the never-synced and last-failure facts as additive JSON
// fields; human mode stays quiet about a failed attempt (offline use).
func TestLocalFirstRunResultsCarryUnsyncedAndLastSyncFailure(t *testing.T) {
	s := newLocalFirstScenario(t)
	s.writeSyncState(t, map[string]any{
		"consecutive_failures": 2,
		"next_attempt_at":      rfc3339(localFirstClock.Add(time.Hour)),
		"last_error":           map[string]any{"cause": "http_5xx", "message": "sync server returned an error (HTTP 503)", "at": rfc3339(localFirstClock)},
	})
	run := s.runTrue(t)
	if run["inventory_unsynced"] != true || run["inventory_sync_error"] != "http_5xx" {
		t.Fatalf("run result lacks the additive sync visibility fields: %v", run)
	}
	human := s.run(t, "run", s.alias, "--argv", "true")
	if human.ProcessExit != 0 || strings.Contains(human.Stderr, "http_5xx") || strings.Contains(human.Stderr, "sync failed") ||
		strings.Contains(human.Stderr, "unreachable") {
		t.Fatalf("human run must stay quiet about a failed sync attempt; stderr=%q", human.Stderr)
	}

	s.writeSyncState(t, map[string]any{
		"last_success_at": rfc3339(localFirstClock.Add(-time.Minute)),
		"next_attempt_at": rfc3339(localFirstClock.Add(time.Hour)),
	})
	clean := s.runTrue(t)
	if clean["inventory_unsynced"] != nil || clean["inventory_sync_error"] != nil {
		t.Fatalf("a confirmed sync must clear the fields: %v", clean)
	}
}
