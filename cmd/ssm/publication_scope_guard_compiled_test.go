package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"ssm/internal/config"
)

const scopeGuardHint = "local vault remains pending; fix sync, then retry with sshctl --json push --only <transaction-id> or, after reviewing all pending transactions, sshctl --json push --all"

func newTwoPublicationScenario(t *testing.T, label string) (*compiledCLIHarness, *publicationSyncFixture, *config.Vault) {
	t.Helper()
	alpha := config.Connection{Name: "alpha", Host: "alpha.example", Port: 22, User: "root", Password: "SCOPE_GUARD_ALPHA_" + strings.ToUpper(label)}
	bravo := config.Connection{Name: "bravo", Host: "bravo.example", Port: 22, User: "root", Password: "SCOPE_GUARD_BRAVO_" + strings.ToUpper(label)}
	original := &config.Vault{
		Connections: []config.Connection{alpha, bravo}, PendingBase: &config.InventorySnapshot{},
		PendingMutations: []config.PendingMutation{
			{ID: "tx_scope_alpha_0000000000000000000000000001", Alias: alpha.Name, Operation: "created", CreatedAt: "2026-07-29T00:00:01Z", After: &alpha},
			{ID: "tx_scope_bravo_0000000000000000000000000002", Alias: bravo.Name, Operation: "created", CreatedAt: "2026-07-29T00:00:02Z", After: &bravo},
		},
	}
	cli := newCompiledCLIHarness(t)
	cli.SaveVault(t, original)
	sync := newPublicationSyncFixture(t)
	prerequisite := encryptCompiledVault(t, cli, &config.Vault{})
	sync.setRemote(prerequisite)
	cli.SaveRemoteETag(t, compiledOpaqueIdentity(prerequisite))
	cli.SaveCloud(t, sync.server.URL, "SCOPE_GUARD_TOKEN_"+strings.ToUpper(label))
	return cli, sync, original
}

func assertScopeGuardFailure(t *testing.T, result compiledCLIResult, message string) {
	t.Helper()
	if result.ProcessExit != 1 || result.Stderr != "" {
		t.Fatalf("scope guard failure process contract: %s", compiledOutputIdentity(result))
	}
	value := decodeExactlyOneJSONObject(t, result.Stdout)
	wantMessage := "interrupted publication was returned to pending; requested push scope did not match it and was not published; review status and retry"
	if message == "finalized" {
		wantMessage = "interrupted publication was finalized; requested push scope did not match it and was not published; review status and retry"
	}
	want := map[string]any{"ok": false, "error": "sync_push_failed", "exit": float64(1), "hint": scopeGuardHint, "message": wantMessage}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("scope guard failure JSON = %v, want %v", value, want)
	}
}

func runScopeGuardRejection(t *testing.T, cli *compiledCLIHarness, sync *publicationSyncFixture, only, message string, headDelta int, unchangedVault bool) {
	t.Helper()
	before := cli.VaultBlob(t)
	putsBefore, headsBefore := sync.putCount(), sync.headCount()
	if _, exists := scopeIntentBytes(t, cli); !exists {
		t.Fatal("recovery intent is missing before rejection")
	}
	args := []string{"--json", "push", "--all"}
	if only != "" {
		args = []string{"--json", "push", "--only", only}
	}
	assertScopeGuardFailure(t, cli.Run(t, "sshctl", nil, args...), message)
	if sync.putCount() != putsBefore || sync.headCount() != headsBefore+headDelta {
		t.Fatalf("rejection transport delta: PUT=%d HEAD=%d, want PUT=0 HEAD=%d", sync.putCount()-putsBefore, sync.headCount()-headsBefore, headDelta)
	}
	if _, exists := scopeIntentBytes(t, cli); exists {
		t.Fatal("reconciled intent still exists after rejection")
	}
	if unchangedVault && !bytes.Equal(before, cli.VaultBlob(t)) {
		t.Fatal("scope rejection rewrote the encrypted pending ledger")
	}
}

func pendingScopeIDs(t *testing.T, cli *compiledCLIHarness) []string {
	t.Helper()
	result := cli.Run(t, "sshctl", nil, "--offline", "--json", "status")
	value := assertCompiledJSONSuccess(t, result)
	items, ok := value["pending_mutations"].([]any)
	if !ok {
		t.Fatalf("pending_mutations = %T", value["pending_mutations"])
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		mutation := item.(map[string]any)
		ids = append(ids, mutation["id"].(string))
	}
	sort.Strings(ids)
	return ids
}

func scopeIntentBytes(t *testing.T, cli *compiledCLIHarness) ([]byte, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")) //nolint:gosec // test-owned temporary home
	if os.IsNotExist(err) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("read publishing intent: %v", err)
	}
	return data, true
}

func TestPublicationScopeGuardRejectsMismatchedPendingRecovery(t *testing.T) {
	cli, sync, original := newTwoPublicationScenario(t, "pending")
	crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist"}, "--json", "push", "--all")
	if crashed.ProcessExit != 86 || sync.putCount() != 0 {
		t.Fatalf("failed to create ready all intent: %s", compiledOutputIdentity(crashed))
	}
	before := pendingScopeIDs(t, cli)
	runScopeGuardRejection(t, cli, sync, original.PendingMutations[0].ID, "returned to pending", 1, true)
	if sync.putCount() != 0 || !reflectDeepEqualStrings(pendingScopeIDs(t, cli), before) {
		t.Fatalf("mismatched pending recovery changed publication state")
	}
	if _, ok := scopeIntentBytes(t, cli); ok {
		t.Fatal("pending recovery intent was not cleared by reconcile")
	}
	retry := cli.Run(t, "sshctl", nil, "--json", "push", "--only", original.PendingMutations[0].ID)
	value := assertCompiledJSONSuccess(t, retry)
	assertCompiledSinglePreflightID(t, value, original.PendingMutations[0].ID)
	if sync.putCount() != 1 {
		t.Fatalf("matching retry PUT count = %d, want 1", sync.putCount())
	}
	if ids := pendingScopeIDs(t, cli); len(ids) != 1 || ids[0] != original.PendingMutations[1].ID {
		t.Fatalf("only alpha retry left pending IDs = %v", ids)
	}
}

func TestPublicationScopeGuardMatchesSingleAllIntentForOnlyRetry(t *testing.T) {
	const transactionID = "tx_scope_single_0000000000000000000000000003"
	cli, sync, _ := newSinglePublicationScenario(t, transactionID, "single-all-match")
	crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist"}, "--json", "push", "--all")
	if crashed.ProcessExit != 86 || sync.putCount() != 0 {
		t.Fatalf("failed to create single all intent: %s", compiledOutputIdentity(crashed))
	}
	retry := cli.Run(t, "sshctl", nil, "--json", "push", "--only", transactionID)
	value := assertCompiledJSONSuccess(t, retry)
	assertCompiledSinglePreflightID(t, value, transactionID)
	if value["scope"] != "only" || value["transaction_id"] != transactionID {
		t.Fatalf("single all intent only retry receipt = %v", value)
	}
	if sync.putCount() != 1 {
		t.Fatalf("single all intent only retry PUT count = %d, want 1", sync.putCount())
	}
}

func TestPublicationScopeGuardRejectsPendingScopeReplacementAndExpansion(t *testing.T) {
	t.Run("only to other only", func(t *testing.T) {
		cli, sync, original := newTwoPublicationScenario(t, "replacement")
		crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist"}, "--json", "push", "--only", original.PendingMutations[0].ID)
		if crashed.ProcessExit != 86 {
			t.Fatalf("failed to create only intent: %s", compiledOutputIdentity(crashed))
		}
		runScopeGuardRejection(t, cli, sync, original.PendingMutations[1].ID, "returned to pending", 1, true)
		if sync.putCount() != 0 {
			t.Fatalf("replacement mismatch PUT count = %d", sync.putCount())
		}
		retry := cli.Run(t, "sshctl", nil, "--json", "push", "--only", original.PendingMutations[1].ID)
		value := assertCompiledJSONSuccess(t, retry)
		assertCompiledSinglePreflightID(t, value, original.PendingMutations[1].ID)
		if ids := pendingScopeIDs(t, cli); len(ids) != 1 || ids[0] != original.PendingMutations[0].ID {
			t.Fatalf("replacement retry left pending IDs = %v", ids)
		}
	})

	t.Run("only to all", func(t *testing.T) {
		cli, sync, original := newTwoPublicationScenario(t, "expansion")
		crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist"}, "--json", "push", "--only", original.PendingMutations[0].ID)
		if crashed.ProcessExit != 86 {
			t.Fatalf("failed to create only intent: %s", compiledOutputIdentity(crashed))
		}
		runScopeGuardRejection(t, cli, sync, "", "returned to pending", 1, true)
		if sync.putCount() != 0 {
			t.Fatalf("expansion mismatch PUT count = %d", sync.putCount())
		}
		retry := cli.Run(t, "sshctl", nil, "--json", "push", "--all")
		value := assertCompiledJSONSuccess(t, retry)
		preflight, ok := value["preflight"].([]any)
		if !ok || len(preflight) != 2 {
			t.Fatalf("all retry preflight = %v, want two transactions", value["preflight"])
		}
		if sync.putCount() != 1 || len(pendingScopeIDs(t, cli)) != 0 {
			t.Fatal("all retry did not publish both pending transactions exactly once")
		}
	})
}

func TestPublicationScopeGuardRejectsUnknownPendingScope(t *testing.T) {
	cli, sync, _ := newTwoPublicationScenario(t, "unknown")
	crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist"}, "--json", "push", "--all")
	if crashed.ProcessExit != 86 {
		t.Fatalf("failed to create all intent: %s", compiledOutputIdentity(crashed))
	}
	runScopeGuardRejection(t, cli, sync, "tx_scope_unknown_0000000000000000000000000009", "returned to pending", 1, true)
	if sync.putCount() != 0 {
		t.Fatalf("unknown scope mismatch PUT count = %d", sync.putCount())
	}
}

func TestPublicationScopeGuardRejectsPreparedMismatch(t *testing.T) {
	cli, sync, original := newTwoPublicationScenario(t, "prepared")
	crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_intent_persist"}, "--json", "push", "--only", original.PendingMutations[0].ID)
	if crashed.ProcessExit != 86 {
		t.Fatalf("failed to create prepared intent: %s", compiledOutputIdentity(crashed))
	}
	runScopeGuardRejection(t, cli, sync, original.PendingMutations[1].ID, "returned to pending", 0, true)
	if sync.putCount() != 0 {
		t.Fatalf("prepared mismatch PUT count = %d", sync.putCount())
	}
}

func TestPublicationScopeGuardRejectsMismatchedConfirmedRecovery(t *testing.T) {
	cli, sync, original := newTwoPublicationScenario(t, "confirmed")
	sync.dropNextResponse()
	lost := cli.Run(t, "sshctl", nil, "--json", "push", "--only", original.PendingMutations[0].ID)
	if lost.ProcessExit == 0 || sync.putCount() != 1 {
		t.Fatalf("failed to create confirmed recovery: %s", compiledOutputIdentity(lost))
	}
	runScopeGuardRejection(t, cli, sync, original.PendingMutations[1].ID, "finalized", 1, false)
	if sync.putCount() != 1 {
		t.Fatalf("confirmed mismatch repeated PUT: %d", sync.putCount())
	}
	if got := pendingScopeIDs(t, cli); len(got) != 1 || got[0] != original.PendingMutations[1].ID {
		t.Fatalf("confirmed mismatch pending IDs = %v", got)
	}
	if _, ok := scopeIntentBytes(t, cli); ok {
		t.Fatal("confirmed recovery intent was not cleared")
	}
	retry := assertCompiledJSONSuccess(t, cli.Run(t, "sshctl", nil, "--json", "push", "--only", original.PendingMutations[1].ID))
	assertCompiledSinglePreflightID(t, retry, original.PendingMutations[1].ID)
	if sync.putCount() != 2 || len(pendingScopeIDs(t, cli)) != 0 {
		t.Fatal("confirmed recovery retry did not publish bravo exactly once")
	}
}

func TestPublicationScopeGuardRejectsConfirmedFinalizationWindow(t *testing.T) {
	for _, name := range []string{"first recovery", "identical recovery repeated"} {
		t.Run(name, testPublicationScopeGuardConfirmedFinalizationWindow)
	}
}

func testPublicationScopeGuardConfirmedFinalizationWindow(t *testing.T) {
	t.Helper()
	cli, sync, original := newTwoPublicationScenario(t, "finalization-window")
	crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_local_finalization"}, "--json", "push", "--only", original.PendingMutations[0].ID)
	if crashed.ProcessExit != 86 || sync.putCount() != 1 {
		t.Fatalf("failed to create finalization window: %s", compiledOutputIdentity(crashed))
	}
	runScopeGuardRejection(t, cli, sync, original.PendingMutations[1].ID, "finalized", 1, true)
	if sync.putCount() != 1 {
		t.Fatalf("finalization-window mismatch repeated PUT: %d", sync.putCount())
	}
	retry := cli.Run(t, "sshctl", nil, "--json", "push", "--only", original.PendingMutations[1].ID)
	if retry.ProcessExit != 0 {
		t.Fatalf("matching retry after finalization window failed: %s", compiledOutputIdentity(retry))
	}
	assertCompiledSinglePreflightID(t, assertCompiledJSONSuccess(t, retry), original.PendingMutations[1].ID)
	if sync.putCount() != 2 || len(pendingScopeIDs(t, cli)) != 0 {
		t.Fatal("finalization window retry did not publish bravo exactly once")
	}
}

func TestPublicationScopeGuardAllRetryKeepsRecordedSnapshot(t *testing.T) {
	cli, sync, original := newTwoPublicationScenario(t, "snapshot")
	crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist"}, "--json", "push", "--all")
	if crashed.ProcessExit != 86 {
		t.Fatalf("failed to create snapshot recovery: %s", compiledOutputIdentity(crashed))
	}
	gamma := config.Connection{Name: "gamma", Host: "gamma.example", Port: 22, User: "root", Password: "SCOPE_GUARD_SNAPSHOT_GAMMA"} //nolint:gosec // fake credential in an isolated test vault
	original.Connections = append(original.Connections, gamma)
	original.PendingMutations = append(original.PendingMutations, config.PendingMutation{ID: "tx_scope_gamma_0000000000000000000000000003", Alias: "gamma", Operation: "created", CreatedAt: "2026-07-29T00:00:03Z", After: &gamma})
	cli.SaveVault(t, original)
	putsBefore, headsBefore := sync.putCount(), sync.headCount()
	value := assertCompiledJSONSuccess(t, cli.Run(t, "sshctl", nil, "--json", "push", "--all"))
	preflight, ok := value["preflight"].([]any)
	if !ok || len(preflight) != 2 || sync.putCount() != putsBefore+1 || sync.headCount() <= headsBefore {
		t.Fatalf("snapshot retry changed recorded scope: %v", value)
	}
	ids := pendingScopeIDs(t, cli)
	if len(ids) != 1 || ids[0] != original.PendingMutations[2].ID {
		t.Fatalf("snapshot retry pending IDs = %v", ids)
	}
	if _, exists := scopeIntentBytes(t, cli); exists {
		t.Fatal("snapshot retry left its publishing intent")
	}
}

func TestPublicationScopeGuardRejectsHostPushMismatch(t *testing.T) {
	cli, sync, original := newTwoPublicationScenario(t, "host-push")
	crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist"}, "--json", "push", "--all")
	if crashed.ProcessExit != 86 {
		t.Fatalf("failed to create host recovery: %s", compiledOutputIdentity(crashed))
	}
	password := "SCOPE_GUARD_GAMMA_PASSWORD" //nolint:gosec // fake password for a local SSH test fixture
	server := newCompiledSSHFixture(t, compiledSSHFixtureOptions{
		Password: password, RunCommandContains: "hostname; uname -sr",
		RunStdoutFragments: []string{"gamma\nLinux test\n"},
	})
	cli.TrustSSHHost(t, server)
	host, port, err := net.SplitHostPort(server.Address())
	if err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(cli.temp, "gamma.password")
	if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	headsBefore, putsBefore := sync.headCount(), sync.putCount()
	result := cli.Run(t, "sshctl", nil, "--json", "host", "add", "gamma", "--host", host, "--port", port, "--user", "root", "--password-file", passwordPath, "--verify", "--push")
	if result.ProcessExit != 1 {
		t.Fatalf("host recovery verification fixture failed: %s", result.Stdout)
	}
	assertCompiledMachineContract(t, result, compiledMachineContract{
		OK: false, Error: "sync_push_failed", Stage: "sync_push", JSONExit: 1, ProcessExit: 1,
		Hint: "local change remains pending; inspect sshctl --json status and retry with sshctl --json push --only <transaction-id>",
	})
	value := decodeExactlyOneJSONObject(t, result.Stdout)
	if value["applied"] != true || value["pushed"] != false || value["sync_pending"] != true || value["changed"] != true || value["action"] != "created" {
		t.Fatalf("host scope rejection receipt = %v", value)
	}
	wantFields := []string{"ok", "error", "message", "hint", "exit", "stage", "action", "changed", "applied", "pushed", "host", "verification", "sync_pending"}
	if len(value) != len(wantFields) {
		t.Fatalf("host scope rejection JSON fields = %v", value)
	}
	for _, field := range wantFields {
		if _, exists := value[field]; !exists {
			t.Fatalf("host scope rejection omitted %q", field)
		}
	}
	if value["host"].(map[string]any)["name"] != "gamma" || value["verification"].(map[string]any)["ok"] != true {
		t.Fatal("host mismatch lost the verified gamma receipt")
	}
	if sync.putCount() != putsBefore || sync.headCount() != headsBefore+2 {
		t.Fatalf("host mismatch transport delta: PUT=%d HEAD=%d", sync.putCount()-putsBefore, sync.headCount()-headsBefore)
	}
	if _, exists := scopeIntentBytes(t, cli); exists {
		t.Fatal("host mismatch left the reconciled intent")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	local := cli.LoadVaultIdentity(t)
	if len(local.PendingMutations) != 3 {
		t.Fatalf("host mismatch pending mutation count = %d", len(local.PendingMutations))
	}
	if local.PendingMutations[0].ID != original.PendingMutations[0].ID || local.PendingMutations[1].ID != original.PendingMutations[1].ID || local.PendingMutations[2].Alias != "gamma" {
		t.Fatal("host mismatch changed the original pending transactions")
	}
	if len(local.Connections) != 3 || local.Connections[2].Host != host || local.Connections[2].Port != portNumber {
		t.Fatal("host mismatch did not preserve the applied gamma change")
	}
}

func TestPublicationScopeGuardMatchesOnlyIntent(t *testing.T) {
	cli, sync, original := newTwoPublicationScenario(t, "only-match")
	only := original.PendingMutations[0].ID
	crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist"}, "--json", "push", "--only", only)
	if crashed.ProcessExit != 86 {
		t.Fatalf("failed to create only recovery: %s", compiledOutputIdentity(crashed))
	}
	headsBefore := sync.headCount()
	value := assertCompiledJSONSuccess(t, cli.Run(t, "sshctl", nil, "--json", "push", "--only", only))
	assertCompiledSinglePreflightID(t, value, only)
	if value["scope"] != "only" || value["transaction_id"] != only || sync.putCount() != 1 || sync.headCount() <= headsBefore {
		t.Fatalf("same only scope retry receipt = %v", value)
	}
	ids := pendingScopeIDs(t, cli)
	if len(ids) != 1 || ids[0] != original.PendingMutations[1].ID {
		t.Fatalf("same only scope retry pending IDs = %v", ids)
	}
	if _, exists := scopeIntentBytes(t, cli); exists {
		t.Fatal("only scope retry left its publishing intent")
	}
}

func TestPublicationScopeGuardDivergentRemainsFailClosed(t *testing.T) {
	cli, sync, original := newTwoPublicationScenario(t, "divergent-scopes")
	crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist"}, "--json", "push", "--all")
	if crashed.ProcessExit != 86 {
		t.Fatalf("failed to create divergent scenario: %s", compiledOutputIdentity(crashed))
	}
	third := &config.Vault{Connections: []config.Connection{{Name: "third", Host: "third.example", Port: 22, User: "root"}}}
	sync.setRemote(encryptCompiledVault(t, cli, third))
	for _, only := range []string{original.PendingMutations[0].ID, "", "tx_doesnotexist"} {
		t.Run(only, func(t *testing.T) {
			before := cli.VaultBlob(t)
			headsBefore, putsBefore := sync.headCount(), sync.putCount()
			args := []string{"--json", "push", "--all"}
			if only != "" {
				args = []string{"--json", "push", "--only", only}
			}
			result := cli.Run(t, "sshctl", nil, args...)
			assertCompiledMachineContract(t, result, compiledMachineContract{
				OK: false, Error: "sync_conflict", Stage: "sync_compare", JSONExit: 1, ProcessExit: 1,
				Hint: "local and remote blobs were preserved; inspect sshctl --offline --json doctor, then run sshctl --json pull after review",
			})
			if sync.putCount() != putsBefore || sync.headCount() != headsBefore+1 || !bytes.Equal(before, cli.VaultBlob(t)) {
				t.Fatal("divergent recovery changed publication state")
			}
			intent, exists := scopeIntentBytes(t, cli)
			if !exists || decodeExactlyOneJSONObject(t, string(intent))["state"] != "divergent" {
				t.Fatal("divergent recovery evidence was lost")
			}
		})
	}
}

func reflectDeepEqualStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
