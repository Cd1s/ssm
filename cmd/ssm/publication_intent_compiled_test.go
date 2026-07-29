package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"ssm/internal/config"
	"ssm/internal/privatepath"
)

func TestBarePushRequiresExplicitScope(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	sync := newCompiledSyncFixture(t)
	cli.SaveCloud(t, sync.URL(), "ISSUE23_BARE_PUSH_TOKEN_CANARY")
	missingPass := filepath.Join(cli.temp, "missing-master.pass")

	const wantPushFailure = "{\n" +
		"  \"ok\": false,\n" +
		"  \"error\": \"invalid_arguments\",\n" +
		"  \"message\": \"push requires --all or --only \\u003ctransaction-id\\u003e\",\n" +
		"  \"hint\": \"inspect pending_mutations with sshctl --json status\",\n" +
		"  \"exit\": 2\n" +
		"}\n"
	for _, test := range []struct {
		name       string
		executable string
		stdin      []byte
		args       []string
		want       string
	}{
		{
			name: "direct ssm", executable: "ssm",
			args: []string{"--json", "push"}, want: wantPushFailure,
		},
		{
			name: "sshctl compatibility name", executable: "sshctl",
			args: []string{"--json", "push"}, want: wantPushFailure,
		},
		{
			name: "typed request cannot bypass explicit scope", executable: "sshctl",
			stdin: []byte("{\"version\":1,\"op\":\"push\"}\n"),
			args:  []string{"request", "-"},
			want: "{\n" +
				"  \"ok\": false,\n" +
				"  \"error\": \"invalid_request\",\n" +
				"  \"message\": \"unsupported request op \\\"push\\\"\",\n" +
				"  \"hint\": \"use run, plan, check, doctor, put, get, or host.list/search/show/add/update/upsert/remove\",\n" +
				"  \"exit\": 2\n" +
				"}\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := cli.RunWithEnv(t, test.executable, test.stdin, map[string]string{
				"SSM_MASTER_PASS_FILE": missingPass,
			}, test.args...)
			if result.ProcessExit != 2 || result.Stdout != test.want || result.Stderr != "" {
				t.Fatalf("bare push rejection changed; output=%s", compiledOutputIdentity(result))
			}
			decodeExactlyOneJSONObject(t, result.Stdout)
		})
	}
	if got := sync.MethodCount(http.MethodHead); got != 0 {
		t.Fatalf("bare push HEAD count = %d, want 0", got)
	}
	if got := sync.MethodCount(http.MethodGet); got != 0 {
		t.Fatalf("bare push GET count = %d, want 0", got)
	}
	if got := sync.MethodCount(http.MethodPut); got != 0 {
		t.Fatalf("bare push PUT count = %d, want 0", got)
	}
}

func TestConcurrentScopedPublicationsSerializeAcrossProcesses(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	const (
		alphaID = "tx_12121212121212121212121212121212"
		betaID  = "tx_34343434343434343434343434343434"
	)
	alpha := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "alpha", Host: "alpha.example", Port: 22, User: "root",
		Password: "ISSUE23_CONCURRENT_ALPHA_PASSWORD_CANARY",
	}
	beta := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "beta", Host: "beta.example", Port: 22, User: "root",
		Password: "ISSUE23_CONCURRENT_BETA_PASSWORD_CANARY",
	}
	cli.SaveVault(t, &config.Vault{
		Connections: []config.Connection{alpha, beta},
		PendingBase: &config.InventorySnapshot{},
		PendingMutations: []config.PendingMutation{
			{
				ID: alphaID, Alias: alpha.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:10Z", After: &alpha,
			},
			{
				ID: betaID, Alias: beta.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:11Z", After: &beta,
			},
		},
	})
	sync := newPublicationSyncFixture(t)
	prerequisiteBlob := encryptCompiledVault(t, cli, &config.Vault{})
	sync.setRemote(prerequisiteBlob)
	cli.SaveRemoteETag(t, compiledOpaqueIdentity(prerequisiteBlob))
	cli.SaveCloud(t, sync.server.URL, "ISSUE23_CONCURRENT_TOKEN_CANARY")
	releaseFirst := sync.holdFirstBeforeCommit()

	first := startCompiledPublication(t, cli, alphaID)
	waitPublicationEvent(t, sync.requestRead, "first scoped PUT body")
	headCountWhileFirstHeld := sync.headCount()
drainFirstRequests:
	for {
		select {
		case <-sync.nextRequest:
		default:
			break drainFirstRequests
		}
	}

	second := startCompiledPublication(t, cli, betaID)
	secondReachedRemote := false
	select {
	case <-sync.nextRequest:
		secondReachedRemote = true
	case <-time.After(2 * time.Second):
	}
	close(releaseFirst)
	firstResult := waitCompiledPublication(t, first)
	secondResult := waitCompiledPublication(t, second)
	if secondReachedRemote {
		t.Fatal("second scoped publication reached remote transport while the first held publication lock")
	}
	if got := sync.headCount(); got < headCountWhileFirstHeld {
		t.Fatalf("serialized scoped publication HEAD count = %d, want at least %d", got, headCountWhileFirstHeld)
	}
	firstValue := assertCompiledJSONSuccess(t, firstResult)
	secondValue := assertCompiledJSONSuccess(t, secondResult)
	assertCompiledSinglePreflightID(t, firstValue, alphaID)
	assertCompiledSinglePreflightID(t, secondValue, betaID)

	if got := sync.putCount(); got != 2 {
		t.Fatalf("serialized scoped publication PUT count = %d, want 2", got)
	}
	committed := sync.committedBlobs()
	if len(committed) != 2 {
		t.Fatalf("serialized remote commit count = %d, want 2", len(committed))
	}
	assertCompiledEncryptedPublication(t, committed[0], cli.passphrase, nil, &config.Vault{
		Connections: []config.Connection{alpha},
	})
	wantRemote := &config.Vault{Connections: []config.Connection{alpha, beta}}
	assertCompiledEncryptedPublication(t, committed[1], cli.passphrase, nil, wantRemote)
	assertCompiledEncryptedPublication(t, sync.remote(), cli.passphrase, nil, wantRemote)
	assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), wantRemote)

	intentPath := filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")
	if _, err := os.Stat(intentPath); !os.IsNotExist(err) {
		t.Fatalf("serialized publication left or corrupted intent sidecar: %v", err)
	}
	lockPath := filepath.Join(cli.home, ".config", "ssm", "publication.lock")
	if err := privatepath.VerifyFile(lockPath); err != nil {
		t.Fatalf("publication lock path is not private: %v", err)
	}
}

func TestPublicationLockContentionFailsBeforeUnlockOrMutation(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	const (
		alphaID = "tx_56565656565656565656565656565656"
		betaID  = "tx_78787878787878787878787878787878"
	)
	alpha := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "alpha", Host: "alpha.example", Port: 22, User: "root",
		Password: "ISSUE23_BUSY_ALPHA_PASSWORD_CANARY",
	}
	beta := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "beta", Host: "beta.example", Port: 22, User: "root",
		Password: "ISSUE23_BUSY_BETA_PASSWORD_CANARY",
	}
	cli.SaveVault(t, &config.Vault{
		Connections: []config.Connection{alpha, beta},
		PendingBase: &config.InventorySnapshot{},
		PendingMutations: []config.PendingMutation{
			{
				ID: alphaID, Alias: alpha.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:12Z", After: &alpha,
			},
			{
				ID: betaID, Alias: beta.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:13Z", After: &beta,
			},
		},
	})
	sync := newPublicationSyncFixture(t)
	prerequisiteBlob := encryptCompiledVault(t, cli, &config.Vault{})
	sync.setRemote(prerequisiteBlob)
	cli.SaveRemoteETag(t, compiledOpaqueIdentity(prerequisiteBlob))
	cli.SaveCloud(t, sync.server.URL, "ISSUE23_BUSY_TOKEN_CANARY")
	releaseFirst := sync.holdFirstBeforeCommit()

	first := startCompiledPublication(t, cli, alphaID)
	waitPublicationEvent(t, sync.requestRead, "held scoped PUT body")
	intentPath := filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")
	intentBefore, err := os.ReadFile(intentPath) //nolint:gosec // fixed path under test-owned compiled CLI home
	if err != nil {
		t.Fatalf("read held publication intent: %v", err)
	}
	vaultPath := filepath.Join(cli.home, ".config", "ssm", "connections.enc")
	vaultBefore, err := os.ReadFile(vaultPath) //nolint:gosec // fixed path under test-owned compiled CLI home
	if err != nil {
		t.Fatalf("read held publication ledger: %v", err)
	}
	headsBefore, putsBefore := sync.headCount(), sync.putCount()

	busy := cli.RunWithEnv(t, "sshctl", nil, map[string]string{
		"SSM_MASTER_PASS_FILE": filepath.Join(cli.temp, "missing-during-contention.pass"),
	}, "--json", "push", "--only", betaID)
	assertCompiledMachineContract(t, busy, compiledMachineContract{
		OK: false, Error: "sync_push_failed", JSONExit: 1, ProcessExit: 1,
		Hint: "local vault remains pending; fix sync and retry push",
	})
	if !strings.Contains(busy.Stdout, "publication is busy") ||
		strings.Contains(busy.Stdout, "master pass file") {
		t.Fatalf("publication contention did not fail canonically before unlock; output=%s", compiledOutputIdentity(busy))
	}
	if got := sync.headCount(); got != headsBefore {
		t.Fatalf("busy publication HEAD count = %d, want %d", got, headsBefore)
	}
	if got := sync.putCount(); got != putsBefore {
		t.Fatalf("busy publication PUT count = %d, want %d", got, putsBefore)
	}
	intentAfter, err := os.ReadFile(intentPath) //nolint:gosec // fixed path under test-owned compiled CLI home
	if err != nil {
		t.Fatalf("read publication intent after contention: %v", err)
	}
	if !bytes.Equal(intentAfter, intentBefore) {
		t.Fatal("busy publication mutated the held publishing intent")
	}
	vaultAfter, err := os.ReadFile(vaultPath) //nolint:gosec // fixed path under test-owned compiled CLI home
	if err != nil {
		t.Fatalf("read publication ledger after contention: %v", err)
	}
	if !bytes.Equal(vaultAfter, vaultBefore) {
		t.Fatal("busy publication mutated the pending ledger")
	}

	close(releaseFirst)
	firstResult := waitCompiledPublication(t, first)
	firstValue := assertCompiledJSONSuccess(t, firstResult)
	assertCompiledSinglePreflightID(t, firstValue, alphaID)
}

func TestPublicationIntentOmitsSavedKeyNamesAcrossDurableWindows(t *testing.T) {
	const (
		transactionID         = "tx_23232323232323232323232323232323"
		savedKeyNameCanary    = "ISSUE23_SAVED_KEY_NAME_CANARY"
		privateKeyMaterial    = "ISSUE23_SAVED_KEY_PRIVATE_MATERIAL_CANARY"
		savedKeyOperationTime = "2026-07-29T00:00:23Z"
	)
	tests := []struct {
		name      string
		wantState string
		run       func(*testing.T, *compiledCLIHarness, *publicationSyncFixture) compiledCLIResult
	}{
		{
			name: "prepared",
			run: func(t *testing.T, cli *compiledCLIHarness, _ *publicationSyncFixture) compiledCLIResult {
				return cli.RunWithEnv(t, "sshctl", nil, map[string]string{
					"SSM_TEST_PUBLICATION_FAULT": "after_intent_persist",
				}, "--json", "push", "--only", transactionID)
			},
			wantState: "prepared",
		},
		{
			name: "ambiguous",
			run: func(t *testing.T, cli *compiledCLIHarness, sync *publicationSyncFixture) compiledCLIResult {
				sync.dropNextResponse()
				return cli.Run(t, "sshctl", nil, "--json", "push", "--only", transactionID)
			},
			wantState: "ambiguous",
		},
		{
			name: "finalization failed",
			run: func(t *testing.T, cli *compiledCLIHarness, _ *publicationSyncFixture) compiledCLIResult {
				return cli.RunWithEnv(t, "sshctl", nil, map[string]string{
					"SSM_TEST_PUBLICATION_FAULT": "before_local_finalization_error",
				}, "--json", "push", "--only", transactionID)
			},
			wantState: "finalization_failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cli := newCompiledCLIHarness(t)
			savedKey := config.SSHKey{Name: savedKeyNameCanary, PrivateKey: privateKeyMaterial}
			cli.SaveVault(t, &config.Vault{
				PendingBase: &config.InventorySnapshot{Keys: []config.SSHKey{savedKey}},
				PendingMutations: []config.PendingMutation{{
					ID: transactionID, KeyName: savedKeyNameCanary, Operation: "saved_key_removed",
					CreatedAt: savedKeyOperationTime, KeysBefore: []config.SSHKey{savedKey}, KeyCount: 1,
				}},
			})
			sync := newPublicationSyncFixture(t)
			prerequisiteBlob := encryptCompiledVault(t, cli, &config.Vault{Keys: []config.SSHKey{savedKey}})
			sync.setRemote(prerequisiteBlob)
			cli.SaveRemoteETag(t, compiledOpaqueIdentity(prerequisiteBlob))
			cli.SaveCloud(t, sync.server.URL, "ISSUE23_SAVED_KEY_TOKEN_CANARY")

			pendingStatus := assertCompiledJSONSuccess(
				t,
				cli.Run(t, "sshctl", nil, "--offline", "--json", "status"),
			)
			pending, ok := pendingStatus["pending_mutations"].([]any)
			if !ok || len(pending) != 1 {
				t.Fatal("saved-key removal did not remain publicly reviewable")
			}
			pendingView, ok := pending[0].(map[string]any)
			if !ok || pendingView["key_name"] != savedKeyNameCanary ||
				pendingView["operation"] != "saved_key_removed" || pendingView["keys"] != float64(1) {
				t.Fatal("public pending view lost the #24 saved-key diagnostics")
			}

			failed := test.run(t, cli, sync)
			if failed.ProcessExit == 0 {
				t.Fatalf("%s publication unexpectedly succeeded: %s", test.name, compiledOutputIdentity(failed))
			}
			intentPath := filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")
			intentBytes, err := os.ReadFile(intentPath) //nolint:gosec // fixed path beneath the test-owned compiled CLI home
			if err != nil {
				t.Fatalf("read %s publishing intent: %v", test.name, err)
			}
			for label, canary := range map[string]string{
				"saved-key name":       savedKeyNameCanary,
				"private-key material": privateKeyMaterial,
			} {
				if bytes.Contains(intentBytes, []byte(canary)) {
					t.Fatalf("%s publishing intent exposed %s", test.name, label)
				}
			}

			var intent map[string]any
			if err := json.Unmarshal(intentBytes, &intent); err != nil {
				t.Fatalf("decode %s publishing intent: %v", test.name, err)
			}
			if intent["version"] != float64(2) || intent["state"] != test.wantState {
				t.Fatalf("%s publishing intent version/state = %v/%v, want 2/%s", test.name, intent["version"], intent["state"], test.wantState)
			}
			transactions, ok := intent["transactions"].([]any)
			if !ok || len(transactions) != 1 {
				t.Fatalf("%s publishing intent transaction projection = %v, want one", test.name, intent["transactions"])
			}
			transaction, ok := transactions[0].(map[string]any)
			if !ok || !reflect.DeepEqual(sortedCompiledJSONFields(transaction), []string{"created_at", "operation"}) ||
				transaction["operation"] != "saved_key_removed" ||
				transaction["created_at"] != savedKeyOperationTime {
				t.Fatalf("%s publishing intent transaction projection exceeded its minimum schema", test.name)
			}

			putsBeforeRetry := sync.putCount()
			retried := cli.Run(t, "sshctl", nil, "--json", "push", "--only", transactionID)
			retryValue := assertCompiledJSONSuccess(t, retried)
			preflight, ok := retryValue["preflight"].([]any)
			if !ok || len(preflight) != 1 {
				t.Fatal("reconciled publication lost its public preflight")
			}
			preflightView, ok := preflight[0].(map[string]any)
			if !ok || preflightView["key_name"] != savedKeyNameCanary ||
				preflightView["operation"] != "saved_key_removed" || preflightView["keys"] != float64(1) {
				t.Fatal("public publication preflight lost the #24 saved-key diagnostics")
			}
			wantRetryPUTs := putsBeforeRetry
			if test.wantState == "prepared" {
				wantRetryPUTs++
			}
			if got := sync.putCount(); got != wantRetryPUTs {
				t.Fatalf("%s reconciliation PUT count = %d, want %d", test.name, got, wantRetryPUTs)
			}
		})
	}
}

func TestPublicationIntentCrashMatrix(t *testing.T) {
	t.Run("after intent persistence before request send", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		const (
			transactionID   = "tx_11111111111111111111111111111111"
			passwordCanary  = "ISSUE23_INTENT_PASSWORD_CANARY" //nolint:gosec // test-only fake credential canary
			tokenCanary     = "ISSUE23_INTENT_TOKEN_CANARY"    //nolint:gosec // test-only fake credential canary
			keyCanary       = "ISSUE23_INTENT_PRIVATE_KEY_CANARY"
			inventoryCanary = "ISSUE23_INTENT_DECRYPTED_INVENTORY_CANARY"
		)
		key := config.SSHKey{Name: "intent-key", PrivateKey: keyCanary}
		alpha := config.Connection{
			Name: "alpha", Host: "alpha.example", Port: 22, User: "root",
			Password: passwordCanary, Group: inventoryCanary,
		}
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{alpha},
			Keys:        []config.SSHKey{key},
			PendingBase: &config.InventorySnapshot{},
			PendingMutations: []config.PendingMutation{{
				ID: transactionID, Alias: alpha.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:00Z", After: &alpha, KeysAfter: []config.SSHKey{key},
			}},
		})

		sync := newCompiledSyncFixture(t)
		prerequisiteBlob := encryptCompiledVault(t, cli, &config.Vault{})
		prerequisiteIdentity := compiledOpaqueIdentity(prerequisiteBlob)
		sync.SetRemote(t, prerequisiteBlob, prerequisiteIdentity)
		cli.SaveRemoteETag(t, prerequisiteIdentity)
		cli.SaveCloud(t, sync.URL(), tokenCanary)

		crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{
			"SSM_TEST_PUBLICATION_FAULT": "after_intent_persist",
		}, "--json", "push", "--only", transactionID)
		if crashed.ProcessExit == 0 {
			t.Fatalf("fault-injected publication unexpectedly succeeded: %s", compiledOutputIdentity(crashed))
		}
		if got := sync.MethodCount(http.MethodPut); got != 0 {
			t.Fatalf("PUT count after intent-persistence crash = %d, want 0", got)
		}

		intentPath := filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")
		intent, err := os.ReadFile(intentPath) //nolint:gosec // fixed path beneath the test-owned compiled CLI home
		if err != nil {
			t.Fatalf("read persisted publishing intent: %v", err)
		}
		if err := privatepath.VerifyFile(intentPath); err != nil {
			t.Fatalf("publishing intent is not private: %v", err)
		}
		var encodedIntent map[string]any
		if err := json.Unmarshal(intent, &encodedIntent); err != nil {
			t.Fatalf("decode persisted publishing intent: %v", err)
		}
		if got, want := sortedCompiledJSONFields(encodedIntent), []string{
			"prerequisite_remote_exists", "prerequisite_remote_identity", "scope", "state",
			"target_encrypted_blob_identity", "transaction_ids", "transactions", "version",
		}; !reflect.DeepEqual(got, want) {
			t.Fatalf("publishing intent fields = %v, want safe allowlist %v", got, want)
		}
		for label, forbidden := range map[string]string{
			"password":            passwordCanary,
			"cloud token":         tokenCanary,
			"private key":         keyCanary,
			"decrypted inventory": inventoryCanary,
			"master passphrase":   cli.passphrase,
		} {
			if strings.Contains(string(intent), forbidden) {
				t.Fatalf("publishing intent exposed %s", label)
			}
		}
		if !strings.Contains(string(intent), transactionID) ||
			!strings.Contains(string(intent), prerequisiteIdentity) {
			t.Fatal("publishing intent omitted exact transaction or prerequisite identity")
		}

		status := cli.Run(t, "sshctl", nil, "--json", "status")
		statusValue := assertCompiledJSONSuccess(t, status)
		pending, ok := statusValue["pending_mutations"].([]any)
		if !ok || len(pending) != 1 {
			t.Fatal("restart reconciliation changed the exact pending transaction")
		}
		pendingValue, ok := pending[0].(map[string]any)
		if !ok || pendingValue["id"] != transactionID {
			t.Fatal("restart reconciliation changed the stable pending transaction ID")
		}
		recovery, ok := statusValue["publication_recovery"].(map[string]any)
		if !ok || recovery["state"] != "pending" {
			t.Fatal("status omitted safe pending publication recovery state")
		}
		if got := sync.MethodCount(http.MethodPut); got != 0 {
			t.Fatalf("PUT count after restart reconciliation = %d, want 0", got)
		}
		if _, err := os.Stat(intentPath); !os.IsNotExist(err) {
			t.Fatalf("reconciled prerequisite intent still exists: %v", err)
		}
	})

	t.Run("after prerequisite persistence before request send", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		const transactionID = "tx_22222222222222222222222222222222"
		beta := config.Connection{ //nolint:gosec // test-only fake credential canary
			Name: "beta", Host: "beta.example", Port: 22, User: "root",
			Password: "ISSUE23_READY_PASSWORD_CANARY",
		}
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{beta},
			PendingBase: &config.InventorySnapshot{},
			PendingMutations: []config.PendingMutation{{
				ID: transactionID, Alias: beta.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:01Z", After: &beta,
			}},
		})
		sync := newCompiledSyncFixture(t)
		prerequisiteBlob := encryptCompiledVault(t, cli, &config.Vault{})
		prerequisiteIdentity := compiledOpaqueIdentity(prerequisiteBlob)
		sync.SetRemote(t, prerequisiteBlob, prerequisiteIdentity)
		cli.SaveRemoteETag(t, prerequisiteIdentity)
		cli.SaveCloud(t, sync.URL(), "ISSUE23_READY_TOKEN_CANARY")

		crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{
			"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist",
		}, "--json", "push", "--only", transactionID)
		if crashed.ProcessExit == 0 {
			t.Fatalf("fault-injected publication unexpectedly succeeded: %s", compiledOutputIdentity(crashed))
		}
		if got := sync.MethodCount(http.MethodPut); got != 0 {
			t.Fatalf("PUT count after prerequisite-persistence crash = %d, want 0", got)
		}

		intentPath := filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")
		intentBytes, err := os.ReadFile(intentPath) //nolint:gosec // fixed path beneath the test-owned compiled CLI home
		if err != nil {
			t.Fatalf("read ready publishing intent: %v", err)
		}
		var intent map[string]any
		if err := json.Unmarshal(intentBytes, &intent); err != nil {
			t.Fatalf("decode safe ready publishing intent: %v", err)
		}
		if intent["state"] != "ready" ||
			intent["prerequisite_remote_identity"] != prerequisiteIdentity {
			t.Fatal("ready intent omitted the confirmed prerequisite identity")
		}

		headBeforeOffline := sync.MethodCount(http.MethodHead)
		offline := cli.Run(t, "sshctl", nil, "--offline", "--json", "status")
		offlineValue := assertCompiledJSONSuccess(t, offline)
		offlineRecovery, ok := offlineValue["publication_recovery"].(map[string]any)
		if !ok || offlineRecovery["state"] != "ready" {
			t.Fatal("offline status omitted safe outstanding recovery state")
		}
		if got := sync.MethodCount(http.MethodHead); got != headBeforeOffline {
			t.Fatalf("offline recovery status made network requests: HEAD=%d want=%d", got, headBeforeOffline)
		}
		if _, err := os.Stat(intentPath); err != nil {
			t.Fatalf("offline status mutated outstanding intent: %v", err)
		}

		status := cli.Run(t, "sshctl", nil, "--json", "status")
		statusValue := assertCompiledJSONSuccess(t, status)
		pending, ok := statusValue["pending_mutations"].([]any)
		if !ok || len(pending) != 1 {
			t.Fatal("ready-intent restart reconciliation changed pending scope")
		}
		pendingValue, ok := pending[0].(map[string]any)
		if !ok || pendingValue["id"] != transactionID {
			t.Fatal("ready-intent restart reconciliation changed stable ID")
		}
		if got := sync.MethodCount(http.MethodPut); got != 0 {
			t.Fatalf("PUT count after ready-intent restart = %d, want 0", got)
		}
	})

	for _, test := range []struct {
		name             string
		fault            string
		transactionID    string
		wantPUTs         int
		wantPendingAfter int
		wantIntent       bool
	}{
		{
			name: "before intent persistence", fault: "before_intent_persist",
			transactionID: "tx_66666666666666666666666666666666", wantPendingAfter: 1,
		},
		{
			name: "before request send", fault: "before_request_send",
			transactionID: "tx_77777777777777777777777777777777", wantPendingAfter: 1, wantIntent: true,
		},
		{
			name: "after response receipt", fault: "after_response_receipt",
			transactionID: "tx_88888888888888888888888888888888", wantPUTs: 1, wantIntent: true,
		},
		{
			name: "before local finalization", fault: "before_local_finalization",
			transactionID: "tx_99999999999999999999999999999999", wantPUTs: 1, wantIntent: true,
		},
		{
			name: "after local finalization", fault: "after_local_finalization",
			transactionID: "tx_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", wantPUTs: 1, wantIntent: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cli, sync, original := newSinglePublicationScenario(t, test.transactionID, test.name)
			crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{
				"SSM_TEST_PUBLICATION_FAULT": test.fault,
			}, "--json", "push", "--only", test.transactionID)
			if crashed.ProcessExit != 86 {
				t.Fatalf("fault exit = %d, want 86; output=%s", crashed.ProcessExit, compiledOutputIdentity(crashed))
			}
			if got := sync.putCount(); got != test.wantPUTs {
				t.Fatalf("fault PUT count = %d, want %d", got, test.wantPUTs)
			}
			intentPath := filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")
			_, intentErr := os.Stat(intentPath)
			if test.wantIntent && intentErr != nil {
				t.Fatalf("durable intent missing after fault: %v", intentErr)
			}
			if !test.wantIntent && !os.IsNotExist(intentErr) {
				t.Fatalf("intent exists before persistence: %v", intentErr)
			}
			if test.fault != "after_local_finalization" {
				assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), original)
			}

			status := cli.Run(t, "sshctl", nil, "--json", "status")
			statusValue := assertCompiledJSONSuccess(t, status)
			pending, ok := statusValue["pending_mutations"].([]any)
			if !ok || len(pending) != test.wantPendingAfter {
				t.Fatalf("restart pending count = %v, want %d", statusValue["pending_mutations"], test.wantPendingAfter)
			}
			if test.wantPendingAfter == 1 {
				pendingValue, ok := pending[0].(map[string]any)
				if !ok || pendingValue["id"] != test.transactionID {
					t.Fatal("restart changed pending transaction identity")
				}
			}
			if got := sync.putCount(); got != test.wantPUTs {
				t.Fatalf("restart repeated PUT: count=%d want=%d", got, test.wantPUTs)
			}
		})
	}

	t.Run("after request send before remote commit", func(t *testing.T) {
		const transactionID = "tx_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		cli, sync, original := newSinglePublicationScenario(t, transactionID, "request-sent")
		sync.blockBeforeCommit()
		command := startCompiledPublication(t, cli, transactionID)
		waitPublicationEvent(t, sync.requestRead, "request body read")
		killCompiledPublication(t, command)
		waitPublicationEvent(t, sync.blockDone, "pre-commit handler cancellation")

		if got := sync.putCount(); got != 1 {
			t.Fatalf("sent request count = %d, want 1", got)
		}
		lockPath := filepath.Join(cli.home, ".config", "ssm", "publication.lock")
		if err := privatepath.VerifyFile(lockPath); err != nil {
			t.Fatalf("crashed publication lock path is not private: %v", err)
		}
		assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), original)
		status := cli.Run(t, "sshctl", nil, "--json", "status")
		statusValue := assertCompiledJSONSuccess(t, status)
		pending, ok := statusValue["pending_mutations"].([]any)
		if !ok || len(pending) != 1 {
			t.Fatal("pre-commit crash did not leave exact pending scope")
		}
		if got := sync.putCount(); got != 1 {
			t.Fatalf("pre-commit restart repeated PUT: count=%d", got)
		}
	})

	t.Run("after remote commit before response", func(t *testing.T) {
		const transactionID = "tx_cccccccccccccccccccccccccccccccc"
		cli, sync, _ := newSinglePublicationScenario(t, transactionID, "remote-committed")
		sync.blockAfterCommit()
		command := startCompiledPublication(t, cli, transactionID)
		waitPublicationEvent(t, sync.remoteCommitted, "remote commit")
		killCompiledPublication(t, command)
		waitPublicationEvent(t, sync.blockDone, "post-commit handler cancellation")

		if got := sync.putCount(); got != 1 {
			t.Fatalf("remote-commit request count = %d, want 1", got)
		}
		status := cli.Run(t, "sshctl", nil, "--json", "status")
		statusValue := assertCompiledJSONSuccess(t, status)
		pending, ok := statusValue["pending_mutations"].([]any)
		if !ok || len(pending) != 0 {
			t.Fatal("post-commit crash did not finalize exact confirmed scope")
		}
		if got := sync.putCount(); got != 1 {
			t.Fatalf("post-commit restart repeated PUT: count=%d", got)
		}
	})

	t.Run("retry keeps invocation-start all scope", func(t *testing.T) {
		const (
			alphaID = "tx_dddddddddddddddddddddddddddddddd"
			betaID  = "tx_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		)
		cli, sync, original := newSinglePublicationScenario(t, alphaID, "retry-all")
		crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{
			"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist",
		}, "--json", "push", "--all")
		if crashed.ProcessExit != 86 || sync.putCount() != 0 {
			t.Fatalf("pre-send all-scope crash was not isolated: %s", compiledOutputIdentity(crashed))
		}

		beta := config.Connection{ //nolint:gosec // test-only fake credential canary
			Name: "beta", Host: "beta.example", Port: 22, User: "root",
			Password: "ISSUE23_RETRY_ALL_BETA_CANARY",
		}
		withNewMutation := &config.Vault{
			Connections: []config.Connection{original.Connections[0], beta},
			PendingBase: &config.InventorySnapshot{},
			PendingMutations: []config.PendingMutation{
				original.PendingMutations[0],
				{
					ID: betaID, Alias: beta.Name, Operation: "created",
					CreatedAt: "2026-07-29T00:00:06Z", After: &beta,
				},
			},
		}
		cli.SaveVault(t, withNewMutation)

		retried := cli.Run(t, "sshctl", nil, "--json", "push", "--all")
		value := assertCompiledJSONSuccess(t, retried)
		preflight, ok := value["preflight"].([]any)
		if !ok || len(preflight) != 1 {
			t.Fatal("retry widened the invocation-start all scope")
		}
		selected, ok := preflight[0].(map[string]any)
		if !ok || selected["id"] != alphaID {
			t.Fatal("retry did not preserve the original ordered transaction ID")
		}
		assertCompiledVaultIdentity(t, decodeCompiledVaultIdentity(t, sync.remote(), cli.passphrase), &config.Vault{
			Connections: []config.Connection{original.Connections[0]},
		})
		assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), &config.Vault{
			Connections: []config.Connection{original.Connections[0], beta},
			PendingBase: &config.InventorySnapshot{Connections: []config.Connection{original.Connections[0]}},
			PendingMutations: []config.PendingMutation{{
				ID: betaID, Alias: beta.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:06Z", After: &beta,
			}},
		})
		if got := sync.putCount(); got != 1 {
			t.Fatalf("exact retry PUT count = %d, want 1", got)
		}
	})

	t.Run("divergent third identity preserves both sides", func(t *testing.T) {
		const transactionID = "tx_ffffffffffffffffffffffffffffffff"
		cli, sync, original := newSinglePublicationScenario(t, transactionID, "divergent")
		crashed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{
			"SSM_TEST_PUBLICATION_FAULT": "after_prerequisite_persist",
		}, "--json", "push", "--only", transactionID)
		if crashed.ProcessExit != 86 || sync.putCount() != 0 {
			t.Fatalf("divergence setup did not stop before PUT: %s", compiledOutputIdentity(crashed))
		}

		third := &config.Vault{Connections: []config.Connection{{ //nolint:gosec // test-only fake credential canary
			Name: "third", Host: "third.example", Port: 22, User: "review",
			Password: "ISSUE23_DIVERGENT_REMOTE_CANARY",
		}}}
		thirdBlob := encryptCompiledVault(t, cli, third)
		sync.setRemote(thirdBlob)

		status := cli.Run(t, "sshctl", nil, "--json", "status")
		if status.ProcessExit != 1 || status.Stderr != "" {
			t.Fatalf("divergent status contract changed: %s", compiledOutputIdentity(status))
		}
		statusValue := decodeExactlyOneJSONObject(t, status.Stdout)
		recovery, ok := statusValue["publication_recovery"].(map[string]any)
		if !ok || recovery["state"] != "divergent" ||
			recovery["observed_remote_identity"] != compiledOpaqueIdentity(thirdBlob) {
			t.Fatal("status omitted safe divergent identity evidence")
		}
		assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), original)
		assertCompiledVaultIdentity(t, decodeCompiledVaultIdentity(t, sync.remote(), cli.passphrase), third)

		retry := cli.Run(t, "sshctl", nil, "--json", "push", "--only", transactionID)
		if retry.ProcessExit != 1 {
			t.Fatalf("divergent retry unexpectedly succeeded: %s", compiledOutputIdentity(retry))
		}
		if got := sync.putCount(); got != 0 {
			t.Fatalf("divergent recovery overwrote remote: PUT count=%d", got)
		}
		intentPath := filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")
		intentBytes, err := os.ReadFile(intentPath) //nolint:gosec // fixed path beneath the test-owned compiled CLI home
		if err != nil {
			t.Fatalf("read divergent intent evidence: %v", err)
		}
		var intent map[string]any
		if err := json.Unmarshal(intentBytes, &intent); err != nil {
			t.Fatalf("decode divergent intent evidence: %v", err)
		}
		if intent["state"] != "divergent" ||
			intent["observed_remote_identity"] != compiledOpaqueIdentity(thirdBlob) {
			t.Fatal("durable intent did not preserve divergent remote evidence")
		}
	})

	t.Run("explicit rejection returns exact scope to pending", func(t *testing.T) {
		const transactionID = "tx_0123456789abcdef0123456789abcdef"
		cli, sync, original := newSinglePublicationScenario(t, transactionID, "rejected")
		sync.rejectNext()
		rejected := cli.Run(t, "sshctl", nil, "--json", "push", "--only", transactionID)
		if rejected.ProcessExit != 1 {
			t.Fatalf("explicit rejection unexpectedly succeeded: %s", compiledOutputIdentity(rejected))
		}
		if got := sync.putCount(); got != 1 {
			t.Fatalf("explicit rejection PUT count = %d, want 1", got)
		}
		assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), original)
		intentPath := filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")
		if _, err := os.Stat(intentPath); !os.IsNotExist(err) {
			t.Fatalf("explicit rejection left an ambiguous intent: %v", err)
		}

		retried := cli.Run(t, "sshctl", nil, "--json", "push", "--only", transactionID)
		value := assertCompiledJSONSuccess(t, retried)
		if value["transaction_id"] != transactionID {
			t.Fatal("explicit rejection retry changed the stable ID")
		}
		if got := sync.putCount(); got != 2 {
			t.Fatalf("explicit rejection retry PUT count = %d, want 2 total", got)
		}
	})
}

func TestPublicationReconcilesLostResponse(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	const (
		alphaID = "tx_33333333333333333333333333333333"
		betaID  = "tx_44444444444444444444444444444444"
	)
	alpha := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "alpha", Host: "alpha.example", Port: 22, User: "root",
		Password: "ISSUE23_LOST_RESPONSE_ALPHA_CANARY",
	}
	original := &config.Vault{
		Connections: []config.Connection{alpha},
		PendingBase: &config.InventorySnapshot{},
		PendingMutations: []config.PendingMutation{{
			ID: alphaID, Alias: alpha.Name, Operation: "created",
			CreatedAt: "2026-07-29T00:00:02Z", After: &alpha,
		}},
	}
	cli.SaveVault(t, original)

	sync := newPublicationSyncFixture(t)
	prerequisiteBlob := encryptCompiledVault(t, cli, &config.Vault{})
	sync.setRemote(prerequisiteBlob)
	sync.dropNextResponse()
	prerequisiteIdentity := compiledOpaqueIdentity(prerequisiteBlob)
	cli.SaveRemoteETag(t, prerequisiteIdentity)
	cli.SaveCloud(t, sync.server.URL, "ISSUE23_LOST_RESPONSE_TOKEN_CANARY")

	lost := cli.Run(t, "sshctl", nil, "--json", "push", "--only", alphaID)
	if lost.ProcessExit == 0 {
		t.Fatalf("response-loss publication unexpectedly reported success: %s", compiledOutputIdentity(lost))
	}
	if got := sync.putCount(); got != 1 {
		t.Fatalf("response-loss PUT count = %d, want 1", got)
	}
	targetBlob := sync.remote()
	if len(targetBlob) == 0 || compiledOpaqueIdentity(targetBlob) == prerequisiteIdentity {
		t.Fatal("response-loss fixture did not commit the encrypted target")
	}

	beta := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "beta", Host: "beta.example", Port: 22, User: "root",
		Password: "ISSUE23_LOST_RESPONSE_BETA_CANARY",
	}
	withNewMutation := &config.Vault{
		Connections: []config.Connection{alpha, beta},
		PendingBase: &config.InventorySnapshot{},
		PendingMutations: []config.PendingMutation{
			original.PendingMutations[0],
			{
				ID: betaID, Alias: beta.Name, Operation: "created",
				CreatedAt: "2026-07-29T00:00:03Z", After: &beta,
			},
		},
	}
	cli.SaveVault(t, withNewMutation)

	status := cli.Run(t, "sshctl", nil, "--json", "status")
	statusValue := assertCompiledJSONSuccess(t, status)
	pending, ok := statusValue["pending_mutations"].([]any)
	if !ok || len(pending) != 1 {
		t.Fatal("lost-response reconciliation did not retain exactly one new mutation")
	}
	pendingValue, ok := pending[0].(map[string]any)
	if !ok || pendingValue["id"] != betaID {
		t.Fatal("lost-response reconciliation absorbed or renumbered the new mutation")
	}
	recovery, ok := statusValue["publication_recovery"].(map[string]any)
	if !ok || recovery["state"] != "confirmed" {
		t.Fatal("status omitted target-confirmed recovery state")
	}
	if got := sync.putCount(); got != 1 {
		t.Fatalf("restart repeated a confirmed publication: PUT count=%d", got)
	}

	assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), &config.Vault{
		Connections: []config.Connection{alpha, beta},
		PendingBase: &config.InventorySnapshot{Connections: []config.Connection{alpha}},
		PendingMutations: []config.PendingMutation{{
			ID: betaID, Alias: beta.Name, Operation: "created",
			CreatedAt: "2026-07-29T00:00:03Z", After: &beta,
		}},
	})
	assertCompiledVaultIdentity(t, decodeCompiledVaultIdentity(t, targetBlob, cli.passphrase), &config.Vault{
		Connections: []config.Connection{alpha},
	})

	secondStatus := cli.Run(t, "sshctl", nil, "--json", "status")
	_ = assertCompiledJSONSuccess(t, secondStatus)
	if got := sync.putCount(); got != 1 {
		t.Fatalf("second restart repeated confirmed PUT: count=%d", got)
	}
}

func TestPublicationReconcilesFinalizeFailure(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	const transactionID = "tx_55555555555555555555555555555555"
	alpha := config.Connection{ //nolint:gosec // test-only fake credential canary
		Name: "alpha", Host: "alpha.example", Port: 22, User: "root",
		Password: "ISSUE23_FINALIZE_ALPHA_CANARY",
	}
	original := &config.Vault{
		Connections: []config.Connection{alpha},
		PendingBase: &config.InventorySnapshot{},
		PendingMutations: []config.PendingMutation{{
			ID: transactionID, Alias: alpha.Name, Operation: "created",
			CreatedAt: "2026-07-29T00:00:04Z", After: &alpha,
		}},
	}
	cli.SaveVault(t, original)

	sync := newPublicationSyncFixture(t)
	prerequisiteBlob := encryptCompiledVault(t, cli, &config.Vault{})
	sync.setRemote(prerequisiteBlob)
	cli.SaveRemoteETag(t, compiledOpaqueIdentity(prerequisiteBlob))
	cli.SaveCloud(t, sync.server.URL, "ISSUE23_FINALIZE_TOKEN_CANARY")

	failed := cli.RunWithEnv(t, "sshctl", nil, map[string]string{
		"SSM_TEST_PUBLICATION_FAULT": "before_local_finalization_error",
	}, "--json", "push", "--only", transactionID)
	if failed.ProcessExit == 0 {
		t.Fatalf("fault-injected finalization unexpectedly succeeded: %s", compiledOutputIdentity(failed))
	}
	if got := sync.putCount(); got != 1 {
		t.Fatalf("finalization-failure PUT count = %d, want 1", got)
	}
	assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), original)

	intentPath := filepath.Join(cli.home, ".config", "ssm", "publishing-intent.json")
	intentBytes, err := os.ReadFile(intentPath) //nolint:gosec // fixed path beneath the test-owned compiled CLI home
	if err != nil {
		t.Fatalf("read finalization-failure intent: %v", err)
	}
	var intent map[string]any
	if err := json.Unmarshal(intentBytes, &intent); err != nil {
		t.Fatalf("decode finalization-failure intent: %v", err)
	}
	if intent["state"] != "finalization_failed" {
		t.Fatalf("finalization failure state = %v, want finalization_failed", intent["state"])
	}

	headBeforeRestart := sync.headCount()
	status := cli.Run(t, "sshctl", nil, "--offline", "--json", "status")
	statusValue := assertCompiledJSONSuccess(t, status)
	pending, ok := statusValue["pending_mutations"].([]any)
	if !ok || len(pending) != 0 {
		t.Fatal("restart did not finalize exactly the target-confirmed transaction")
	}
	recovery, ok := statusValue["publication_recovery"].(map[string]any)
	if !ok || recovery["state"] != "confirmed" {
		t.Fatal("status omitted confirmed finalization recovery")
	}
	if got := sync.putCount(); got != 1 {
		t.Fatalf("restart repeated PUT after local finalization failure: count=%d", got)
	}
	if got := sync.headCount(); got != headBeforeRestart {
		t.Fatalf("offline finalization recovery made a HEAD request: count=%d want=%d", got, headBeforeRestart)
	}
	if _, err := os.Stat(intentPath); !os.IsNotExist(err) {
		t.Fatalf("finalized intent still exists: %v", err)
	}

	secondStatus := cli.Run(t, "sshctl", nil, "--json", "status")
	_ = assertCompiledJSONSuccess(t, secondStatus)
	if got := sync.putCount(); got != 1 {
		t.Fatalf("second restart repeated finalized PUT: count=%d", got)
	}
}

func newSinglePublicationScenario(
	t *testing.T,
	transactionID string,
	label string,
) (*compiledCLIHarness, *publicationSyncFixture, *config.Vault) {
	t.Helper()
	cli := newCompiledCLIHarness(t)
	alpha := config.Connection{
		Name: "alpha", Host: "alpha.example", Port: 22, User: "root",
		Password: "ISSUE23_MATRIX_PASSWORD_" + strings.ToUpper(strings.ReplaceAll(label, " ", "_")),
	}
	original := &config.Vault{
		Connections: []config.Connection{alpha},
		PendingBase: &config.InventorySnapshot{},
		PendingMutations: []config.PendingMutation{{
			ID: transactionID, Alias: alpha.Name, Operation: "created",
			CreatedAt: "2026-07-29T00:00:05Z", After: &alpha,
		}},
	}
	cli.SaveVault(t, original)
	sync := newPublicationSyncFixture(t)
	prerequisiteBlob := encryptCompiledVault(t, cli, &config.Vault{})
	sync.setRemote(prerequisiteBlob)
	cli.SaveRemoteETag(t, compiledOpaqueIdentity(prerequisiteBlob))
	cli.SaveCloud(t, sync.server.URL, "ISSUE23_MATRIX_TOKEN_"+strings.ToUpper(strings.ReplaceAll(label, " ", "_")))
	return cli, sync, original
}

type runningCompiledPublication struct {
	command *exec.Cmd
	stdout  bytes.Buffer
	stderr  bytes.Buffer
}

func startCompiledPublication(
	t *testing.T,
	cli *compiledCLIHarness,
	transactionID string,
) *runningCompiledPublication {
	t.Helper()
	running := &runningCompiledPublication{
		command: exec.Command( //nolint:gosec // fixed test-built CLI and arguments under the compiled harness
			cli.paths["sshctl"], "--json", "push", "--only", transactionID,
		),
	}
	running.command.Env = isolatedCompiledCLIEnvironmentWith(cli.home, cli.temp, map[string]string{
		"SSM_MASTER_PASS_FILE": cli.passPath,
	})
	running.command.Stdout = &running.stdout
	running.command.Stderr = &running.stderr
	if err := running.command.Start(); err != nil {
		t.Fatalf("start compiled publication: %v", err)
	}
	return running
}

func killCompiledPublication(t *testing.T, running *runningCompiledPublication) {
	t.Helper()
	if err := running.command.Process.Kill(); err != nil {
		t.Fatalf("kill compiled publication: %v", err)
	}
	if err := running.command.Wait(); err == nil {
		t.Fatal("killed compiled publication unexpectedly exited successfully")
	}
}

func waitCompiledPublication(t *testing.T, running *runningCompiledPublication) compiledCLIResult {
	t.Helper()
	err := running.command.Wait()
	processExit := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("wait for compiled publication: %v", err)
		}
		processExit = exitErr.ExitCode()
	}
	result := compiledCLIResult{
		ProcessExit: processExit,
		Stdout:      running.stdout.String(),
		Stderr:      running.stderr.String(),
	}
	return result
}

func assertCompiledSinglePreflightID(t *testing.T, value map[string]any, want string) {
	t.Helper()
	preflight, ok := value["preflight"].([]any)
	if !ok || len(preflight) != 1 {
		t.Fatalf("publication preflight = %v, want one transaction", value["preflight"])
	}
	transaction, ok := preflight[0].(map[string]any)
	if !ok || transaction["id"] != want {
		t.Fatalf("publication preflight transaction = %v, want id %s", preflight[0], want)
	}
}

func waitPublicationEvent(t *testing.T, event <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for publication %s", label)
	}
}

type publicationSyncFixture struct {
	server *httptest.Server

	mu               sync.Mutex
	remoteBlob       []byte
	committed        [][]byte
	heads            int
	puts             int
	loseNextResponse bool
	requestRead      chan struct{}
	requestReadOnce  sync.Once
	nextRequest      chan struct{}
	remoteCommitted  chan struct{}
	blockDone        chan struct{}
	blockPreCommit   bool
	releasePreCommit chan struct{}
	blockPostCommit  bool
	rejectNextPut    bool
}

func newPublicationSyncFixture(t *testing.T) *publicationSyncFixture {
	t.Helper()
	fixture := &publicationSyncFixture{}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *publicationSyncFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/sync" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodHead:
		f.mu.Lock()
		f.heads++
		blob := append([]byte(nil), f.remoteBlob...)
		nextRequest := f.nextRequest
		f.mu.Unlock()
		if nextRequest != nil {
			select {
			case nextRequest <- struct{}{}:
			default:
			}
		}
		if len(blob) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", `"`+compiledOpaqueIdentity(blob)+`"`)
		w.WriteHeader(http.StatusOK)
	case http.MethodPut:
		blob, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "fixture read failed", http.StatusInternalServerError)
			return
		}
		f.mu.Lock()
		f.puts++
		blockPreCommit := f.blockPreCommit
		requestRead := f.requestRead
		blockDone := f.blockDone
		releasePreCommit := f.releasePreCommit
		reject := f.rejectNextPut
		f.rejectNextPut = false
		f.mu.Unlock()
		if reject {
			http.Error(w, `{"error":"fixture explicit rejection"}`, http.StatusConflict)
			return
		}
		if requestRead != nil {
			f.requestReadOnce.Do(func() { close(requestRead) })
		}
		if blockPreCommit {
			select {
			case <-releasePreCommit:
			case <-r.Context().Done():
				if blockDone != nil {
					close(blockDone)
				}
				return
			}
		}

		f.mu.Lock()
		f.remoteBlob = append([]byte(nil), blob...)
		f.committed = append(f.committed, append([]byte(nil), blob...))
		loseResponse := f.loseNextResponse
		f.loseNextResponse = false
		blockPostCommit := f.blockPostCommit
		remoteCommitted := f.remoteCommitted
		blockDone = f.blockDone
		f.mu.Unlock()
		if remoteCommitted != nil {
			close(remoteCommitted)
		}
		if blockPostCommit {
			<-r.Context().Done()
			close(blockDone)
			return
		}
		if loseResponse {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				panic("publication fixture does not support response loss")
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				panic(err)
			}
			_ = connection.Close()
			return
		}
		w.Header().Set("ETag", `"`+compiledOpaqueIdentity(blob)+`"`)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "fixture method rejected", http.StatusMethodNotAllowed)
	}
}

func (f *publicationSyncFixture) setRemote(blob []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remoteBlob = append([]byte(nil), blob...)
}

func (f *publicationSyncFixture) remote() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.remoteBlob...)
}

func (f *publicationSyncFixture) committedBlobs() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	blobs := make([][]byte, len(f.committed))
	for i := range f.committed {
		blobs[i] = append([]byte(nil), f.committed[i]...)
	}
	return blobs
}

func (f *publicationSyncFixture) putCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.puts
}

func (f *publicationSyncFixture) headCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heads
}

func (f *publicationSyncFixture) blockBeforeCommit() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockPreCommit = true
	f.requestRead = make(chan struct{})
	f.requestReadOnce = sync.Once{}
	f.blockDone = make(chan struct{})
}

func (f *publicationSyncFixture) holdFirstBeforeCommit() chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockPreCommit = true
	f.requestRead = make(chan struct{})
	f.requestReadOnce = sync.Once{}
	f.nextRequest = make(chan struct{}, 1)
	f.releasePreCommit = make(chan struct{})
	return f.releasePreCommit
}

func (f *publicationSyncFixture) blockAfterCommit() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockPostCommit = true
	f.remoteCommitted = make(chan struct{})
	f.blockDone = make(chan struct{})
}

func (f *publicationSyncFixture) rejectNext() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejectNextPut = true
}

func (f *publicationSyncFixture) dropNextResponse() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loseNextResponse = true
}

func encryptCompiledVault(t *testing.T, cli *compiledCLIHarness, value *config.Vault) []byte {
	t.Helper()
	blob, err := config.EncryptVault(value, cli.passphrase)
	if err != nil {
		t.Fatalf("encrypt compiled publication vault: %v", err)
	}
	return blob
}

func compiledOpaqueIdentity(blob []byte) string {
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}
