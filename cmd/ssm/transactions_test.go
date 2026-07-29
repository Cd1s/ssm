package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"ssm/internal/cloud"
	"ssm/internal/config"
	"ssm/internal/inventorytransaction"
	securevault "ssm/internal/vault"
)

func TestPushCommandLoadsMasterPassFile(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	pass := "push-command-test-pass" //nolint:gosec // test-only vault passphrase
	if err := config.Save(&config.Vault{}, pass); err != nil {
		t.Fatal(err)
	}
	passPath := filepath.Join(config.Dir(), "master.pass")
	if err := os.WriteFile(passPath, []byte(pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/sync" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "test-token"}); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestPushCommandHelper") //nolint:gosec // executes this test binary with fixed arguments
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "SSM_TEST_PUSH_HELPER=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("push command failed: %v: %s", err, output)
	}
	if !strings.Contains(string(output), `"ok": true`) {
		t.Fatalf("push output = %s", output)
	}
}

func TestPushCommandHelper(t *testing.T) {
	t.Helper()
	if os.Getenv("SSM_TEST_PUSH_HELPER") != "1" {
		return
	}
	injectPushPersistenceFailureFromEnvironment()
	runSSHCTL([]string{"--json", "push", "--all"})
}

func TestPushLocalPersistenceFailurePreventsPublication(t *testing.T) {
	if !pushPersistenceFailureSupported() {
		t.Skip("regular-file persistence fault injection is unavailable on this platform")
	}
	home := t.TempDir()
	setTestHome(t, home)
	pass := "ISSUE20_PERSISTENCE_PASSPHRASE_CANARY"        //nolint:gosec // test-only vault passphrase
	connectionSecret := "ISSUE20_PERSISTENCE_VAULT_CANARY" //nolint:gosec // test-only fake credential canary
	tokenSecret := "ISSUE20_PERSISTENCE_TOKEN_CANARY"      //nolint:gosec // test-only fake credential canary
	original := &config.Vault{
		Connections: []config.Connection{{
			Name: "alpha", Host: "alpha.example", Port: 22, User: "root", Password: connectionSecret,
		}},
		PendingBase: &config.InventorySnapshot{},
		PendingMutations: []config.PendingMutation{{
			ID: "tx_alpha", Alias: "alpha", Operation: "created", CreatedAt: "2026-07-28T00:00:00Z",
			After: &config.Connection{Name: "alpha", Host: "alpha.example", Port: 22, User: "root", Password: connectionSecret},
		}},
	}
	if err := config.Save(original, pass); err != nil {
		t.Fatal(err)
	}
	passPath := filepath.Join(config.Dir(), "master.pass")
	if err := os.WriteFile(passPath, []byte(pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", `"must-not-publish"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: tokenSecret}); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestPushCommandHelper$", "-test.count=1") //nolint:gosec // executes this test binary with fixed arguments
	cmd.Env = append(
		os.Environ(),
		"HOME="+home,
		"USERPROFILE="+home,
		"SSM_TEST_PUSH_HELPER=1",
		"SSM_TEST_PUSH_PERSISTENCE_FAILURE=1",
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push unexpectedly succeeded: %s", output)
	}
	for label, canary := range map[string]string{
		"passphrase": pass,
		"vault":      connectionSecret,
		"token":      tokenSecret,
	} {
		if strings.Contains(string(output), canary) {
			t.Fatalf("push persistence failure leaked %s: %s", label, output)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("sync requests = %d, want 0 before local persistence succeeds", got)
	}
	after, loadErr := config.Load(pass)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !reflect.DeepEqual(after, original) {
		t.Fatalf("local pending ledger changed after persistence failure: got=%+v want=%+v", after, original)
	}
}

func TestScopedPushDoesNotPublishUnrelatedPendingMutation(t *testing.T) {
	setTestHome(t, t.TempDir())
	previousPass := masterPass
	masterPass = "transaction-test-pass"
	t.Cleanup(func() { masterPass = previousPass })

	base := &config.Vault{Connections: []config.Connection{{Name: "base", Host: "base.example", Port: 22, User: "root", Password: "base-secret"}}}
	alpha := config.Connection{Name: "alpha", Host: "alpha.example", Port: 22, User: "root", Password: "alpha-secret"}
	beta := config.Connection{Name: "beta", Host: "beta.example", Port: 22, User: "root", Password: "beta-secret"}
	withBeta := &config.Vault{
		Connections: []config.Connection{base.Connections[0], alpha, beta},
		PendingBase: &config.InventorySnapshot{
			Connections: append([]config.Connection(nil), base.Connections...),
		},
		PendingMutations: []config.PendingMutation{
			{ID: "tx_alpha", Alias: alpha.Name, Operation: "created", CreatedAt: "2026-07-29T00:00:00Z", After: &alpha},
			{ID: "tx_beta", Alias: beta.Name, Operation: "created", CreatedAt: "2026-07-29T00:00:01Z", After: &beta},
		},
	}
	if err := config.Save(withBeta, masterPass); err != nil {
		t.Fatal(err)
	}

	var uploaded []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/sync" {
			http.NotFound(w, r)
			return
		}
		var err error
		uploaded, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upload: %v", err)
		}
		w.Header().Set("ETag", `"`+compiledOpaqueIdentity(uploaded)+`"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "test-token"}); err != nil {
		t.Fatal(err)
	}

	result, err := pushTransactionScope("tx_beta")
	if err != nil {
		t.Fatal(err)
	}
	if result.Scope != "only" || len(result.Preflight) != 1 || result.Preflight[0].Alias != "beta" {
		t.Fatalf("preflight = %+v", result)
	}
	plaintext, err := securevault.Decrypt(uploaded, masterPass)
	if err != nil {
		t.Fatal(err)
	}
	var published config.Vault
	if err := json.Unmarshal(plaintext, &published); err != nil {
		t.Fatal(err)
	}
	if exactConnectionIndex(&published, "beta") < 0 || exactConnectionIndex(&published, "alpha") >= 0 {
		t.Fatalf("scoped published aliases = %+v", published.Connections)
	}
	if published.PendingBase != nil || len(published.PendingMutations) != 0 {
		t.Fatalf("published transaction metadata: %+v", published)
	}

	local, err := config.Load(masterPass)
	if err != nil {
		t.Fatal(err)
	}
	if exactConnectionIndex(local, "alpha") < 0 || exactConnectionIndex(local, "beta") < 0 {
		t.Fatalf("local inventory lost pending changes: %+v", local.Connections)
	}
	if len(local.PendingMutations) != 1 || local.PendingMutations[0].ID != "tx_alpha" {
		t.Fatalf("remaining mutations = %+v", local.PendingMutations)
	}
}

func TestScopedPushRemoteFailureRestoresExactPendingLedger(t *testing.T) {
	setTestHome(t, t.TempDir())
	previousPass := masterPass
	masterPass = "ISSUE20_REMOTE_FAILURE_PASSPHRASE_CANARY" //nolint:gosec // test-only vault passphrase
	t.Cleanup(func() { masterPass = previousPass })

	base := config.Connection{Name: "base", Host: "base.example", Port: 22, User: "root", Password: "ISSUE20_BASE_SECRET_CANARY"}     //nolint:gosec // test-only fake credential canary
	alpha := config.Connection{Name: "alpha", Host: "alpha.example", Port: 22, User: "root", Password: "ISSUE20_ALPHA_SECRET_CANARY"} //nolint:gosec // test-only fake credential canary
	beta := config.Connection{Name: "beta", Host: "beta.example", Port: 22, User: "root", Password: "ISSUE20_BETA_SECRET_CANARY"}     //nolint:gosec // test-only fake credential canary
	original := &config.Vault{
		Connections: []config.Connection{base, alpha, beta},
		PendingBase: &config.InventorySnapshot{Connections: []config.Connection{base}},
		PendingMutations: []config.PendingMutation{
			{ID: "tx_alpha", Alias: "alpha", Operation: "created", CreatedAt: "2026-07-28T00:00:00Z", After: &alpha},
			{ID: "tx_beta", Alias: "beta", Operation: "created", CreatedAt: "2026-07-28T00:00:01Z", After: &beta},
		},
	}
	if err := config.Save(original, masterPass); err != nil {
		t.Fatal(err)
	}
	originalBlob, err := os.ReadFile(config.Path())
	if err != nil {
		t.Fatal(err)
	}

	var uploaded []byte
	var putCount atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/sync" {
			http.NotFound(w, r)
			return
		}
		putCount.Add(1)
		var err error
		uploaded, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upload: %v", err)
		}
		http.Error(w, `{"error":"fixture remote rejection"}`, http.StatusInternalServerError)
	}))
	defer server.Close()
	tokenSecret := "ISSUE20_REMOTE_FAILURE_TOKEN_CANARY" //nolint:gosec // test-only fake credential canary
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: tokenSecret}); err != nil {
		t.Fatal(err)
	}

	_, err = pushTransactionScope("tx_beta")
	if err == nil {
		t.Fatal("scoped push unexpectedly succeeded")
	}
	for label, canary := range map[string]string{
		"passphrase": masterPass,
		"base":       base.Password,
		"alpha":      alpha.Password,
		"beta":       beta.Password,
		"token":      tokenSecret,
	} {
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("push failure leaked %s: %v", label, err)
		}
		if strings.Contains(string(uploaded), canary) {
			t.Fatalf("encrypted upload exposed %s plaintext", label)
		}
	}
	if got := putCount.Load(); got != 1 {
		t.Fatalf("PUT count = %d, want 1", got)
	}
	plaintext, decryptErr := securevault.Decrypt(uploaded, masterPass)
	if decryptErr != nil {
		t.Fatal(decryptErr)
	}
	var attempted config.Vault
	if unmarshalErr := json.Unmarshal(plaintext, &attempted); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	wantAttempted := &config.Vault{Connections: []config.Connection{base, beta}}
	if !reflect.DeepEqual(&attempted, wantAttempted) {
		t.Fatalf("attempted scoped publication widened: got=%+v want=%+v", &attempted, wantAttempted)
	}
	after, loadErr := config.Load(masterPass)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !reflect.DeepEqual(after, original) {
		t.Fatalf("remote failure did not restore exact pending ledger: got=%+v want=%+v", after, original)
	}
	afterBlob, readErr := os.ReadFile(config.Path())
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(afterBlob, originalBlob) {
		t.Fatal("remote failure did not atomically restore the exact original opaque vault bytes")
	}
}

func TestPushAllPersistsIntentBeforePUTAndFinalizesAfterConfirmation(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	pass := "ISSUE20_SUCCESS_PASSPHRASE_CANARY"   //nolint:gosec // test-only vault passphrase
	tokenSecret := "ISSUE20_SUCCESS_TOKEN_CANARY" //nolint:gosec // test-only fake credential canary
	alpha := config.Connection{Name: "alpha", Host: "alpha.example", Port: 22, User: "root", Password: "ISSUE20_SUCCESS_ALPHA_CANARY"}
	beta := config.Connection{Name: "beta", Host: "beta.example", Port: 22, User: "root", Password: "ISSUE20_SUCCESS_BETA_CANARY"}
	original := &config.Vault{
		Connections: []config.Connection{alpha, beta},
		PendingBase: &config.InventorySnapshot{},
		PendingMutations: []config.PendingMutation{
			{ID: "tx_alpha", Alias: "alpha", Operation: "created", CreatedAt: "2026-07-28T00:00:00Z", After: &alpha},
			{ID: "tx_beta", Alias: "beta", Operation: "created", CreatedAt: "2026-07-28T00:00:01Z", After: &beta},
		},
	}
	if err := config.Save(original, pass); err != nil {
		t.Fatal(err)
	}
	passPath := filepath.Join(config.Dir(), "master.pass")
	if err := os.WriteFile(passPath, []byte(pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	type publicationObservation struct {
		uploaded    []byte
		persisted   []byte
		intentAtPUT []byte
		err         error
	}
	observed := make(chan publicationObservation, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/sync" {
			http.NotFound(w, r)
			return
		}
		observation := publicationObservation{}
		if r.Method != http.MethodPut || r.URL.Path != "/sync" {
			http.NotFound(w, r)
			return
		} else {
			observation.uploaded, observation.err = io.ReadAll(r.Body)
			if observation.err == nil {
				observation.persisted, observation.err = os.ReadFile(config.Path())
			}
			if observation.err == nil {
				observation.intentAtPUT, observation.err = os.ReadFile(
					filepath.Join(config.Dir(), "publishing-intent.json"),
				)
			}
		}
		observed <- observation
		w.Header().Set("ETag", `"`+compiledOpaqueIdentity(observation.uploaded)+`"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: tokenSecret}); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestPushCommandHelper$", "-test.count=1") //nolint:gosec // executes this test binary with fixed arguments
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "SSM_TEST_PUSH_HELPER=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("push command failed: %v: %s", err, output)
	}
	observation := <-observed
	if observation.err != nil {
		t.Fatal(observation.err)
	}
	for label, canary := range map[string]string{
		"passphrase": pass,
		"alpha":      alpha.Password,
		"beta":       beta.Password,
		"token":      tokenSecret,
	} {
		if strings.Contains(string(output), canary) {
			t.Fatalf("successful push leaked %s in output: %s", label, output)
		}
		if strings.Contains(string(observation.uploaded), canary) {
			t.Fatalf("successful push exposed %s plaintext in transport", label)
		}
		if strings.Contains(string(observation.intentAtPUT), canary) {
			t.Fatalf("successful push exposed %s in publishing intent", label)
		}
	}
	if bytes.Equal(observation.uploaded, observation.persisted) {
		t.Fatal("--all marked the local ledger published before target confirmation")
	}
	persistedPlaintext, decryptErr := securevault.Decrypt(observation.persisted, pass)
	if decryptErr != nil {
		t.Fatal(decryptErr)
	}
	var persistedAtPUT config.Vault
	if unmarshalErr := json.Unmarshal(persistedPlaintext, &persistedAtPUT); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if !reflect.DeepEqual(&persistedAtPUT, original) {
		t.Fatal("local vault did not retain the exact pending ledger until target confirmation")
	}
	plaintext, decryptErr := securevault.Decrypt(observation.uploaded, pass)
	if decryptErr != nil {
		t.Fatal(decryptErr)
	}
	var published config.Vault
	if unmarshalErr := json.Unmarshal(plaintext, &published); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	wantFinalized := &config.Vault{Connections: []config.Connection{alpha, beta}}
	if !reflect.DeepEqual(&published, wantFinalized) {
		t.Fatal("published target was not the exact finalized projection")
	}
	var intent map[string]any
	if err := json.Unmarshal(observation.intentAtPUT, &intent); err != nil {
		t.Fatalf("decode intent persisted before PUT: %v", err)
	}
	ids, ok := intent["transaction_ids"].([]any)
	if !ok || len(ids) != 2 || ids[0] != "tx_alpha" || ids[1] != "tx_beta" ||
		intent["target_encrypted_blob_identity"] != compiledOpaqueIdentity(observation.uploaded) {
		t.Fatal("intent did not bind the exact ordered scope and target before PUT")
	}
	after, loadErr := config.Load(pass)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !reflect.DeepEqual(after, wantFinalized) {
		t.Fatal("confirmed target did not finalize the exact local transaction IDs")
	}
	if _, err := os.Stat(filepath.Join(config.Dir(), "publishing-intent.json")); !os.IsNotExist(err) {
		t.Fatalf("confirmed publishing intent still exists: %v", err)
	}
	for _, transactionID := range []string{"tx_alpha", "tx_beta"} {
		if !strings.Contains(string(output), transactionID) {
			t.Fatalf("successful push output omitted stable selected transaction %q: %s", transactionID, output)
		}
	}
}

func TestPendingMutationViewsDoNotRevealSecrets(t *testing.T) {
	v := &config.Vault{PendingMutations: []config.PendingMutation{{
		ID: "tx_safe", Alias: "prod", Operation: "updated", CreatedAt: "2026-01-01T00:00:00Z",
		After:     &config.Connection{Name: "prod", Password: "must-not-leak"},
		KeysAfter: []config.SSHKey{{Name: "deploy", PrivateKey: "private-material"}},
	}}}
	encoded, err := json.Marshal(inventorytransaction.Pending(v))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "must-not-leak") || strings.Contains(string(encoded), "private-material") {
		t.Fatalf("pending view leaked a secret: %s", encoded)
	}
}

func TestScopedPushRejectsDependentAliasTransaction(t *testing.T) {
	v := &config.Vault{
		PendingBase: &config.InventorySnapshot{},
		PendingMutations: []config.PendingMutation{
			{ID: "tx_first", Alias: "same", Operation: "created"},
			{ID: "tx_second", Alias: "same", Operation: "updated"},
		},
	}
	if _, err := inventorytransaction.Preflight(v, "tx_second"); err == nil || !strings.Contains(err.Error(), "requires pending") {
		t.Fatalf("dependency error = %v", err)
	}
}
