package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ssm/internal/cloud"
	"ssm/internal/config"
	securevault "ssm/internal/vault"
)

func TestScopedPushDoesNotPublishUnrelatedPendingMutation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	previousPass := masterPass
	masterPass = "transaction-test-pass"
	t.Cleanup(func() { masterPass = previousPass })

	base := &config.Vault{Connections: []config.Connection{{Name: "base", Host: "base.example", Port: 22, User: "root", Password: "base-secret"}}}
	withAlpha := cloneVault(base)
	withAlpha.Connections = append(withAlpha.Connections, config.Connection{Name: "alpha", Host: "alpha.example", Port: 22, User: "root", Password: "alpha-secret"})
	alphaResult := hostMutationResult{Changed: true, Action: "created", Host: newHostView(withAlpha.Connections[1])}
	if err := appendHostMutation(base, withAlpha, &alphaResult); err != nil {
		t.Fatal(err)
	}

	withBeta := cloneVault(withAlpha)
	withBeta.Connections = append(withBeta.Connections, config.Connection{Name: "beta", Host: "beta.example", Port: 22, User: "root", Password: "beta-secret"})
	betaResult := hostMutationResult{Changed: true, Action: "created", Host: newHostView(withBeta.Connections[2])}
	if err := appendHostMutation(withAlpha, withBeta, &betaResult); err != nil {
		t.Fatal(err)
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
		w.Header().Set("ETag", `"scoped-etag"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "test-token"}); err != nil {
		t.Fatal(err)
	}

	result, err := pushTransactionScope(betaResult.TransactionID)
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
	if len(local.PendingMutations) != 1 || local.PendingMutations[0].ID != alphaResult.TransactionID {
		t.Fatalf("remaining mutations = %+v", local.PendingMutations)
	}
}

func TestPendingMutationViewsDoNotRevealSecrets(t *testing.T) {
	v := &config.Vault{PendingMutations: []config.PendingMutation{{
		ID: "tx_safe", Alias: "prod", Operation: "updated", CreatedAt: "2026-01-01T00:00:00Z",
		After:     &config.Connection{Name: "prod", Password: "must-not-leak"},
		KeysAfter: []config.SSHKey{{Name: "deploy", PrivateKey: "private-material"}},
	}}}
	encoded, err := json.Marshal(pendingMutationViews(v))
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
	if _, _, err := publishProjection(v, "tx_second"); err == nil || !strings.Contains(err.Error(), "depends on earlier") {
		t.Fatalf("dependency error = %v", err)
	}
}
