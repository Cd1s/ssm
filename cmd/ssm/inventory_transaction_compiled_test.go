package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/config"
)

func TestInventoryTransactionPolicy(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	cli.SaveVault(t, &config.Vault{})
	password := strings.Repeat("compiled-material-", 3)
	passwordPath := filepath.Join(cli.temp, "policy.password")
	if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0o600); err != nil {
		t.Fatalf("write compiled policy password fixture: %v", err)
	}
	assertReceipt := func(
		t *testing.T,
		result compiledCLIResult,
		action string,
		changed bool,
	) string {
		t.Helper()
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"password":      password,
			"password_path": passwordPath,
			"passphrase":    cli.passphrase,
		})
		value := assertCompiledJSONSuccess(t, result)
		if value["action"] != action || value["changed"] != changed ||
			value["applied"] != true || value["pushed"] != false ||
			value["sync_pending"] != true {
			t.Fatalf("compiled mutation receipt fields changed; output=%s", compiledOutputIdentity(result))
		}
		if !changed {
			if _, exists := value["transaction_id"]; exists {
				t.Fatalf("unchanged upsert created a transaction; output=%s", compiledOutputIdentity(result))
			}
			return ""
		}
		return compiledTransactionID(t, value, result)
	}

	add := cli.Run(
		t, "sshctl", nil,
		"--json", "host", "add", "policy-host", "--host", "192.0.2.70", "--user", "runner",
		"--password-file", passwordPath, "--offline",
	)
	addID := assertReceipt(t, add, "created", true)
	update := cli.Run(
		t, "ssm", nil,
		"--json", "host", "update", "policy-host", "--host", "192.0.2.71", "--group", "prod", "--offline",
	)
	updateID := assertReceipt(t, update, "updated", true)

	request := func(group string) []byte {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"version": 1, "op": "host.upsert", "alias": "policy-host",
			"host": map[string]any{
				"address": "192.0.2.71", "user": "runner", "group": group,
				"password_file": passwordPath, "offline": true, "verify": false,
			},
		})
		if err != nil {
			t.Fatalf("marshal compiled policy request: %v", err)
		}
		return body
	}
	unchanged := cli.Run(t, "sshctl", request("prod"), "request", "-")
	assertReceipt(t, unchanged, "unchanged", false)
	changedRequest := request("stage")
	upsert := cli.Run(t, "sshctl", changedRequest, "request", "-")
	assertNoCompiledCanaryLeak(t, upsert, map[string]string{"request_body": string(changedRequest)})
	upsertID := assertReceipt(t, upsert, "updated", true)

	removeRequest, err := json.Marshal(map[string]any{
		"version": 1, "op": "host.remove", "alias": "policy-host",
		"host": map[string]any{"offline": true, "confirm": true},
	})
	if err != nil {
		t.Fatalf("marshal compiled remove request: %v", err)
	}
	remove := cli.Run(t, "sshctl", removeRequest, "request", "-")
	assertNoCompiledCanaryLeak(t, remove, map[string]string{"request_body": string(removeRequest)})
	removeID := assertReceipt(t, remove, "removed", true)

	ids := []string{addID, updateID, upsertID, removeID}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatal("compiled direct/request-v1 mutations reused a stable transaction ID")
		}
		seen[id] = true
	}
	status := cli.Run(t, "sshctl", nil, "--offline", "--json", "status")
	pending := compiledPendingTransactionViews(t, assertCompiledJSONSuccess(t, status), status)
	if len(pending) != len(ids) {
		t.Fatalf("pending mutation count = %d, want %d", len(pending), len(ids))
	}
	wantOperations := []string{"created", "updated", "updated", "removed"}
	for i := range ids {
		if pending[i].ID != ids[i] || pending[i].Alias != "policy-host" ||
			pending[i].Operation != wantOperations[i] {
			t.Fatal("compiled direct/request-v1 pending receipt order or fields changed")
		}
	}
	local := cli.LoadVaultIdentity(t)
	if len(local.Connections) != 0 || len(local.PendingMutations) != len(ids) ||
		local.PendingBase == nil || len(local.PendingBase.Connections) != 0 {
		t.Fatal("compiled host policy did not preserve the compatible removed candidate and pending base")
	}
}

func TestScopedPublicationSavedKeyDependencies(t *testing.T) {
	t.Run("key creation is an explicit cross-alias prerequisite", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		keyMaterial := strings.Repeat("create-material-", 3)
		token := strings.Repeat("create-access-", 3)
		key := config.SSHKey{Name: "shared-key", PrivateKey: keyMaterial}
		alpha := config.Connection{
			Name: "alpha", Host: "192.0.2.20", Port: 22, User: "runner", KeyName: key.Name,
		}
		beta := config.Connection{
			Name: "beta", Host: "192.0.2.21", Port: 22, User: "runner", KeyName: key.Name,
		}
		starting := &config.Vault{
			Connections: []config.Connection{alpha, beta},
			Keys:        []config.SSHKey{key},
			PendingBase: &config.InventorySnapshot{},
			PendingMutations: []config.PendingMutation{
				{
					ID: "tx_key_create", Alias: alpha.Name, Operation: "created", CreatedAt: "2026-07-29T00:00:00Z",
					After: &alpha, KeysAfter: []config.SSHKey{key},
				},
				{
					ID: "tx_key_reference", Alias: beta.Name, Operation: "created", CreatedAt: "2026-07-29T00:00:01Z",
					After: &beta, KeysBefore: []config.SSHKey{key}, KeysAfter: []config.SSHKey{key},
				},
			},
		}
		cli.SaveVault(t, starting)
		cli.SaveCloud(t, sync.URL(), token)

		result := cli.Run(t, "sshctl", nil, "--json", "push", "--only", "tx_key_reference")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"private_key": keyMaterial,
			"token":       token,
			"passphrase":  cli.passphrase,
		})
		assertCompiledMachineContract(t, result, compiledMachineContract{
			OK: false, Error: "sync_push_failed", JSONExit: 1, ProcessExit: 1,
			Hint:   "local vault remains pending; fix sync and retry push",
			Absent: []string{"stage", "alias", "candidates"},
		})
		for _, safe := range []string{
			"tx_key_create", "alpha", "created", "shared-key", "saved_key_create",
		} {
			if !strings.Contains(result.Stdout, safe) {
				t.Fatalf("dependency failure omitted safe prerequisite field %q; output=%s", safe, compiledOutputIdentity(result))
			}
		}
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("rejected dependency scope %s count = %d, want 0", method, got)
			}
		}
		assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), starting)
	})

	t.Run("saved-key deletion orders later recreation", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		oldMaterial := strings.Repeat("delete-old-material-", 3)
		newMaterial := strings.Repeat("delete-new-material-", 3)
		token := strings.Repeat("delete-access-", 3)
		oldKey := config.SSHKey{Name: "deleted-key", PrivateKey: oldMaterial}
		newKey := config.SSHKey{Name: oldKey.Name, PrivateKey: newMaterial}
		alphaBefore := config.Connection{
			Name: "alpha", Host: "192.0.2.25", Port: 22, User: "runner", KeyName: oldKey.Name,
		}
		alphaAfter := alphaBefore
		alphaAfter.KeyName = ""
		alphaAfter.Password = strings.Repeat("delete-auth-material-", 3)
		beta := config.Connection{
			Name: "beta", Host: "192.0.2.26", Port: 22, User: "runner", KeyName: newKey.Name,
		}
		starting := &config.Vault{
			Connections: []config.Connection{alphaAfter, beta},
			Keys:        []config.SSHKey{newKey},
			PendingBase: &config.InventorySnapshot{
				Connections: []config.Connection{alphaBefore},
				Keys:        []config.SSHKey{oldKey},
			},
			PendingMutations: []config.PendingMutation{
				{
					ID: "tx_key_delete", Alias: alphaAfter.Name, Operation: "updated", CreatedAt: "2026-07-29T00:00:10Z",
					Before: &alphaBefore, After: &alphaAfter, KeysBefore: []config.SSHKey{oldKey},
				},
				{
					ID: "tx_key_recreate", Alias: beta.Name, Operation: "created", CreatedAt: "2026-07-29T00:00:11Z",
					After: &beta, KeysAfter: []config.SSHKey{newKey},
				},
			},
		}
		cli.SaveVault(t, starting)
		cli.SaveCloud(t, sync.URL(), token)

		result := cli.Run(t, "sshctl", nil, "--json", "push", "--only", "tx_key_recreate")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"old_private_key": oldMaterial,
			"new_private_key": newMaterial,
			"password":        alphaAfter.Password,
			"token":           token,
			"passphrase":      cli.passphrase,
		})
		assertCompiledMachineContract(t, result, compiledMachineContract{
			OK: false, Error: "sync_push_failed", JSONExit: 1, ProcessExit: 1,
			Hint:   "local vault remains pending; fix sync and retry push",
			Absent: []string{"stage", "alias", "candidates"},
		})
		for _, safe := range []string{"tx_key_delete", "alpha", "updated", oldKey.Name, "saved_key_delete"} {
			if !strings.Contains(result.Stdout, safe) {
				t.Fatalf("delete dependency failure omitted %q; output=%s", safe, compiledOutputIdentity(result))
			}
		}
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("rejected delete scope %s count = %d, want 0", method, got)
			}
		}
		assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), starting)
	})

	t.Run("replacement waits for cross-alias reference change", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		originalMaterial := strings.TrimSpace(string(testPrivateKey(t)))
		replacementMaterial := strings.TrimSpace(string(testPrivateKey(t)))
		key := config.SSHKey{Name: "rotated-key", PrivateKey: originalMaterial}
		alpha := config.Connection{
			Name: "alpha", Host: "192.0.2.40", Port: 22, User: "runner", KeyName: key.Name,
		}
		beta := config.Connection{
			Name: "beta", Host: "192.0.2.41", Port: 22, User: "runner", KeyName: key.Name,
		}
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{alpha, beta},
			Keys:        []config.SSHKey{key},
		})
		passwordPath := filepath.Join(cli.temp, "beta.password")
		password := strings.Repeat("replacement-auth-material-", 3)
		if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0o600); err != nil {
			t.Fatalf("write replacement password fixture: %v", err)
		}
		replacementPath := filepath.Join(cli.temp, "replacement.key")
		if err := os.WriteFile(replacementPath, []byte(replacementMaterial), 0o600); err != nil {
			t.Fatalf("write replacement key fixture: %v", err)
		}

		referenceChange := cli.Run(
			t, "sshctl", nil,
			"--json", "host", "update", beta.Name, "--password-file", passwordPath, "--offline",
		)
		referenceID := compiledTransactionID(t, assertCompiledJSONSuccess(t, referenceChange), referenceChange)
		replacement := cli.Run(
			t, "sshctl", nil,
			"--json", "host", "update", alpha.Name, "--key-file", replacementPath, "--offline",
		)
		replacementID := compiledTransactionID(t, assertCompiledJSONSuccess(t, replacement), replacement)
		newReference := cli.Run(
			t, "sshctl", nil,
			"--json", "host", "add", "gamma", "--host", "192.0.2.42", "--user", "runner",
			"--key", key.Name, "--offline",
		)
		newReferenceID := compiledTransactionID(t, assertCompiledJSONSuccess(t, newReference), newReference)
		if referenceID == replacementID || replacementID == newReferenceID || referenceID == newReferenceID {
			t.Fatal("replacement dependency fixture reused a stable transaction ID")
		}

		token := strings.Repeat("replacement-access-", 3)
		cli.SaveCloud(t, sync.URL(), token)
		result := cli.Run(t, "sshctl", nil, "--json", "push", "--only", newReferenceID)
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"original_private_key":    originalMaterial,
			"replacement_private_key": replacementMaterial,
			"password":                password,
			"token":                   token,
			"passphrase":              cli.passphrase,
		})
		assertCompiledMachineContract(t, result, compiledMachineContract{
			OK: false, Error: "sync_push_failed", JSONExit: 1, ProcessExit: 1,
			Hint:   "local vault remains pending; fix sync and retry push",
			Absent: []string{"stage", "alias", "candidates"},
		})
		referenceAt := strings.Index(result.Stdout, referenceID)
		replacementAt := strings.Index(result.Stdout, replacementID)
		if referenceAt < 0 || replacementAt < 0 || referenceAt >= replacementAt {
			t.Fatalf("replacement dependencies are missing or nondeterministic; output=%s", compiledOutputIdentity(result))
		}
		for _, safe := range []string{
			"beta", "updated", key.Name, "saved_key_reference", "saved_key_replace",
		} {
			if !strings.Contains(result.Stdout, safe) {
				t.Fatalf("replacement dependency failure omitted %q; output=%s", safe, compiledOutputIdentity(result))
			}
		}
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("rejected replacement scope %s count = %d, want 0", method, got)
			}
		}
		status := cli.Run(t, "sshctl", nil, "--offline", "--json", "status")
		pending := compiledPendingTransactionViews(t, assertCompiledJSONSuccess(t, status), status)
		if len(pending) != 3 ||
			pending[0].ID != referenceID || pending[1].ID != replacementID || pending[2].ID != newReferenceID {
			t.Fatal("rejected replacement scope changed stable pending transaction IDs")
		}
	})

	t.Run("last-reference prune is explicit and exact publication never widens", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		originalMaterial := strings.TrimSpace(string(testPrivateKey(t)))
		recreatedMaterial := strings.TrimSpace(string(testPrivateKey(t)))
		key := config.SSHKey{Name: "pruned-key", PrivateKey: originalMaterial}
		alpha := config.Connection{
			Name: "alpha", Host: "192.0.2.50", Port: 22, User: "runner", KeyName: key.Name,
		}
		beta := config.Connection{
			Name: "beta", Host: "192.0.2.51", Port: 22, User: "runner", KeyName: key.Name,
		}
		cli.SaveVault(t, &config.Vault{
			Connections: []config.Connection{alpha, beta},
			Keys:        []config.SSHKey{key},
		})
		alphaPassword := strings.Repeat("prune-alpha-material-", 3)
		alphaPasswordPath := filepath.Join(cli.temp, "alpha.password")
		if err := os.WriteFile(alphaPasswordPath, []byte(alphaPassword+"\n"), 0o600); err != nil {
			t.Fatalf("write prune password fixture: %v", err)
		}
		recreatedPath := filepath.Join(cli.temp, "recreated.key")
		if err := os.WriteFile(recreatedPath, []byte(recreatedMaterial), 0o600); err != nil {
			t.Fatalf("write recreated key fixture: %v", err)
		}
		unrelatedPassword := strings.Repeat("prune-unrelated-material-", 3)
		unrelatedPasswordPath := filepath.Join(cli.temp, "unrelated.password")
		if err := os.WriteFile(unrelatedPasswordPath, []byte(unrelatedPassword+"\n"), 0o600); err != nil {
			t.Fatalf("write unrelated password fixture: %v", err)
		}

		referenceChange := cli.Run(
			t, "sshctl", nil,
			"--json", "host", "update", alpha.Name, "--password-file", alphaPasswordPath, "--offline",
		)
		referenceID := compiledTransactionID(t, assertCompiledJSONSuccess(t, referenceChange), referenceChange)
		prune := cli.Run(
			t, "sshctl", nil,
			"--json", "host", "remove", beta.Name, "--yes", "--prune-key", "--offline",
		)
		pruneID := compiledTransactionID(t, assertCompiledJSONSuccess(t, prune), prune)
		recreate := cli.Run(
			t, "sshctl", nil,
			"--json", "host", "add", "gamma", "--host", "192.0.2.52", "--user", "runner",
			"--key-file", recreatedPath, "--key-name", key.Name, "--offline",
		)
		recreateID := compiledTransactionID(t, assertCompiledJSONSuccess(t, recreate), recreate)
		unrelated := cli.Run(
			t, "sshctl", nil,
			"--json", "host", "add", "unrelated", "--host", "192.0.2.53", "--user", "runner",
			"--password-file", unrelatedPasswordPath, "--offline",
		)
		unrelatedID := compiledTransactionID(t, assertCompiledJSONSuccess(t, unrelated), unrelated)

		token := strings.Repeat("prune-access-", 3)
		cli.SaveCloud(t, sync.URL(), token)
		rejected := cli.Run(t, "sshctl", nil, "--json", "push", "--only", recreateID)
		assertNoCompiledCanaryLeak(t, rejected, map[string]string{
			"original_private_key":  originalMaterial,
			"recreated_private_key": recreatedMaterial,
			"alpha_password":        alphaPassword,
			"unrelated_password":    unrelatedPassword,
			"token":                 token,
			"passphrase":            cli.passphrase,
		})
		assertCompiledMachineContract(t, rejected, compiledMachineContract{
			OK: false, Error: "sync_push_failed", JSONExit: 1, ProcessExit: 1,
			Hint:   "local vault remains pending; fix sync and retry push",
			Absent: []string{"stage", "alias", "candidates"},
		})
		referenceAt := strings.Index(rejected.Stdout, referenceID)
		pruneAt := strings.Index(rejected.Stdout, pruneID)
		if referenceAt < 0 || pruneAt < 0 || referenceAt >= pruneAt {
			t.Fatalf("prune dependencies are missing or nondeterministic; output=%s", compiledOutputIdentity(rejected))
		}
		for _, safe := range []string{"saved_key_reference", "saved_key_prune", key.Name} {
			if !strings.Contains(rejected.Stdout, safe) {
				t.Fatalf("prune dependency failure omitted %q; output=%s", safe, compiledOutputIdentity(rejected))
			}
		}
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("rejected prune scope %s count = %d, want 0", method, got)
			}
		}

		for _, transactionID := range []string{referenceID, pruneID, recreateID} {
			pushed := cli.Run(t, "sshctl", nil, "--json", "push", "--only", transactionID)
			value := assertCompiledJSONSuccess(t, pushed)
			assertCompiledStringField(t, value, "transaction_id", transactionID, pushed)
			assertNoCompiledCanaryLeak(t, pushed, map[string]string{
				"original_private_key":  originalMaterial,
				"recreated_private_key": recreatedMaterial,
				"alpha_password":        alphaPassword,
				"unrelated_password":    unrelatedPassword,
				"token":                 token,
				"passphrase":            cli.passphrase,
			})
		}
		alphaAfter := alpha
		alphaAfter.Password = alphaPassword
		alphaAfter.KeyName = ""
		gamma := config.Connection{
			Name: "gamma", Host: "192.0.2.52", Port: 22, User: "runner", KeyName: key.Name,
		}
		recreatedKey := config.SSHKey{Name: key.Name, PrivateKey: recreatedMaterial}
		assertCompiledVaultIdentity(
			t,
			decodeCompiledVaultIdentity(t, sync.UploadedBlob(), cli.passphrase),
			&config.Vault{
				Connections: []config.Connection{alphaAfter, gamma},
				Keys:        []config.SSHKey{recreatedKey},
			},
		)
		status := cli.Run(t, "sshctl", nil, "--offline", "--json", "status")
		assertNoCompiledCanaryLeak(t, status, map[string]string{
			"original_private_key":  originalMaterial,
			"recreated_private_key": recreatedMaterial,
			"alpha_password":        alphaPassword,
			"unrelated_password":    unrelatedPassword,
			"token":                 token,
			"passphrase":            cli.passphrase,
		})
		statusValue := assertCompiledJSONSuccess(t, status)
		pending, ok := statusValue["pending_mutations"].([]any)
		if !ok || len(pending) != 1 {
			t.Fatal("exact dependent publication did not leave only the unrelated stable transaction pending")
		}
		pendingValue, ok := pending[0].(map[string]any)
		if !ok || pendingValue["id"] != unrelatedID {
			t.Fatal("public pending view lost the unrelated stable transaction ID")
		}
		local := cli.LoadVaultIdentity(t)
		if len(local.PendingMutations) != 1 || local.PendingMutations[0].ID != unrelatedID {
			t.Fatal("local ledger lost or published the unrelated transaction")
		}
		if len(local.Connections) != 3 {
			t.Fatal("local candidate inventory lost an unrelated pending host")
		}
	})

	t.Run("rename dependencies include transitive alias order", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		oldMaterial := strings.Repeat("rename-old-material-", 3)
		newMaterial := strings.Repeat("rename-new-material-", 3)
		token := strings.Repeat("rename-access-", 3)
		oldKey := config.SSHKey{Name: "old-key", PrivateKey: oldMaterial}
		newKey := config.SSHKey{Name: "new-key", PrivateKey: newMaterial}
		alphaBefore := config.Connection{
			Name: "alpha", Host: "192.0.2.30", Port: 22, User: "runner", KeyName: oldKey.Name,
		}
		alphaAfter := alphaBefore
		alphaAfter.KeyName = newKey.Name
		beta := config.Connection{
			Name: "beta", Host: "192.0.2.31", Port: 22, User: "runner", KeyName: newKey.Name,
		}
		starting := &config.Vault{
			Connections: []config.Connection{alphaAfter, beta},
			Keys:        []config.SSHKey{oldKey, newKey},
			PendingBase: &config.InventorySnapshot{},
			PendingMutations: []config.PendingMutation{
				{
					ID: "tx_alpha_create", Alias: alphaBefore.Name, Operation: "created", CreatedAt: "2026-07-29T00:01:00Z",
					After: &alphaBefore, KeysAfter: []config.SSHKey{oldKey},
				},
				{
					ID: "tx_alpha_rename", Alias: alphaAfter.Name, Operation: "updated", CreatedAt: "2026-07-29T00:01:01Z",
					Before: &alphaBefore, After: &alphaAfter,
					KeysBefore: []config.SSHKey{oldKey}, KeysAfter: []config.SSHKey{oldKey, newKey},
				},
				{
					ID: "tx_beta_reference", Alias: beta.Name, Operation: "created", CreatedAt: "2026-07-29T00:01:02Z",
					After: &beta, KeysBefore: []config.SSHKey{oldKey, newKey}, KeysAfter: []config.SSHKey{oldKey, newKey},
				},
			},
		}
		cli.SaveVault(t, starting)
		cli.SaveCloud(t, sync.URL(), token)

		result := cli.Run(t, "sshctl", nil, "--json", "push", "--only", "tx_beta_reference")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"old_private_key": oldMaterial,
			"new_private_key": newMaterial,
			"token":           token,
			"passphrase":      cli.passphrase,
		})
		assertCompiledMachineContract(t, result, compiledMachineContract{
			OK: false, Error: "sync_push_failed", JSONExit: 1, ProcessExit: 1,
			Hint:   "local vault remains pending; fix sync and retry push",
			Absent: []string{"stage", "alias", "candidates"},
		})
		createAt := strings.Index(result.Stdout, "tx_alpha_create")
		renameAt := strings.Index(result.Stdout, "tx_alpha_rename")
		if createAt < 0 || renameAt < 0 || createAt >= renameAt {
			t.Fatalf("transitive dependencies are missing or nondeterministic; output=%s", compiledOutputIdentity(result))
		}
		for _, safe := range []string{"alias_order", "new-key", "saved_key_rename"} {
			if !strings.Contains(result.Stdout, safe) {
				t.Fatalf("transitive dependency failure omitted %q; output=%s", safe, compiledOutputIdentity(result))
			}
		}
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("rejected transitive scope %s count = %d, want 0", method, got)
			}
		}
		assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), starting)
	})
}
