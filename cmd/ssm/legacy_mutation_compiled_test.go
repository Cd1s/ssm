//nolint:gosec // Compiled fixtures intentionally use fake credential canaries and fixed reviewed source paths.
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ssm/internal/config"
)

func TestLegacyMutationsCreatePendingTransactions(t *testing.T) {
	t.Run("legacy remove creates one reviewable transaction", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		password := "ISSUE24_LEGACY_REMOVE_PASSWORD_CANARY"
		starting := &config.Vault{Connections: []config.Connection{{
			Name: "legacy-remove", Host: "192.0.2.24", Port: 22, User: "runner", Password: password,
		}}}
		cli.SaveVault(t, starting)
		cli.SaveCloud(t, sync.URL(), "ISSUE24_LEGACY_REMOVE_TOKEN_CANARY")

		result := cli.Run(t, "ssm", nil, "--offline", "--json", "remove", "legacy-remove")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"password": password,
			"token":    "ISSUE24_LEGACY_REMOVE_TOKEN_CANARY",
		})
		value := assertCompiledJSONSuccess(t, result)
		if value["action"] != "removed" || value["applied"] != true ||
			value["pushed"] != false || value["sync_pending"] != true {
			t.Fatalf("legacy remove receipt fields changed; output=%s", compiledOutputIdentity(result))
		}
		transactionID := compiledTransactionID(t, value, result)

		statusResult := cli.Run(t, "sshctl", nil, "--offline", "--json", "status")
		pending := compiledPendingTransactionViews(
			t,
			assertCompiledJSONSuccess(t, statusResult),
			statusResult,
		)
		if len(pending) != 1 || pending[0].ID != transactionID ||
			pending[0].Alias != "legacy-remove" || pending[0].Operation != "removed" {
			t.Fatal("legacy remove did not create exactly one stable pending removal")
		}
		local := cli.LoadVaultIdentity(t)
		if len(local.Connections) != 0 || local.PendingBase == nil ||
			len(local.PendingBase.Connections) != 1 || len(local.PendingMutations) != 1 {
			t.Fatal("legacy remove did not persist the candidate and its pending base atomically")
		}
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("offline legacy remove %s count = %d, want 0", method, got)
			}
		}
	})

	t.Run("saved-key removal creates one reviewable key transaction", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		privateKey := "ISSUE24_LEGACY_KEY_MATERIAL_CANARY"
		starting := &config.Vault{Keys: []config.SSHKey{{
			Name: "orphan-key", PrivateKey: privateKey,
		}}}
		cli.SaveVault(t, starting)
		cli.SaveCloud(t, sync.URL(), "ISSUE24_LEGACY_KEY_TOKEN_CANARY")

		result := cli.Run(t, "ssm", nil, "--offline", "--json", "keys", "remove", "orphan-key")
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"private_key": privateKey,
			"token":       "ISSUE24_LEGACY_KEY_TOKEN_CANARY",
		})
		value := assertCompiledJSONSuccess(t, result)
		if value["action"] != "saved_key_removed" || value["key_name"] != "orphan-key" ||
			value["keys"] != float64(1) || value["applied"] != true ||
			value["pushed"] != false || value["sync_pending"] != true {
			t.Fatalf("saved-key removal receipt fields changed; output=%s", compiledOutputIdentity(result))
		}
		transactionID := compiledTransactionID(t, value, result)

		statusResult := cli.Run(t, "sshctl", nil, "--offline", "--json", "status")
		status := assertCompiledJSONSuccess(t, statusResult)
		raw, ok := status["pending_mutations"].([]any)
		if !ok || len(raw) != 1 {
			t.Fatal("saved-key removal did not create exactly one pending transaction")
		}
		pending, ok := raw[0].(map[string]any)
		if !ok || pending["id"] != transactionID ||
			pending["operation"] != "saved_key_removed" ||
			pending["key_name"] != "orphan-key" || pending["keys"] != float64(1) {
			t.Fatal("saved-key pending view lost its stable safe metadata")
		}
		for _, forbidden := range []string{"alias", "aliases", "connections"} {
			if _, exists := pending[forbidden]; exists {
				t.Fatalf("saved-key pending view contains unrelated field %q", forbidden)
			}
		}
		local := cli.LoadVaultIdentity(t)
		if len(local.Keys) != 0 || local.PendingBase == nil ||
			len(local.PendingBase.Keys) != 1 || len(local.PendingMutations) != 1 {
			t.Fatal("saved-key removal did not persist the candidate and pending base atomically")
		}
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("offline saved-key removal %s count = %d, want 0", method, got)
			}
		}
	})

	t.Run("saved-key removal rejects live references without side effects", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		privateKey := "ISSUE24_REFERENCED_KEY_MATERIAL_CANARY"
		starting := &config.Vault{
			Connections: []config.Connection{{
				Name: "key-user", Host: "192.0.2.25", Port: 22, User: "runner", KeyName: "shared-key",
			}},
			Keys: []config.SSHKey{{Name: "shared-key", PrivateKey: privateKey}},
		}
		cli.SaveVault(t, starting)
		cli.SaveCloud(t, sync.URL(), "ISSUE24_REFERENCED_KEY_TOKEN_CANARY")

		result := cli.Run(t, "ssm", nil, "--offline", "--json", "keys", "remove", "shared-key")
		if result.ProcessExit == 0 {
			t.Fatalf("referenced saved-key removal unexpectedly succeeded; output=%s", compiledOutputIdentity(result))
		}
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"private_key": privateKey,
			"token":       "ISSUE24_REFERENCED_KEY_TOKEN_CANARY",
		})
		for _, safe := range []string{"shared-key", "key-user"} {
			if !strings.Contains(result.Stdout+result.Stderr, safe) {
				t.Fatalf("saved-key rejection omitted safe reference %q; output=%s", safe, compiledOutputIdentity(result))
			}
		}
		assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), starting)
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("rejected saved-key removal %s count = %d, want 0", method, got)
			}
		}
	})

	t.Run("saved-key removal preserves reference dependency and later exact projection", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		privateKey := "ISSUE24_DEPENDENT_KEY_MATERIAL_CANARY"
		starting := &config.Vault{
			Connections: []config.Connection{{
				Name: "dependent-host", Host: "192.0.2.26", Port: 22, User: "runner", KeyName: "dependent-key",
			}},
			Keys: []config.SSHKey{{Name: "dependent-key", PrivateKey: privateKey}},
		}
		cli.SaveVault(t, starting)

		removeHost := cli.Run(
			t,
			"ssm",
			nil,
			"--offline", "--json", "host", "remove", "dependent-host", "--yes",
		)
		removeHostID := compiledTransactionID(t, assertCompiledJSONSuccess(t, removeHost), removeHost)
		removeKey := cli.Run(
			t,
			"ssm",
			nil,
			"--offline", "--json", "keys", "remove", "dependent-key",
		)
		removeKeyID := compiledTransactionID(t, assertCompiledJSONSuccess(t, removeKey), removeKey)
		if removeHostID == removeKeyID {
			t.Fatal("host and saved-key removals reused a stable transaction ID")
		}

		cli.SaveCloud(t, sync.URL(), "ISSUE24_DEPENDENT_KEY_TOKEN_CANARY")
		rejected := cli.Run(t, "sshctl", nil, "--json", "push", "--only", removeKeyID)
		if rejected.ProcessExit == 0 {
			t.Fatal("dependent saved-key transaction published without its host prerequisite")
		}
		assertNoCompiledCanaryLeak(t, rejected, map[string]string{
			"private_key": privateKey,
			"token":       "ISSUE24_DEPENDENT_KEY_TOKEN_CANARY",
		})
		for _, safe := range []string{
			removeHostID, "dependent-host", "removed", "dependent-key", "saved_key_reference",
		} {
			if !strings.Contains(rejected.Stdout+rejected.Stderr, safe) {
				t.Fatalf("saved-key dependency rejection omitted %q; output=%s", safe, compiledOutputIdentity(rejected))
			}
		}
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("saved-key dependency preflight %s count = %d, want 0", method, got)
			}
		}

		for _, transactionID := range []string{removeHostID, removeKeyID} {
			result := cli.Run(t, "sshctl", nil, "--json", "push", "--only", transactionID)
			value := assertCompiledJSONSuccess(t, result)
			assertCompiledStringField(t, value, "transaction_id", transactionID, result)
			assertNoCompiledCanaryLeak(t, result, map[string]string{
				"private_key": privateKey,
				"token":       "ISSUE24_DEPENDENT_KEY_TOKEN_CANARY",
			})
		}
		remote := decodeCompiledVaultIdentity(t, sync.UploadedBlob(), cli.passphrase)
		if len(remote.Connections) != 0 || len(remote.Keys) != 0 ||
			remote.PendingBase != nil || len(remote.PendingMutations) != 0 {
			t.Fatal("explicit prerequisite workflow did not publish the exact empty inventory")
		}
	})

	t.Run("legacy not-found compatibility output remains", func(t *testing.T) {
		cases := []struct {
			name       string
			args       []string
			wantStdout string
		}{
			{
				name:       "connection",
				args:       []string{"--offline", "--json", "remove", "missing"},
				wantStdout: "Connection \"missing\" not found.\n",
			},
			{
				name:       "saved key",
				args:       []string{"--offline", "--json", "keys", "remove", "missing"},
				wantStdout: "Key \"missing\" not found.\n",
			},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				cli := newCompiledCLIHarness(t)
				cli.SaveVault(t, &config.Vault{})
				result := cli.Run(t, "ssm", nil, test.args...)
				if result.ProcessExit == 0 || result.Stdout != test.wantStdout || result.Stderr != "" {
					t.Fatalf("legacy not-found output changed; output=%s", compiledOutputIdentity(result))
				}
				local := cli.LoadVaultIdentity(t)
				if len(local.PendingMutations) != 0 || local.PendingBase != nil {
					t.Fatal("legacy not-found compatibility route created pending state")
				}
			})
		}
	})
}

func TestImportCreatesOneAtomicBulkTransaction(t *testing.T) {
	for _, mode := range []string{"merge", "replace"} {
		t.Run(mode+" import is one bulk transaction", func(t *testing.T) {
			cli := newCompiledCLIHarness(t)
			sync := newCompiledSyncFixture(t)
			startingPassword := "ISSUE24_IMPORT_STARTING_PASSWORD_CANARY"
			importedPassword := "ISSUE24_IMPORT_PASSWORD_CANARY"
			importedKey := "ISSUE24_IMPORT_KEY_CANARY"
			starting := &config.Vault{Connections: []config.Connection{{
				Name: "existing", Host: "192.0.2.30", Port: 22, User: "runner", Password: startingPassword,
			}}}
			cli.SaveVault(t, starting)
			cli.SaveCloud(t, sync.URL(), "ISSUE24_IMPORT_TOKEN_CANARY")
			importPath := filepath.Join(cli.temp, mode+"-import.json")
			importBody := `[
				{"alias":"bulk-alpha","host":"192.0.2.31","port":22,"user":"runner","auth_type":"password","password":"` + importedPassword + `"},
				{"alias":"bulk-beta","host":"192.0.2.32","port":2222,"user":"runner","auth_type":"key","private_key":"` + importedKey + `"}
			]`
			if err := os.WriteFile(importPath, []byte(importBody), 0o600); err != nil {
				t.Fatalf("write bulk import fixture: %v", err)
			}
			args := []string{"--offline", "--json", "import-json", importPath, "--" + mode}
			if mode == "replace" {
				args = append(args, "--yes")
			}

			result := cli.Run(t, "ssm", nil, args...)
			assertNoCompiledCanaryLeak(t, result, map[string]string{
				"starting_password": startingPassword,
				"imported_password": importedPassword,
				"imported_key":      importedKey,
				"token":             "ISSUE24_IMPORT_TOKEN_CANARY",
			})
			value := assertCompiledJSONSuccess(t, result)
			if value["action"] != mode+"d" || value["connections"] != float64(2) ||
				value["keys"] != float64(1) || value["applied"] != true ||
				value["pushed"] != false || value["sync_pending"] != true {
				t.Fatalf("bulk import receipt fields changed; output=%s", compiledOutputIdentity(result))
			}
			transactionID := compiledTransactionID(t, value, result)
			receiptAliases, receiptAliasesOK := value["aliases"].([]any)

			statusResult := cli.Run(t, "sshctl", nil, "--offline", "--json", "status")
			status := assertCompiledJSONSuccess(t, statusResult)
			raw, ok := status["pending_mutations"].([]any)
			if !ok || len(raw) != 1 {
				t.Fatalf("%s import created %d pending records, want one", mode, len(raw))
			}
			pending, ok := raw[0].(map[string]any)
			aliases, aliasesOK := pending["aliases"].([]any)
			wantAliases := []any{"bulk-alpha", "bulk-beta"}
			if mode == "replace" {
				wantAliases = append(wantAliases, "existing")
			}
			if !ok || !aliasesOK || pending["id"] != transactionID ||
				pending["operation"] != "import_"+mode+"d" ||
				pending["connections"] != float64(len(wantAliases)) || pending["keys"] != float64(1) ||
				!reflect.DeepEqual(aliases, wantAliases) ||
				!receiptAliasesOK || !reflect.DeepEqual(receiptAliases, wantAliases) {
				t.Fatal("bulk import pending view lost stable safe aliases or counts")
			}
			for _, forbidden := range []string{"alias", "key_name", "before", "after", "payload"} {
				if _, exists := pending[forbidden]; exists {
					t.Fatalf("bulk import pending view contains unsafe or misleading field %q", forbidden)
				}
			}
			local := cli.LoadVaultIdentity(t)
			if local.PendingBase == nil || len(local.PendingMutations) != 1 {
				t.Fatal("bulk import did not persist one pending base and one transaction")
			}
			wantConnections := 2
			if mode == "merge" {
				wantConnections++
			}
			if len(local.Connections) != wantConnections || len(local.Keys) != 1 {
				t.Fatal("bulk import candidate inventory does not match the selected mode")
			}
			for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
				if got := sync.MethodCount(method); got != 0 {
					t.Fatalf("offline %s import %s count = %d, want 0", mode, method, got)
				}
			}
		})
	}

	t.Run("late invalid item leaves inventory and ledger unchanged", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		starting := &config.Vault{Connections: []config.Connection{{
			Name: "preserved", Host: "192.0.2.33", Port: 22, User: "runner",
			Password: "ISSUE24_LATE_INVALID_STARTING_CANARY",
		}}}
		cli.SaveVault(t, starting)
		cli.SaveCloud(t, sync.URL(), "ISSUE24_LATE_INVALID_TOKEN_CANARY")
		beforeBlob := cli.VaultBlob(t)
		importPath := filepath.Join(cli.temp, "late-invalid.json")
		importBody := `[
			{"alias":"valid-first","host":"192.0.2.34","port":22,"user":"runner","auth_type":"password","password":"ISSUE24_LATE_VALID_CANARY"},
			{"alias":"invalid-last","host":"192.0.2.35","port":70000,"user":"runner","auth_type":"password","password":"ISSUE24_LATE_INVALID_CANARY"}
		]`
		if err := os.WriteFile(importPath, []byte(importBody), 0o600); err != nil {
			t.Fatalf("write late-invalid import fixture: %v", err)
		}

		result := cli.Run(
			t,
			"ssm",
			nil,
			"--offline", "--json", "import-json", importPath, "--merge",
		)
		if result.ProcessExit == 0 {
			t.Fatalf("late-invalid import unexpectedly succeeded; output=%s", compiledOutputIdentity(result))
		}
		assertNoCompiledCanaryLeak(t, result, map[string]string{
			"starting":     "ISSUE24_LATE_INVALID_STARTING_CANARY",
			"valid_first":  "ISSUE24_LATE_VALID_CANARY",
			"invalid_last": "ISSUE24_LATE_INVALID_CANARY",
			"token":        "ISSUE24_LATE_INVALID_TOKEN_CANARY",
		})
		if afterBlob := cli.VaultBlob(t); !bytes.Equal(afterBlob, beforeBlob) {
			t.Fatal("late-invalid import changed the encrypted vault")
		}
		assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), starting)
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("late-invalid import %s count = %d, want 0", method, got)
			}
		}
	})

	t.Run("replace guard and expected count stop before mutation", func(t *testing.T) {
		cases := []struct {
			name string
			args func(string) []string
		}{
			{
				name: "replace without yes",
				args: func(path string) []string {
					return []string{"--offline", "--json", "import-json", path, "--replace"}
				},
			},
			{
				name: "expected count mismatch",
				args: func(path string) []string {
					return []string{
						"--offline", "--json", "import-json", path, "--merge", "--expect-count", "2",
					}
				},
			},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				cli := newCompiledCLIHarness(t)
				sync := newCompiledSyncFixture(t)
				starting := &config.Vault{Connections: []config.Connection{{
					Name: "guarded", Host: "192.0.2.36", Port: 22, User: "runner",
					Password: "ISSUE24_IMPORT_GUARD_STARTING_CANARY",
				}}}
				cli.SaveVault(t, starting)
				cli.SaveCloud(t, sync.URL(), "ISSUE24_IMPORT_GUARD_TOKEN_CANARY")
				beforeBlob := cli.VaultBlob(t)
				importPath := filepath.Join(cli.temp, "guarded-import.json")
				importBody := `[{"alias":"candidate","host":"192.0.2.37","port":22,"user":"runner","auth_type":"password","password":"ISSUE24_IMPORT_GUARD_CANDIDATE_CANARY"}]`
				if err := os.WriteFile(importPath, []byte(importBody), 0o600); err != nil {
					t.Fatal(err)
				}

				result := cli.Run(t, "ssm", nil, test.args(importPath)...)
				if result.ProcessExit == 0 {
					t.Fatalf("guarded import unexpectedly succeeded; output=%s", compiledOutputIdentity(result))
				}
				assertNoCompiledCanaryLeak(t, result, map[string]string{
					"starting":  "ISSUE24_IMPORT_GUARD_STARTING_CANARY",
					"candidate": "ISSUE24_IMPORT_GUARD_CANDIDATE_CANARY",
					"token":     "ISSUE24_IMPORT_GUARD_TOKEN_CANARY",
				})
				if afterBlob := cli.VaultBlob(t); !bytes.Equal(afterBlob, beforeBlob) {
					t.Fatal("guard or expected-count failure changed the encrypted vault")
				}
				assertCompiledVaultIdentity(t, cli.LoadVaultIdentity(t), starting)
				for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
					if got := sync.MethodCount(method); got != 0 {
						t.Fatalf("guarded import %s count = %d, want 0", method, got)
					}
				}
			})
		}
	})

	t.Run("bulk import orders surrounding mutations and preserves exact projection", func(t *testing.T) {
		cli := newCompiledCLIHarness(t)
		sync := newCompiledSyncFixture(t)
		base := config.Connection{
			Name: "base", Host: "192.0.2.50", Port: 22, User: "runner",
			Password: "ISSUE24_BULK_BASE_CANARY",
		}
		cli.SaveVault(t, &config.Vault{Connections: []config.Connection{base}})
		passwordPath := filepath.Join(cli.temp, "surrounding.password")
		password := "ISSUE24_BULK_SURROUNDING_CANARY"
		if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		priorResult := cli.Run(
			t,
			"sshctl",
			nil,
			"--offline", "--json", "host", "add", "prior",
			"--host", "192.0.2.51", "--user", "runner", "--password-file", passwordPath,
		)
		priorID := compiledTransactionID(t, assertCompiledJSONSuccess(t, priorResult), priorResult)
		importPath := filepath.Join(cli.temp, "ordered-import.json")
		importedPassword := "ISSUE24_BULK_IMPORTED_CANARY"
		importBody := `[{"alias":"imported","host":"192.0.2.52","port":22,"user":"runner","auth_type":"password","password":"` + importedPassword + `"}]`
		if err := os.WriteFile(importPath, []byte(importBody), 0o600); err != nil {
			t.Fatal(err)
		}
		importResult := cli.Run(
			t,
			"ssm",
			nil,
			"--offline", "--json", "import-json", importPath, "--merge",
		)
		importID := compiledTransactionID(t, assertCompiledJSONSuccess(t, importResult), importResult)
		laterResult := cli.Run(
			t,
			"sshctl",
			nil,
			"--offline", "--json", "host", "add", "later",
			"--host", "192.0.2.53", "--user", "runner", "--password-file", passwordPath,
		)
		laterID := compiledTransactionID(t, assertCompiledJSONSuccess(t, laterResult), laterResult)

		cli.SaveCloud(t, sync.URL(), "ISSUE24_BULK_ORDER_TOKEN_CANARY")
		rejected := cli.Run(t, "sshctl", nil, "--json", "push", "--only", laterID)
		if rejected.ProcessExit == 0 {
			t.Fatal("later host published without its bulk import and earlier prerequisite")
		}
		assertNoCompiledCanaryLeak(t, rejected, map[string]string{
			"base":     base.Password,
			"password": password,
			"imported": importedPassword,
			"token":    "ISSUE24_BULK_ORDER_TOKEN_CANARY",
		})
		priorAt := strings.Index(rejected.Stdout, priorID)
		importAt := strings.Index(rejected.Stdout, importID)
		if priorAt < 0 || importAt < 0 || priorAt >= importAt ||
			!strings.Contains(rejected.Stdout, "inventory_order") {
			t.Fatalf("bulk ordering prerequisites are missing or nondeterministic; output=%s", compiledOutputIdentity(rejected))
		}
		for _, safe := range []string{"aliases", "imported", "connections=1", "keys=0"} {
			if !strings.Contains(rejected.Stdout, safe) {
				t.Fatalf("bulk dependency preflight omitted safe metadata %q; output=%s", safe, compiledOutputIdentity(rejected))
			}
		}
		for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPut} {
			if got := sync.MethodCount(method); got != 0 {
				t.Fatalf("bulk dependency preflight %s count = %d, want 0", method, got)
			}
		}

		for _, transactionID := range []string{priorID, importID, laterID} {
			result := cli.Run(t, "sshctl", nil, "--json", "push", "--only", transactionID)
			value := assertCompiledJSONSuccess(t, result)
			assertCompiledStringField(t, value, "transaction_id", transactionID, result)
			assertNoCompiledCanaryLeak(t, result, map[string]string{
				"base":     base.Password,
				"password": password,
				"imported": importedPassword,
				"token":    "ISSUE24_BULK_ORDER_TOKEN_CANARY",
			})
		}
		prior := config.Connection{
			Name: "prior", Host: "192.0.2.51", Port: 22, User: "runner", Password: password,
		}
		imported := config.Connection{
			Name: "imported", Host: "192.0.2.52", Port: 22, User: "runner",
			Password: importedPassword, Group: "imported",
		}
		later := config.Connection{
			Name: "later", Host: "192.0.2.53", Port: 22, User: "runner", Password: password,
		}
		assertCompiledVaultIdentity(
			t,
			decodeCompiledVaultIdentity(t, sync.UploadedBlob(), cli.passphrase),
			&config.Vault{
				Connections: []config.Connection{base, imported, later, prior},
			},
		)
	})
}

func TestMutationEntryPointsNeverAutoPublish(t *testing.T) {
	type commandFixture struct {
		name  string
		setup func(*testing.T, *compiledCLIHarness) ([]byte, []string)
	}
	fixtures := []commandFixture{
		{
			name: "legacy remove",
			setup: func(t *testing.T, cli *compiledCLIHarness) ([]byte, []string) {
				cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
					Name: "legacy-remove", Host: "192.0.2.40", Port: 22, User: "runner",
					Password: "ISSUE24_NEVER_PUSH_REMOVE_CANARY",
				}}})
				return nil, []string{"--json", "remove", "legacy-remove"}
			},
		},
		{
			name: "saved-key remove",
			setup: func(t *testing.T, cli *compiledCLIHarness) ([]byte, []string) {
				cli.SaveVault(t, &config.Vault{Keys: []config.SSHKey{{
					Name: "orphan-key", PrivateKey: "ISSUE24_NEVER_PUSH_KEY_CANARY",
				}}})
				return nil, []string{"--json", "keys", "remove", "orphan-key"}
			},
		},
		{
			name: "merge import",
			setup: func(t *testing.T, cli *compiledCLIHarness) ([]byte, []string) {
				cli.SaveVault(t, &config.Vault{})
				path := filepath.Join(cli.temp, "never-push-merge.json")
				body := `[{"alias":"merged","host":"192.0.2.41","port":22,"user":"runner","auth_type":"password","password":"ISSUE24_NEVER_PUSH_MERGE_CANARY"}]`
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				return nil, []string{"--json", "import-json", path, "--merge"}
			},
		},
		{
			name: "guarded replace import",
			setup: func(t *testing.T, cli *compiledCLIHarness) ([]byte, []string) {
				cli.SaveVault(t, &config.Vault{})
				path := filepath.Join(cli.temp, "never-push-replace.json")
				body := `[{"alias":"replaced","host":"192.0.2.42","port":22,"user":"runner","auth_type":"password","password":"ISSUE24_NEVER_PUSH_REPLACE_CANARY"}]`
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				return nil, []string{"--json", "import-json", path, "--replace", "--yes"}
			},
		},
		{
			name: "ssm host remove compatibility route",
			setup: func(t *testing.T, cli *compiledCLIHarness) ([]byte, []string) {
				cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
					Name: "compat-remove", Host: "192.0.2.43", Port: 22, User: "runner",
					Password: "ISSUE24_NEVER_PUSH_COMPAT_CANARY",
				}}})
				return nil, []string{"--json", "host", "remove", "compat-remove", "--yes"}
			},
		},
		{
			name: "request v1 host remove route",
			setup: func(t *testing.T, cli *compiledCLIHarness) ([]byte, []string) {
				cli.SaveVault(t, &config.Vault{Connections: []config.Connection{{
					Name: "request-remove", Host: "192.0.2.44", Port: 22, User: "runner",
					Password: "ISSUE24_NEVER_PUSH_REQUEST_CANARY",
				}}})
				request, err := json.Marshal(map[string]any{
					"version": 1, "op": "host.remove", "alias": "request-remove",
					"host": map[string]any{"confirm": true},
				})
				if err != nil {
					t.Fatal(err)
				}
				return request, []string{"request", "-"}
			},
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			cli := newCompiledCLIHarness(t)
			sync := newCompiledSyncFixture(t)
			input, args := fixture.setup(t, cli)
			settings := config.DefaultSettings()
			settings.AutoSync = true
			settings.AutoUpdate = false
			settingsData, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			cli.writeConfigFile(t, "settings.json", settingsData)
			sync.SetRemote(t, cli.VaultBlob(t), "issue24-current")
			cli.SaveRemoteETag(t, "issue24-current")
			cli.SaveCloud(t, sync.URL(), "ISSUE24_NEVER_PUSH_TOKEN_CANARY")

			executable := "ssm"
			if fixture.name == "request v1 host remove route" {
				executable = "sshctl"
			}
			result := cli.Run(t, executable, input, args...)
			assertCompiledJSONSuccess(t, result)
			assertNoCompiledCanaryLeak(t, result, map[string]string{
				"token": "ISSUE24_NEVER_PUSH_TOKEN_CANARY",
			})
			if got := sync.MethodCount(http.MethodHead); got != 1 {
				t.Fatalf("automatic refresh HEAD count = %d, want 1", got)
			}
			for _, method := range []string{http.MethodGet, http.MethodPut} {
				if got := sync.MethodCount(method); got != 0 {
					t.Fatalf("successful mutation automatic %s count = %d, want 0", method, got)
				}
			}
			status := assertCompiledJSONSuccess(
				t,
				cli.Run(t, "sshctl", nil, "--offline", "--json", "status"),
			)
			pending, ok := status["pending_mutations"].([]any)
			if !ok || len(pending) != 1 {
				t.Fatal("successful mutation did not leave exactly one reviewable transaction")
			}
		})
	}

	t.Run("legacy command sources retain no direct-save or auto-push bypass", func(t *testing.T) {
		for _, path := range []string{"connections.go", "keys.go"} {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, forbidden := range []string{"config.Save(", "autoPushOpaque(", "AutoPushBlob("} {
				if bytes.Contains(source, []byte(forbidden)) {
					t.Fatalf("%s retains legacy mutation bypass %q", path, forbidden)
				}
			}
		}
		source, err := os.ReadFile("cloud.go")
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(source, []byte("func autoPushOpaque(")) {
			t.Fatal("command layer retains settings-driven legacy auto-push helper")
		}
		source, err = os.ReadFile(filepath.Join("..", "..", "internal", "synctransaction", "transaction.go"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(source, []byte("func (t *Transaction) AutoPushBlob(")) {
			t.Fatal("sync transaction retains the settings-driven legacy auto-push API")
		}
	})
}
