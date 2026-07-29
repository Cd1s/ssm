package inventorytransaction_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ssm/internal/config"
	"ssm/internal/inventorytransaction"
	agentssh "ssm/internal/ssh"
)

func TestInventoryTransactionPolicy(t *testing.T) {
	t.Run("apply owns stable receipt ledger and unchanged retry", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		passphrase := strings.Repeat("unlock-", 6)
		if err := config.Save(&config.Vault{}, passphrase); err != nil {
			t.Fatal(err)
		}
		password := strings.Repeat("credential-", 4)
		passwordPath := filepath.Join(t.TempDir(), "password")
		if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		address, user := "192.0.2.60", "runner"
		random := make([]byte, 16)
		for i := range random {
			random[i] = byte(i)
		}
		transaction := inventorytransaction.New(inventorytransaction.Options{
			MasterPass: passphrase,
			Now: func() time.Time {
				return time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC)
			},
			Random: bytes.NewReader(random),
		})
		change := inventorytransaction.HostChange{
			Action:       inventorytransaction.HostAdd,
			Alias:        "alpha",
			Host:         &address,
			User:         &user,
			PasswordFile: &passwordPath,
		}
		receipt, err := transaction.ApplyHost(&config.Vault{}, change)
		if err != nil {
			t.Fatal(err)
		}
		const transactionID = "tx_000102030405060708090a0b0c0d0e0f"
		if !receipt.OK || !receipt.Changed || !receipt.Applied || receipt.Pushed ||
			!receipt.SyncPending || receipt.Action != "created" ||
			receipt.TransactionID != transactionID ||
			receipt.Host.Name != "alpha" || receipt.Host.Auth != "password" {
			t.Fatalf("safe mutation receipt fields changed: %+v", receipt)
		}
		encoded, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{passphrase, password, passwordPath} {
			if strings.Contains(string(encoded), secret) {
				t.Fatal("mutation receipt exposed secret-bearing input")
			}
		}
		persisted, err := config.Load(passphrase)
		if err != nil {
			t.Fatal(err)
		}
		if len(persisted.PendingMutations) != 1 ||
			persisted.PendingMutations[0].ID != transactionID ||
			persisted.PendingBase == nil ||
			len(persisted.PendingBase.Connections) != 0 ||
			persisted.Connections[0].Password != password {
			t.Fatal("apply did not persist the compatible candidate and pending ledger")
		}

		change.Action = inventorytransaction.HostUpsert
		unchanged, err := transaction.ApplyHost(persisted, change)
		if err != nil {
			t.Fatal(err)
		}
		if unchanged.Changed || unchanged.Action != "unchanged" || unchanged.TransactionID != "" ||
			!unchanged.Applied || !unchanged.SyncPending {
			t.Fatalf("unchanged retry receipt = %+v", unchanged)
		}
		after, err := config.Load(passphrase)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(after, persisted) {
			t.Fatal("unchanged retry created or altered a pending transaction")
		}
	})

	t.Run("pending base and stable IDs are ledger invariants", func(t *testing.T) {
		connection := config.Connection{
			Name: "alpha", Host: "192.0.2.80", Port: 22, User: "runner",
			Password: strings.Repeat("invariant-material-", 3),
		}
		tests := []struct {
			name  string
			vault *config.Vault
		}{
			{
				name: "pending mutation without base",
				vault: &config.Vault{PendingMutations: []config.PendingMutation{
					{ID: "tx_alpha", Alias: "alpha", Operation: "created", After: &connection},
				}},
			},
			{
				name: "base without pending mutation",
				vault: &config.Vault{
					Connections: []config.Connection{connection},
					PendingBase: &config.InventorySnapshot{},
				},
			},
			{
				name: "duplicate stable ID",
				vault: &config.Vault{
					Connections: []config.Connection{connection},
					PendingBase: &config.InventorySnapshot{},
					PendingMutations: []config.PendingMutation{
						{ID: "tx_duplicate", Alias: "alpha", Operation: "created", After: &connection},
						{ID: "tx_duplicate", Alias: "beta", Operation: "created", After: &connection},
					},
				},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				if _, err := inventorytransaction.Preflight(test.vault, "tx_alpha"); err == nil {
					t.Fatal("invalid pending/base ledger was accepted")
				}
			})
		}
	})

	t.Run("candidate verification precedes ID and persistence", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		passphrase := strings.Repeat("verify-unlock-", 4)
		base := &config.Vault{}
		if err := config.Save(base, passphrase); err != nil {
			t.Fatal(err)
		}
		originalBlob, err := os.ReadFile(config.Path())
		if err != nil {
			t.Fatal(err)
		}
		password := strings.Repeat("verify-material-", 3)
		passwordPath := filepath.Join(t.TempDir(), "password")
		if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		address, user := "192.0.2.90", "runner"
		verifiedCandidate := false
		transaction := inventorytransaction.New(inventorytransaction.Options{
			MasterPass: passphrase,
			Random:     bytes.NewReader(nil),
			Verifier: func(connection config.Connection, candidate *config.Vault) agentssh.CheckResult {
				verifiedCandidate = connection.Password == password &&
					len(candidate.Connections) == 1 &&
					candidate.Connections[0].Password == password &&
					len(candidate.PendingMutations) == 0
				return agentssh.CheckResult{OK: false}
			},
		})
		receipt, err := transaction.ApplyHost(base, inventorytransaction.HostChange{
			Action:       inventorytransaction.HostAdd,
			Alias:        "verify-host",
			Host:         &address,
			User:         &user,
			PasswordFile: &passwordPath,
			Verify:       true,
		})
		var verificationFailure *inventorytransaction.VerificationError
		if !errors.As(err, &verificationFailure) {
			t.Fatalf("verification error type = %T", err)
		}
		if !verifiedCandidate || receipt.TransactionID != "" || receipt.Applied ||
			receipt.Verification == nil || receipt.Verification.OK {
			t.Fatal("verification did not observe the complete unpersisted candidate before ID generation")
		}
		afterBlob, err := os.ReadFile(config.Path())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(afterBlob, originalBlob) {
			t.Fatal("failed candidate verification changed the encrypted vault")
		}
	})
}
