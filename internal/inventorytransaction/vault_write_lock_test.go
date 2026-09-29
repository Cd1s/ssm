package inventorytransaction_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ssm/internal/config"
	"ssm/internal/inventorytransaction"
)

func hostAddChange(t *testing.T) inventorytransaction.HostChange {
	t.Helper()
	alias := "added"
	address, user := alias+".example", "root"
	password := filepath.Join(t.TempDir(), "host.password")
	if err := os.WriteFile(password, []byte("VAULT_LOCK_TEST_PASSWORD\n"), 0o600); err != nil { //nolint:gosec // test-only fake credential canary
		t.Fatal(err)
	}
	return inventorytransaction.HostChange{
		Action: inventorytransaction.HostAdd, Alias: alias, Host: &address, User: &user, PasswordFile: &password,
	}
}

// A vault replaced after the command loaded it (a background pull) must never
// be overwritten by that command's save.
func TestMutationRefusesToOverwriteAVaultReplacedAfterItWasLoaded(t *testing.T) {
	base := &config.Vault{Connections: []config.Connection{{Name: "local", Host: "local.example", Port: 22, User: "root"}}}
	transaction, passphrase := newHostPolicyFixture(t, base)
	loaded := loadHostPolicyVault(t, passphrase)

	pulled := &config.Vault{Connections: []config.Connection{
		{Name: "local", Host: "local.example", Port: 22, User: "root"},
		{Name: "pulled", Host: "pulled.example", Port: 22, User: "root"},
	}}
	pulledBlob, err := config.EncryptVault(pulled, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.WritePrivateFile(config.Path(), pulledBlob); err != nil { // what the background pull does
		t.Fatal(err)
	}

	_, err = transaction.ApplyHost(loaded, hostAddChange(t))
	if err == nil || !strings.Contains(err.Error(), "vault changed while this command was running") {
		t.Fatalf("mutation over a replaced vault error = %v", err)
	}
	onDisk, readErr := os.ReadFile(config.Path())
	if readErr != nil || !bytes.Equal(onDisk, pulledBlob) {
		t.Fatal("the pulled vault was overwritten by a stale mutation")
	}

	reloaded := loadHostPolicyVault(t, passphrase)
	if _, err := transaction.ApplyHost(reloaded, hostAddChange(t)); err != nil {
		t.Fatalf("retry after reloading failed: %v", err)
	}
	final := loadHostPolicyVault(t, passphrase)
	names := map[string]bool{}
	for _, connection := range final.Connections {
		names[connection.Name] = true
	}
	if !names["pulled"] || !names["added"] || len(final.PendingMutations) != 1 {
		t.Fatalf("retry lost the pulled host or the pending mutation: %v %d", names, len(final.PendingMutations))
	}
}

func TestMutationWaitIsBoundedAndReportsABusyVaultLock(t *testing.T) {
	transaction, passphrase := newHostPolicyFixture(t, &config.Vault{})
	loaded := loadHostPolicyVault(t, passphrase)
	defer inventorytransaction.SetMutationLockWait(100 * time.Millisecond)()

	holder, err := inventorytransaction.BeginVaultWrite()
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = transaction.ApplyHost(loaded, hostAddChange(t))
	if err == nil || !strings.Contains(err.Error(), "vault is busy") {
		t.Fatalf("busy mutation error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("mutation waited %s for the lock", elapsed)
	}
	if got := loadHostPolicyVault(t, passphrase); len(got.PendingMutations) != 0 {
		t.Fatal("a busy mutation changed the vault")
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.ApplyHost(loadHostPolicyVault(t, passphrase), hostAddChange(t)); err != nil {
		t.Fatalf("mutation after the lock was released failed: %v", err)
	}
}

// A mutation must stay possible while a publication is in flight: only the
// short vault write lock serialises it, not the publication lock.
func TestMutationIsNotBlockedByAnInFlightPublication(t *testing.T) {
	transaction, passphrase := newHostPolicyFixture(t, &config.Vault{})
	loaded := loadHostPolicyVault(t, passphrase)
	defer inventorytransaction.SetMutationLockWait(100 * time.Millisecond)()
	publication, err := inventorytransaction.BeginPublication()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publication.Close() }()
	if _, err := transaction.ApplyHost(loaded, hostAddChange(t)); err != nil {
		t.Fatalf("mutation during publication failed: %v", err)
	}
}
