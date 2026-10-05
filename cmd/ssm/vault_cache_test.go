package main

import (
	"os"
	"path/filepath"
	"testing"

	"ssm/internal/config"
	"ssm/internal/inventorytransaction"
)

func prepareUnlockedVaultForCacheTest(t *testing.T, vault *config.Vault) (string, *config.Vault) {
	t.Helper()
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("SSM_CONFIG_DIR", filepath.Join(home, ".config", "ssm"))
	const pass = "status-cache-test-pass"
	if err := config.Save(vault, pass); err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(t.TempDir(), "master.pass")
	if err := os.WriteFile(passFile, []byte(pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldPass, oldPassFile, oldVault, oldOffline := masterPass, masterPassFile, unlockedVault, offlineMode
	oldIdentity, oldIdentityKnown := unlockedVaultIdentity, unlockedVaultIdentityKnown
	t.Cleanup(func() {
		masterPass, masterPassFile, unlockedVault, offlineMode = oldPass, oldPassFile, oldVault, oldOffline
		unlockedVaultIdentity, unlockedVaultIdentityKnown = oldIdentity, oldIdentityKnown
	})
	masterPassFile = passFile
	offlineMode = true
	if failure, failed := unlockVault(); failed {
		t.Fatalf("unlock failed: %+v", failure)
	}
	return pass, unlockedVault
}

func TestStatusKeepsUnlockedVaultWhenFileUnchangedAfterReconcile(t *testing.T) {
	_, snapshot := prepareUnlockedVaultForCacheTest(t, &config.Vault{Connections: []config.Connection{{Name: "before"}}})
	if snapshot == nil {
		t.Fatal("unlock did not cache a vault")
	}
	if _, err := inventorytransaction.New(inventorytransaction.Options{
		MasterPass: masterPass,
		Sync:       syncTransaction(false),
	}).ReconcilePublishingIntent(); err != nil {
		t.Fatal(err)
	}
	if !unlockedVaultStillCurrent() {
		invalidateVaultCache()
	}
	loaded, err := loadVault()
	if err != nil {
		t.Fatal(err)
	}
	if loaded != snapshot {
		t.Fatalf("loadVault returned a different snapshot: got %p want %p", loaded, snapshot)
	}
}

func TestStatusReloadsVaultAfterAtomicReplacement(t *testing.T) {
	pass, snapshot := prepareUnlockedVaultForCacheTest(t, &config.Vault{Connections: []config.Connection{{Name: "before"}}})
	if snapshot == nil {
		t.Fatal("unlock did not cache a vault")
	}
	if _, err := inventorytransaction.New(inventorytransaction.Options{
		MasterPass: masterPass,
		Sync:       syncTransaction(false),
	}).ReconcilePublishingIntent(); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(&config.Vault{
		Connections:      []config.Connection{{Name: "before"}},
		PendingMutations: []config.PendingMutation{{ID: "pending-after-replace", Alias: "new", Operation: "add"}},
	}, pass); err != nil {
		t.Fatal(err)
	}
	if unlockedVaultStillCurrent() {
		t.Fatal("replaced vault was considered current")
	}
	if !unlockedVaultStillCurrent() {
		invalidateVaultCache()
	}
	loaded, err := loadVault()
	if err != nil {
		t.Fatal(err)
	}
	if loaded == snapshot || len(loaded.PendingMutations) != 1 || loaded.PendingMutations[0].ID != "pending-after-replace" {
		t.Fatalf("loadVault after replacement = %+v", loaded)
	}
}
