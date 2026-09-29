package config

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestCreateVaultIfAbsentNeverReplacesAnExistingVault(t *testing.T) {
	setTestHome(t, t.TempDir())
	created, err := CreateVaultIfAbsent(&Vault{}, "master-pass")
	if err != nil || !created {
		t.Fatalf("first creation: created=%v err=%v", created, err)
	}
	// A pull lands after the caller decided the vault was absent.
	pulled := []byte("opaque pulled vault")
	if err := WritePrivateFile(Path(), pulled); err != nil {
		t.Fatal(err)
	}
	created, err = CreateVaultIfAbsent(&Vault{}, "master-pass")
	if err != nil || created {
		t.Fatalf("second creation: created=%v err=%v, want no-op", created, err)
	}
	if data, _ := os.ReadFile(Path()); !bytes.Equal(data, pulled) {
		t.Fatal("an existing vault was overwritten by the initial empty vault")
	}
}

func TestCreateVaultIfAbsentWaitsForTheVaultWriteLockAndReportsBusy(t *testing.T) {
	setTestHome(t, t.TempDir())
	defer func(old time.Duration) { vaultCreateLockWait = old }(vaultCreateLockWait)
	vaultCreateLockWait = 50 * time.Millisecond
	holder, err := AcquireFileLock(VaultWriteLockName, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if created, err := CreateVaultIfAbsent(&Vault{}, "master-pass"); err == nil || created {
		t.Fatalf("creation under a held lock: created=%v err=%v", created, err)
	}
	if _, err := os.Stat(Path()); !os.IsNotExist(err) {
		t.Fatal("a vault was written without the lock")
	}
}
