package synctransaction

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ssm/internal/config"
)

const pullValidationPass = "pull-validation-pass"

func pullValidationTx() *Transaction {
	return New(Options{MasterPass: pullValidationPass, Now: func() time.Time { return localFirstTestNow }})
}

func setPullValidationBlobs(t *testing.T, f *pullRace, local, remote []byte) {
	t.Helper()
	f.remote = remote
	f.remoteID = opaqueIdentity(remote)
	if err := config.WritePrivateFile(config.Path(), local); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePrivateFile(remoteIdentityPath(), []byte(opaqueIdentity(local)+"\n")); err != nil {
		t.Fatal(err)
	}
}

func TestPullValidationRejectsOneByteAndPreservesVault(t *testing.T) {
	f := newPullRace(t, config.SyncModeStrict, nil)
	old := readVault(t)
	f.remote = []byte{1}
	_, err := pullValidationTx().Pull()
	if err == nil {
		t.Fatal("Pull accepted a one-byte vault")
	}
	if got := readVault(t); !bytes.Equal(got, old) {
		t.Fatalf("vault changed after malformed pull: %x", got)
	}
}

func TestPullValidationRejectsUnauthenticatedShapeAndPreservesVault(t *testing.T) {
	f := newPullRace(t, config.SyncModeStrict, nil)
	old := readVault(t)
	f.remote = fakeVaultBlob("random garbage")
	_, err := pullValidationTx().Pull()
	if err == nil {
		t.Fatal("Pull accepted an unauthenticated vault-shaped blob")
	}
	if got := readVault(t); !bytes.Equal(got, old) {
		t.Fatalf("vault changed after unauthenticated pull: %x", got)
	}
}

func TestPullValidationBackgroundKeepsPreviousVault(t *testing.T) {
	f := newPullRace(t, config.SyncModeLocalFirst, nil)
	old := readVault(t)
	if err := f.tx().BackgroundSync(""); err != nil {
		t.Fatalf("BackgroundSync: %v", err)
	}
	previous, err := os.ReadFile(config.Path() + ".prev")
	if err != nil {
		t.Fatalf("read previous vault: %v", err)
	}
	if !bytes.Equal(previous, old) {
		t.Fatal(".prev does not contain the replaced vault")
	}
}

func TestPullValidationInstallsValidVaultAndKeepsPrevious(t *testing.T) {
	f := newPullRace(t, config.SyncModeStrict, nil)
	local, err := config.EncryptVault(&config.Vault{}, pullValidationPass)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := config.EncryptVault(&config.Vault{Connections: []config.Connection{{Name: "new"}}}, pullValidationPass)
	if err != nil {
		t.Fatal(err)
	}
	setPullValidationBlobs(t, f, local, remote)
	if _, err := pullValidationTx().Pull(); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if got := readVault(t); !bytes.Equal(got, remote) {
		t.Fatal("valid remote vault was not installed")
	}
	previous, err := os.ReadFile(config.Path() + ".prev")
	if err != nil {
		t.Fatalf("read previous vault: %v", err)
	}
	if !bytes.Equal(previous, local) {
		t.Fatal(".prev does not contain the old vault")
	}
	if info, err := os.Stat(config.Path() + ".prev"); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf(".prev permissions = %v, want 0600", info.Mode().Perm())
	}
}

func TestPullValidationFirstInstallHasNoPrevious(t *testing.T) {
	f := newPullRace(t, config.SyncModeStrict, nil)
	remote, err := config.EncryptVault(&config.Vault{}, pullValidationPass)
	if err != nil {
		t.Fatal(err)
	}
	f.remote = remote
	f.remoteID = opaqueIdentity(remote)
	if err := os.Remove(config.Path()); err != nil {
		t.Fatal(err)
	}
	if _, err := pullValidationTx().Pull(); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if _, err := os.Stat(config.Path() + ".prev"); !os.IsNotExist(err) {
		t.Fatalf("unexpected .prev: %v", err)
	}
}

func TestPullValidationPreviousWriteFailurePreservesVault(t *testing.T) {
	f := newPullRace(t, config.SyncModeStrict, nil)
	old := readVault(t)
	if err := os.Mkdir(config.Path()+".prev", 0700); err != nil {
		t.Fatal(err)
	}
	f.remote = fakeVaultBlob("new remote")
	_, err := pullValidationTx().Pull()
	if err == nil {
		t.Fatal("Pull succeeded when .prev was a directory")
	}
	if got := readVault(t); !bytes.Equal(got, old) {
		t.Fatal("vault changed after .prev write failure")
	}
	_ = os.RemoveAll(filepath.Clean(config.Path() + ".prev"))
}
