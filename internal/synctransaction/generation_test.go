package synctransaction

import (
	"errors"
	"os"
	"testing"

	"ssm/internal/config"
	"ssm/internal/vault"
)

func TestInstallFetchedRejectsLowerGenerationAndAdoptResetsHighWaterMark(t *testing.T) {
	isolateTestUserConfig(t)
	pass := "generation-test-pass"
	local, err := vault.Encrypt([]byte("local"), pass, 3)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := vault.Encrypt([]byte("remote"), pass, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.WritePrivateFile(config.Path(), local); err != nil {
		t.Fatal(err)
	}
	config.RecordMaxSeenGeneration(3)
	tx := New(Options{MasterPass: pass})
	_, err = tx.installFetched(remote, opaqueIdentity(remote), pullBackground)
	if !errors.Is(err, errRemoteSuperseded) {
		t.Fatalf("lower generation error = %v, want errRemoteSuperseded", err)
	}
	got, readErr := os.ReadFile(config.Path())
	if readErr != nil || string(got) != string(local) {
		t.Fatalf("local vault changed after refusal")
	}
	if err := preserveConflict(SyncConflict{LocalETag: opaqueIdentity(local), RemoteETag: opaqueIdentity(remote)}); err != nil {
		t.Fatal(err)
	}
	_, err = tx.installFetched(remote, opaqueIdentity(remote), pullAdopt)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if got := config.MaxSeenGeneration(); got != 2 {
		t.Fatalf("max seen after adopt = %d, want 2", got)
	}
}

func TestGenerationLedgerCorruptFailsOpenAndResetClears(t *testing.T) {
	isolateTestUserConfig(t)
	if err := config.WritePrivateFile(config.GenerationPath(), []byte("not-json\n")); err != nil {
		t.Fatal(err)
	}
	if got := config.MaxSeenGeneration(); got != 0 {
		t.Fatalf("corrupt ledger = %d, want 0", got)
	}
	config.RecordMaxSeenGeneration(4)
	if got := config.MaxSeenGeneration(); got != 4 {
		t.Fatalf("recorded generation = %d, want 4", got)
	}
	if err := ResetSyncState(); err != nil {
		t.Fatal(err)
	}
	if got := config.MaxSeenGeneration(); got != 0 {
		t.Fatalf("reset generation = %d, want 0", got)
	}
}

func TestCommitSuccessRecordsLocalGeneration(t *testing.T) {
	isolateTestUserConfig(t)
	blob, err := vault.Encrypt([]byte("published"), "pass", 9)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.WritePrivateFile(config.Path(), blob); err != nil {
		t.Fatal(err)
	}
	New(Options{}).commitSuccess("push", opaqueIdentity(blob))
	if got := config.MaxSeenGeneration(); got != 9 {
		t.Fatalf("max seen after commit = %d, want 9", got)
	}
}
