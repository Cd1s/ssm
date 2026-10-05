package synctransaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"ssm/internal/config"
)

func ledgerPathForTest() string {
	return filepath.Join(config.Dir(), "sync-superseded.json")
}

func readSupersededLedger(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(ledgerPathForTest()) //nolint:gosec // isolated test config directory, never the user's ledger
	if err != nil {
		t.Fatal(err)
	}
	var ledger struct {
		Superseded []string `json:"superseded"`
	}
	if err := json.Unmarshal(data, &ledger); err != nil {
		t.Fatal(err)
	}
	return ledger.Superseded
}

func writeLedgerForTest(t *testing.T, identities ...string) {
	t.Helper()
	data, err := json.Marshal(map[string][]string{"superseded": identities})
	if err != nil {
		t.Fatal(err)
	}
	if err := config.WritePrivateFile(ledgerPathForTest(), data); err != nil {
		t.Fatal(err)
	}
}

func TestCommitSuccessRecordsSupersededIdentity(t *testing.T) {
	for _, operation := range []string{"pull", "push"} {
		t.Run(operation, func(t *testing.T) {
			isolateTestUserConfig(t)
			tx := New(Options{})
			old := opaqueIdentity(fakeVaultBlob("old"))
			next := opaqueIdentity(fakeVaultBlob("next"))
			tx.commitSuccess(operation, old)
			tx.commitSuccess(operation, next)
			tx.commitSuccess(operation, next)
			if got := readSupersededLedger(t); !reflect.DeepEqual(got, []string{old}) {
				t.Fatalf("ledger = %v, want only the superseded head %s", got, old)
			}
			info, err := os.Stat(ledgerPathForTest())
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
				t.Fatalf("ledger permissions = %o, want 600", info.Mode().Perm())
			}
		})
	}
}

func TestLedgerIsBoundedAt64AndEvictsOldest(t *testing.T) {
	isolateTestUserConfig(t)
	tx := New(Options{})
	identities := make([]string, 67)
	for index := range identities {
		identities[index] = opaqueIdentity(fakeVaultBlob(fmt.Sprint(index)))
		tx.commitSuccess("pull", identities[index])
	}
	if got, want := readSupersededLedger(t), identities[2:66]; !reflect.DeepEqual(got, want) {
		t.Fatalf("ledger length = %d, want 64 with the oldest two identities evicted", len(got))
	}
}

func TestLedgerDedupAndRemovesIdentityWhenItBecomesHeadAgain(t *testing.T) {
	isolateTestUserConfig(t)
	tx := New(Options{})
	first := opaqueIdentity(fakeVaultBlob("first"))
	second := opaqueIdentity(fakeVaultBlob("second"))
	third := opaqueIdentity(fakeVaultBlob("third"))
	tx.commitSuccess("pull", first)
	writeLedgerForTest(t, first, second)
	tx.commitSuccess("pull", second)
	if got := readSupersededLedger(t); !reflect.DeepEqual(got, []string{first}) {
		t.Fatalf("deduplicated ledger = %v, want [%s]", got, first)
	}
	tx.commitSuccess("pull", third)
	tx.commitSuccess("pull", first)
	if got := readSupersededLedger(t); !reflect.DeepEqual(got, []string{second, third}) {
		t.Fatalf("promoted identity remains superseded: %v", got)
	}
}

func TestResetSyncStateClearsLedger(t *testing.T) {
	for _, hasState := range []bool{true, false} {
		t.Run(fmt.Sprintf("state-present=%t", hasState), func(t *testing.T) {
			isolateTestUserConfig(t)
			writeLedgerForTest(t, opaqueIdentity(fakeVaultBlob("old-account")))
			if hasState {
				if err := saveSyncState(SyncState{ConsecutiveFailures: 1}); err != nil {
					t.Fatal(err)
				}
			}
			if err := ResetSyncState(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(ledgerPathForTest()); !os.IsNotExist(err) {
				t.Fatalf("reset retained the previous account's ledger: %v", err)
			}
		})
	}
}

func TestCorruptOrMissingLedgerFailsOpen(t *testing.T) {
	for _, fault := range []string{"missing", "corrupt", "unwritable"} {
		t.Run(fault, func(t *testing.T) {
			isolateTestUserConfig(t)
			tx := New(Options{})
			local := fakeVaultBlob("local")
			remote := fakeVaultBlob("remote")
			if err := config.WritePrivateFile(config.Path(), local); err != nil {
				t.Fatal(err)
			}
			tx.commitSuccess("pull", opaqueIdentity(local))
			switch fault {
			case "corrupt":
				if err := config.WritePrivateFile(ledgerPathForTest(), []byte("{broken")); err != nil {
					t.Fatal(err)
				}
			case "unwritable":
				replacePathWithDirectory(t, ledgerPathForTest())
			}
			if _, err := tx.installFetched(remote, opaqueIdentity(remote), pullRefresh); err != nil {
				t.Fatalf("ledger fault blocked a confirmed pull: %v", err)
			}
			if !bytes.Equal(readVault(t), remote) || cachedRemoteIdentity() != opaqueIdentity(remote) {
				t.Fatal("ledger fault prevented the vault or cached identity from committing")
			}
			if fault != "unwritable" {
				if got := readSupersededLedger(t); !reflect.DeepEqual(got, []string{opaqueIdentity(local)}) {
					t.Fatalf("ledger did not recover from %s: %v", fault, got)
				}
			}
		})
	}
}
