package synctransaction

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

// fakeVaultBlob has the shape of an encrypted vault (version byte, header and
// tag length) so it passes the background format check.
func fakeVaultBlob(tag string) []byte {
	return append(append([]byte{1}, bytes.Repeat([]byte{'x'}, 60)...), tag...)
}

// pullRace is a configured machine whose local vault equals the cached remote
// identity while the remote moved on.
type pullRace struct {
	gets, requests *atomic.Int64
	lockHeldAtCall *atomic.Bool
	local, remote  []byte
	remoteID       string
	mode           string
}

func newPullRace(t *testing.T, mode string, serve func(w http.ResponseWriter, r *http.Request)) *pullRace {
	t.Helper()
	isolateTestUserConfig(t)
	t.Setenv(config.SyncModeEnv, mode)
	f := &pullRace{
		gets: new(atomic.Int64), requests: new(atomic.Int64), lockHeldAtCall: new(atomic.Bool),
		local: fakeVaultBlob("local C"), remote: fakeVaultBlob("remote R"), mode: mode,
	}
	f.remoteID = opaqueIdentity(f.remote)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		// A background or explicit pull must never hold the vault write lock
		// while it talks to the sync service.
		if lock, err := config.AcquireFileLock(config.VaultWriteLockName, 20*time.Millisecond); err != nil {
			f.lockHeldAtCall.Store(true)
		} else {
			_ = lock.Close()
		}
		if serve != nil {
			serve(w, r)
			return
		}
		w.Header().Set("ETag", `"`+f.remoteID+`"`)
		if r.Method == http.MethodGet {
			f.gets.Add(1)
			_, _ = w.Write(f.remote)
		}
	}))
	t.Cleanup(server.Close)
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "test-token"}); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePrivateFile(config.Path(), f.local); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePrivateFile(remoteIdentityPath(), []byte(opaqueIdentity(f.local)+"\n")); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *pullRace) tx() *Transaction {
	return New(Options{Now: func() time.Time { return localFirstTestNow }})
}

func readVault(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(config.Path())
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// injectAt makes a concurrent local mutation land exactly at the given vault
// lock stage: after the puller decided to take the lock, before it does.
func injectAt(t *testing.T, stage string, mutated []byte) {
	t.Helper()
	beforeVaultLock = func(got string) {
		if got == stage {
			if err := config.WritePrivateFile(config.Path(), mutated); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() { beforeVaultLock = nil })
}

func assertLocalMutationSurvived(t *testing.T, f *pullRace, mutated []byte, tx *Transaction, err error) {
	t.Helper()
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want %v (fail closed)", err, ErrConflict)
	}
	if !bytes.Equal(readVault(t), mutated) {
		t.Fatal("a pull overwrote the local mutation")
	}
	if got := cachedRemoteIdentity(); got != opaqueIdentity(f.local) {
		t.Fatalf("cached remote identity %q moved although the vault was not replaced", got)
	}
	if loadConflict() == nil {
		t.Fatal("divergence evidence was not preserved")
	}
	if _, err := tx.PreparePublication(mutated); !errors.Is(err, ErrConflict) {
		t.Fatalf("publication after the race error = %v, want %v", err, ErrConflict)
	}
}

func TestPullsNeverHoldTheVaultLockAcrossNetworkIO(t *testing.T) {
	for _, mode := range []string{config.SyncModeLocalFirst, config.SyncModeStrict} {
		f := newPullRace(t, mode, nil)
		var err error
		if mode == config.SyncModeLocalFirst {
			err = f.tx().BackgroundSync()
		} else {
			_, err = f.tx().Refresh()
		}
		if err != nil {
			t.Fatalf("%s pull: %v", mode, err)
		}
		if f.lockHeldAtCall.Load() {
			t.Fatalf("%s: a sync request was made while the vault write lock was held", mode)
		}
		if !bytes.Equal(readVault(t), f.remote) {
			t.Fatalf("%s: changed remote was not pulled", mode)
		}
		if got := cachedRemoteIdentity(); got != f.remoteID {
			t.Fatalf("%s: cached remote identity %q does not match the pulled vault %q", mode, got, f.remoteID)
		}
	}
}

// A local mutation saved between an explicit sync's download and the vault
// replacement must survive: the pull fails closed as a conflict.
func TestExplicitSyncAndPullDoNotOverwriteAMutationSavedDuringTheDownload(t *testing.T) {
	mutated := fakeVaultBlob("local C plus pending mutation")
	for name, pull := range map[string]func(*Transaction) error{
		"sync": func(tx *Transaction) error { _, err := tx.Sync(); return err },
		"pull": func(tx *Transaction) error { _, err := tx.Pull(); return err },
		"refresh (strict)": func(tx *Transaction) error {
			_, err := tx.Refresh()
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPullRace(t, config.SyncModeStrict, nil)
			injectAt(t, "install", mutated)
			tx := f.tx()
			assertLocalMutationSurvived(t, f, mutated, tx, pull(tx))
			if f.lockHeldAtCall.Load() {
				t.Fatal("vault lock held across network I/O")
			}
		})
	}
}

func TestAdoptRemoteInstallsUnderTheVaultLock(t *testing.T) {
	f := newPullRace(t, config.SyncModeStrict, nil)
	// Divergent local vault plus preserved evidence, then the reviewed adoption.
	if err := config.WritePrivateFile(config.Path(), fakeVaultBlob("diverged local")); err != nil {
		t.Fatal(err)
	}
	if err := preserveConflict(SyncConflict{LocalETag: "l", RemoteETag: f.remoteID, CachedETag: opaqueIdentity(f.local)}); err != nil {
		t.Fatal(err)
	}
	lock, err := config.AcquireFileLock(config.VaultWriteLockName, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func(old time.Duration) { vaultLockWait = old }(vaultLockWait)
	vaultLockWait = 50 * time.Millisecond
	if _, err := f.tx().AdoptRemote(BlobIdentity{Exists: true, Value: f.remoteID}); !errors.Is(err, ErrRefresh) {
		t.Fatalf("adoption while the vault lock is held error = %v, want a busy refresh error", err)
	}
	_ = lock.Close()
	if _, err := f.tx().AdoptRemote(BlobIdentity{Exists: true, Value: f.remoteID}); err != nil {
		t.Fatalf("adoption failed: %v", err)
	}
	if !bytes.Equal(readVault(t), f.remote) || cachedRemoteIdentity() != f.remoteID {
		t.Fatal("adoption did not install the reviewed remote vault and identity together")
	}
}

// Divergence already visible before the download is decided without one.
func TestBackgroundSyncDivergedLocalIsNotDownloaded(t *testing.T) {
	f := newPullRace(t, config.SyncModeLocalFirst, nil)
	mutated := fakeVaultBlob("local C plus pending mutation")
	if err := config.WritePrivateFile(config.Path(), mutated); err != nil {
		t.Fatal(err)
	}
	tx := f.tx()
	assertLocalMutationSurvived(t, f, mutated, tx, tx.BackgroundSync())
	if f.gets.Load() != 0 {
		t.Fatal("a diverged vault must not be downloaded")
	}
}

func TestBackgroundSyncMutationSavedDuringDownloadIsDivergence(t *testing.T) {
	f := newPullRace(t, config.SyncModeLocalFirst, nil)
	mutated := fakeVaultBlob("local C plus pending mutation")
	injectAt(t, "install", mutated)
	tx := f.tx()
	assertLocalMutationSurvived(t, f, mutated, tx, tx.BackgroundSync())
	if state := LoadSyncState(); state.LastError == nil || state.LastError.Cause != CauseConflict {
		t.Fatalf("state = %+v, want a recorded conflict", state)
	}
}

func TestBackgroundSyncRefusesAMalformedDownload(t *testing.T) {
	f := newPullRace(t, config.SyncModeLocalFirst, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"`+opaqueIdentity([]byte("short"))+`"`)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("short"))
		}
	})
	if err := f.tx().BackgroundSync(); !errors.Is(err, ErrRefresh) {
		t.Fatalf("malformed download error = %v", err)
	}
	if !bytes.Equal(readVault(t), f.local) {
		t.Fatal("a malformed download replaced the only local copy")
	}
	if state := LoadSyncState(); state.LastError == nil || state.ConsecutiveFailures != 1 {
		t.Fatalf("failure not recorded: %+v", state)
	}
}

func TestBackgroundSyncLeavesLocalStateAloneForAPendingPublicationOrABusyLock(t *testing.T) {
	t.Run("publishing intent", func(t *testing.T) {
		f := newPullRace(t, config.SyncModeLocalFirst, nil)
		if err := config.WritePrivateFile(config.PublishingIntentPath(), []byte("{}")); err != nil {
			t.Fatal(err)
		}
		if err := f.tx().BackgroundSync(); err != nil {
			t.Fatalf("skipped attempt returned %v", err)
		}
		state := LoadSyncState()
		if !bytes.Equal(readVault(t), f.local) || state.ConsecutiveFailures != 0 || state.LastError != nil ||
			state.NextAttemptAt != localFirstTestNow.Add(skippedRetryDelay).Format(time.RFC3339) {
			t.Fatalf("intent pending: vault replaced or failure counted: %+v", state)
		}
	})
	t.Run("busy vault lock", func(t *testing.T) {
		f := newPullRace(t, config.SyncModeLocalFirst, nil)
		lock, err := config.AcquireFileLock(config.VaultWriteLockName, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Close() }()
		defer func(old time.Duration) { vaultLockWait = old }(vaultLockWait)
		vaultLockWait = 50 * time.Millisecond
		// The probe in the fake server also sees the lock as held; only the
		// outcome of the attempt matters here.
		if err := f.tx().BackgroundSync(); err != nil {
			t.Fatalf("busy attempt returned %v", err)
		}
		if state := LoadSyncState(); state.ConsecutiveFailures != 0 || !bytes.Equal(readVault(t), f.local) {
			t.Fatalf("busy lock: failure counted or vault replaced: %+v", state)
		}
	})
}

func TestStateLockDoesNotDelayForALeftoverLockFile(t *testing.T) {
	isolateTestUserConfig(t)
	if err := config.WritePrivateFile(config.Dir()+"/"+syncStateLockName, nil); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := withStateLock(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("a leftover lock file delayed the command by %s", elapsed)
	}
	// Live holders exclude each other.
	holder, err := config.AcquireFileLock(syncStateLockName, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if err := withStateLock(func() error { return nil }); !errors.Is(err, config.ErrLockBusy) {
		t.Fatalf("second holder error = %v, want ErrLockBusy", err)
	}
}

func TestErrorMessageTruncationRespectsUTF8Boundaries(t *testing.T) {
	text := ""
	for len(text) < 400 {
		text += "错误"
	}
	got := truncateUTF8(text, maxErrorMessageBytes)
	if len(got) > maxErrorMessageBytes || !utf8.ValidString(got) || len(got) < maxErrorMessageBytes-3 {
		t.Fatalf("truncated to %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
	if truncateUTF8("short", 10) != "short" {
		t.Fatal("short messages must be unchanged")
	}
}

func TestUnsyncedFactsAreReportedUntilAConfirmedSync(t *testing.T) {
	f := newPullRace(t, config.SyncModeLocalFirst, nil)
	if facts := f.tx().Facts(); !facts.Unsynced {
		t.Fatalf("a configured but never synced inventory must be unsynced: %+v", facts)
	}
	if err := f.tx().BackgroundSync(); err != nil {
		t.Fatal(err)
	}
	if facts := f.tx().Facts(); facts.Unsynced {
		t.Fatalf("a confirmed sync must clear unsynced: %+v", facts)
	}
}
