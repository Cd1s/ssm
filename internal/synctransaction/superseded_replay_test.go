package synctransaction

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

const supersededFailureMessage = "remote vault is a version this machine already replaced (possible rollback); review, then pull --adopt-remote"

type replayService struct {
	blob   atomic.Value
	head   atomic.Value
	gets   atomic.Int64
	server *httptest.Server
}

func newReplayService(t *testing.T) *replayService {
	t.Helper()
	isolateTestUserConfig(t)
	service := &replayService{}
	service.blob.Store(fakeVaultBlob("B1"))
	service.head.Store("")
	service.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(w, "test upload failed", http.StatusBadRequest)
				return
			}
			service.blob.Store(data)
		}
		data := service.blob.Load().([]byte)
		identity := opaqueIdentity(data)
		if advertised := service.head.Load().(string); r.Method == http.MethodHead && advertised != "" {
			identity = advertised
		}
		w.Header().Set("ETag", `"`+identity+`"`)
		if r.Method == http.MethodGet {
			service.gets.Add(1)
			_, _ = w.Write(data)
		}
	}))
	t.Cleanup(service.server.Close)
	configureReplayMachine(t, service)
	return service
}

func configureReplayMachine(t *testing.T, service *replayService) {
	t.Helper()
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: service.server.URL, Token: "test-token"}); err != nil {
		t.Fatal(err)
	}
}

func primeReplayMachine(t *testing.T, service *replayService) (*Transaction, []byte, []byte) {
	t.Helper()
	tx := New(Options{Now: func() time.Time { return localFirstTestNow }})
	first := service.blob.Load().([]byte)
	if err := tx.BackgroundSync(""); err != nil {
		t.Fatal(err)
	}
	second := fakeVaultBlob("B2")
	service.blob.Store(second)
	if err := tx.BackgroundSync(""); err != nil {
		t.Fatal(err)
	}
	return tx, first, second
}

func requireReplayConflict(t *testing.T, err error, local, remote []byte) {
	t.Helper()
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("replay error = %v, want ErrConflict", err)
	}
	if !bytes.Equal(readVault(t), local) || cachedRemoteIdentity() != opaqueIdentity(local) {
		t.Fatal("replay replaced the local vault or its cached remote identity")
	}
	conflict := loadConflict()
	if conflict == nil || conflict.LocalETag != opaqueIdentity(local) ||
		conflict.RemoteETag != opaqueIdentity(remote) || conflict.CachedETag != opaqueIdentity(local) {
		t.Fatalf("replay evidence = %+v", conflict)
	}
}

func TestSupersededReplayIsRefusedForPullOnlyMachine(t *testing.T) {
	service := newReplayService(t)
	t.Setenv(config.SyncModeEnv, config.SyncModeLocalFirst)
	tx, first, second := primeReplayMachine(t, service)
	before := LoadSyncState().LastSuccessAt
	tx.now = func() time.Time { return localFirstTestNow.Add(time.Minute) }
	service.blob.Store(first)
	gets := service.gets.Load()
	requireReplayConflict(t, tx.BackgroundSync(""), second, first)
	if service.gets.Load() != gets {
		t.Fatal("a superseded HEAD identity was downloaded instead of refused before GET")
	}
	state := LoadSyncState()
	if state.LastError == nil || state.LastError.Cause != CauseConflict ||
		state.LastError.Message != supersededFailureMessage || state.LastSuccessAt != before {
		t.Fatalf("replay outcome = %+v", state)
	}
	facts, err := tx.Refresh()
	if err != nil || facts.Conflict == nil || facts.LastError == nil || facts.LastError.Cause != CauseConflict {
		t.Fatalf("local-first inventory read lost the preserved conflict: facts=%+v err=%v", facts, err)
	}
	facts, err = New(Options{Offline: true}).InspectLocal()
	if err != nil || facts.Conflict == nil || !bytes.Equal(readVault(t), second) {
		t.Fatalf("offline inspection lost the conflict or retained inventory: facts=%+v err=%v", facts, err)
	}
}

func TestSupersededReplayRefusedByForegroundRefreshAndExplicitPull(t *testing.T) {
	for _, operation := range []string{"refresh", "pull"} {
		t.Run(operation, func(t *testing.T) {
			service := newReplayService(t)
			tx, first, second := primeReplayMachine(t, service)
			service.blob.Store(first)
			gets := service.gets.Load()
			var err error
			if operation == "refresh" {
				_, err = tx.Refresh()
			} else {
				_, err = tx.Pull()
			}
			requireReplayConflict(t, err, second, first)
			if service.gets.Load() != gets {
				t.Fatal("superseded remote reached GET after the HEAD decision")
			}
		})
	}
}

func TestAdoptRemoteAcceptsSupersededIdentityAndPromotesIt(t *testing.T) {
	service := newReplayService(t)
	tx, first, second := primeReplayMachine(t, service)
	service.blob.Store(first)
	requireReplayConflict(t, tx.BackgroundSync(""), second, first)
	facts, err := tx.AdoptRemote(BlobIdentity{Exists: true, Value: opaqueIdentity(first)})
	if err != nil || !facts.Changed || !bytes.Equal(readVault(t), first) {
		t.Fatalf("reviewed adoption = facts=%+v err=%v", facts, err)
	}
	if got := readSupersededLedger(t); !reflect.DeepEqual(got, []string{opaqueIdentity(second)}) {
		t.Fatalf("adoption did not promote the new head and retire the old head: %v", got)
	}
	if loadConflict() != nil {
		t.Fatal("successful adoption did not clear the conflict")
	}
	gets := service.gets.Load()
	if err := tx.BackgroundSync(""); err != nil || service.gets.Load() != gets {
		t.Fatalf("adopted head did not synchronize as a no-op: %v", err)
	}
	service.blob.Store(second)
	requireReplayConflict(t, tx.BackgroundSync(""), first, second)
}

// Known limitation: after a fresh login, an older blob never seen by this
// machine is not in its ledger and a server replay of that blob is accepted.
func TestFreshLoginReplayIsNotDetected(t *testing.T) {
	service := newReplayService(t)
	older := service.blob.Load().([]byte)
	newer := fakeVaultBlob("B2 first seen after login")
	service.blob.Store(newer)
	tx := New(Options{})
	if err := tx.BackgroundSync(""); err != nil {
		t.Fatal(err)
	}
	if isSuperseded(opaqueIdentity(older)) {
		t.Fatal("fresh login fabricated knowledge of an unseen older blob")
	}
	service.blob.Store(older)
	if err := tx.BackgroundSync(""); err != nil || !bytes.Equal(readVault(t), older) || loadConflict() != nil {
		t.Fatalf("the documented fresh-login limitation changed: %v", err)
	}
}

func TestSupersededCheckRunsAgainstFetchedEtag(t *testing.T) {
	for _, operation := range []string{"background", "refresh", "pull"} {
		t.Run(operation, func(t *testing.T) {
			service := newReplayService(t)
			tx, first, second := primeReplayMachine(t, service)
			service.blob.Store(first)
			service.head.Store(opaqueIdentity(fakeVaultBlob("new HEAD, old GET")))
			gets := service.gets.Load()
			var err error
			switch operation {
			case "background":
				err = tx.BackgroundSync("")
			case "refresh":
				_, err = tx.Refresh()
			case "pull":
				_, err = tx.Pull()
			}
			requireReplayConflict(t, err, second, first)
			if service.gets.Load() != gets+1 {
				t.Fatal("test did not exercise the downloaded identity")
			}
		})
	}
}

func TestSupersededBackgroundNeverNeedsPassword(t *testing.T) {
	service := newReplayService(t)
	t.Setenv("SSM_MASTER_PASS_FILE", "")
	tx, first, second := primeReplayMachine(t, service)
	service.blob.Store(first)
	requireReplayConflict(t, tx.BackgroundSync(""), second, first)
	if state := LoadSyncState(); state.LastError == nil || state.LastError.Cause != CauseConflict {
		t.Fatalf("password-free background refusal was not recorded: %+v", state)
	}
}

func TestSupersededConflictUsesLockedLocalIdentity(t *testing.T) {
	service := newReplayService(t)
	tx, first, _ := primeReplayMachine(t, service)
	service.blob.Store(first)
	mutated := fakeVaultBlob("saved before the decision lock")
	injectAt(t, "decision", mutated)
	if _, err := tx.Refresh(); !errors.Is(err, ErrConflict) {
		t.Fatalf("replay error = %v, want ErrConflict", err)
	}
	if evidence := loadConflict(); evidence == nil || evidence.LocalETag != opaqueIdentity(mutated) {
		t.Fatalf("conflict did not use locked local facts: %+v", evidence)
	}
	if !bytes.Equal(readVault(t), mutated) {
		t.Fatal("the concurrent local mutation was replaced")
	}
}

func TestDescribeRemoteSupersededOverridesInjectedClassifier(t *testing.T) {
	service := newReplayService(t)
	tx, first, _ := primeReplayMachine(t, service)
	called := false
	tx.describe = func(error) (string, string) {
		called = true
		return CauseUnknown, "injected classifier message"
	}
	service.blob.Store(first)
	_, replayErr := tx.Refresh()
	cause, message := tx.describeFailure(replayErr)
	if !called || cause != CauseConflict || message != supersededFailureMessage {
		t.Fatalf("final classification = (%q, %q), classifier called = %t", cause, message, called)
	}
	for _, ordinary := range []error{ErrConflict, ErrEmptyLedgerDivergence} {
		cause, message = tx.describeFailure(fmt.Errorf("wrapped: %w", ordinary))
		if cause != CauseConflict || message != "local and remote vaults diverged" {
			t.Fatalf("ordinary conflict classification changed: (%q, %q)", cause, message)
		}
	}
}

func selectReplayHome(t *testing.T, home string) {
	t.Helper()
	for _, name := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		t.Setenv(name, home)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
}
