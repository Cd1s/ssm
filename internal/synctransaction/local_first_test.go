package synctransaction

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

var localFirstTestNow = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

func localFirstSetup(t *testing.T) (requests *atomic.Int64, opts Options, spawned *atomic.Int64) {
	t.Helper()
	isolateTestUserConfig(t)
	t.Setenv(config.SyncModeEnv, config.SyncModeLocalFirst)
	requests, spawned = new(atomic.Int64), new(atomic.Int64)
	handler := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "test-token"}); err != nil {
		t.Fatal(err)
	}
	opts = Options{
		Now:             func() time.Time { return localFirstTestNow },
		SpawnBackground: func() error { spawned.Add(1); return nil },
	}
	return requests, opts, spawned
}

func TestLocalFirstRefreshNeverContactsTheServiceAndSpawnsOnceWhenDue(t *testing.T) {
	requests, opts, spawned := localFirstSetup(t)
	tx := New(opts)
	facts, err := tx.Refresh()
	if err != nil {
		t.Fatalf("local_first refresh failed: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("local_first refresh made %d requests, want 0", requests.Load())
	}
	if spawned.Load() != 1 {
		t.Fatalf("spawned = %d, want 1 when due", spawned.Load())
	}
	if facts.Remote != RemoteNotChecked {
		t.Fatalf("remote state = %q, want not_checked before any background result", facts.Remote)
	}
	if _, err := tx.Refresh(); err != nil || spawned.Load() != 1 {
		t.Fatalf("second refresh spawned again while a claim is live: spawned=%d err=%v", spawned.Load(), err)
	}
	if LoadSyncState().InFlightUntil == "" {
		t.Fatal("claim was not recorded in sync-state.json")
	}
}

func TestLocalFirstClaimIsAtomicAcrossConcurrentCommands(t *testing.T) {
	_, opts, spawned := localFirstSetup(t)
	var wait sync.WaitGroup
	for i := 0; i < 24; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = New(opts).Refresh()
		}()
	}
	wait.Wait()
	if spawned.Load() != 1 {
		t.Fatalf("concurrent commands spawned %d background processes, want exactly 1", spawned.Load())
	}
}

func TestLocalFirstDoesNotSpawnWhenOfflineDisabledOrNotConfigured(t *testing.T) {
	t.Run("offline", func(t *testing.T) {
		_, opts, spawned := localFirstSetup(t)
		opts.Offline = true
		if _, err := New(opts).Refresh(); err != nil || spawned.Load() != 0 {
			t.Fatalf("offline spawned=%d err=%v", spawned.Load(), err)
		}
	})
	t.Run("auto_sync false", func(t *testing.T) {
		_, opts, spawned := localFirstSetup(t)
		settings := config.LoadSettings()
		settings.AutoSync = false
		if err := config.SaveSettings(settings); err != nil {
			t.Fatal(err)
		}
		facts, err := New(opts).Refresh()
		if err != nil || spawned.Load() != 0 || facts.Remote != RemoteAutoSyncDisabled {
			t.Fatalf("auto_sync=false spawned=%d remote=%q err=%v", spawned.Load(), facts.Remote, err)
		}
	})
	t.Run("not configured", func(t *testing.T) {
		_, opts, spawned := localFirstSetup(t)
		if err := cloud.DeleteCloud(); err != nil {
			t.Fatal(err)
		}
		facts, err := New(opts).Refresh()
		if err != nil || spawned.Load() != 0 || facts.Remote != RemoteNotConfigured {
			t.Fatalf("unconfigured spawned=%d remote=%q err=%v", spawned.Load(), facts.Remote, err)
		}
	})
}

func TestLocalFirstSpawnFailureReleasesTheClaim(t *testing.T) {
	_, opts, spawned := localFirstSetup(t)
	opts.SpawnBackground = func() error { spawned.Add(1); return errors.New("spawn refused") }
	tx := New(opts)
	if _, err := tx.Refresh(); err != nil {
		t.Fatalf("spawn failure must not fail the command: %v", err)
	}
	if _, err := tx.Refresh(); err != nil || spawned.Load() != 2 {
		t.Fatalf("claim was not released after a failed spawn: spawned=%d err=%v", spawned.Load(), err)
	}
}

func TestBackgroundSyncRecordsFailureCauseAndExponentialBackoff(t *testing.T) {
	requests, opts, _ := localFirstSetup(t)
	opts.DescribeFailure = func(err error) (string, string) {
		var status *HTTPStatusError
		if errors.As(err, &status) && status.StatusCode == http.StatusServiceUnavailable {
			return "http_5xx", "server error (503)"
		}
		return "", ""
	}
	tx := New(opts)
	for failures, want := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute} {
		if err := tx.BackgroundSync(); err == nil {
			t.Fatal("background sync against a 503 endpoint returned no error")
		}
		state := LoadSyncState()
		if state.ConsecutiveFailures != failures+1 ||
			state.NextAttemptAt != localFirstTestNow.Add(want).Format(time.RFC3339) ||
			state.LastError == nil || state.LastError.Cause != "http_5xx" || state.InFlightUntil != "" {
			t.Fatalf("after %d failures state = %+v", failures+1, state)
		}
	}
	if requests.Load() != 4 {
		t.Fatalf("requests = %d, want one HEAD per attempt", requests.Load())
	}
	if got := backoffDelay(40); got != time.Hour {
		t.Fatalf("backoff cap = %s, want 1h", got)
	}
}

func TestBackgroundSyncSuccessSchedulesTheNextAttemptAndClearsFailures(t *testing.T) {
	_, opts, _ := localFirstSetup(t)
	if err := saveSyncState(SyncState{
		ConsecutiveFailures: 4, LastError: &SyncError{Cause: "network", Message: "x", At: "2026-08-01T11:00:00Z"},
	}); err != nil {
		t.Fatal(err)
	}
	requests := new(atomic.Int64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", `"`+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+`"`)
	}))
	t.Cleanup(server.Close)
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "test-token"}); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePrivateFile(remoteIdentityPath(), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")); err != nil {
		t.Fatal(err)
	}
	if err := New(opts).BackgroundSync(); err != nil {
		t.Fatalf("background sync failed: %v", err)
	}
	state := LoadSyncState()
	if state.LastSuccessAt != localFirstTestNow.Format(time.RFC3339) ||
		state.NextAttemptAt != localFirstTestNow.Add(config.DefaultSyncInterval).Format(time.RFC3339) ||
		state.ConsecutiveFailures != 0 || state.LastError != nil {
		t.Fatalf("success state = %+v", state)
	}
	if requests.Load() != 1 {
		t.Fatalf("unchanged remote took %d requests, want a single HEAD", requests.Load())
	}
}

func TestLocalFirstStatusFactsReportRecordedOutcomeAndStaleness(t *testing.T) {
	_, opts, _ := localFirstSetup(t)
	settings := config.LoadSettings()
	settings.LastPull = localFirstTestNow.Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	if err := config.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	if err := saveSyncState(SyncState{
		ConsecutiveFailures: 2, NextAttemptAt: "2026-08-01T13:00:00Z",
		LastError: &SyncError{Cause: "dns", Message: "dns lookup failed", At: "2026-08-01T11:59:00Z"},
	}); err != nil {
		t.Fatal(err)
	}
	facts := New(opts).Facts()
	if facts.Remote != RemoteUnreachable || facts.LastError == nil || facts.LastError.Cause != "dns" ||
		facts.NextAttempt != "2026-08-01T13:00:00Z" || !facts.Stale || facts.CacheAge != 8*24*3600 {
		t.Fatalf("facts = %+v", facts)
	}
	settings.StaleAfter = "9d"
	if err := config.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	if New(opts).Facts().Stale {
		t.Fatal("stale_after=9d must not mark an eight day old cache stale")
	}
}

func TestLocalFirstStreamReloadsAfterTheVaultChangesUnderneathIt(t *testing.T) {
	_, opts, _ := localFirstSetup(t)
	if err := os.MkdirAll(config.Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.Path(), []byte("opaque vault one"), 0o600); err != nil {
		t.Fatal(err)
	}
	var invalidated atomic.Int64
	opts.Invalidate = func() { invalidated.Add(1) }
	opts.Now = time.Now
	stream, err := New(opts).BeginStream(time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Initialize(); err != nil {
		t.Fatal(err)
	}
	facts, err := stream.BeforeLine()
	if err != nil || facts.Changed || invalidated.Load() != 0 {
		t.Fatalf("unchanged vault: facts=%+v err=%v invalidated=%d", facts, err, invalidated.Load())
	}
	if err := os.WriteFile(config.Path(), []byte("opaque vault two"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	facts, err = stream.BeforeLine()
	if err != nil || !facts.Changed || invalidated.Load() != 1 {
		t.Fatalf("changed vault: facts=%+v err=%v invalidated=%d", facts, err, invalidated.Load())
	}
}

func TestStrictModeKeepsRefreshBeforeRead(t *testing.T) {
	requests, opts, spawned := localFirstSetup(t)
	t.Setenv(config.SyncModeEnv, config.SyncModeStrict)
	if _, err := New(opts).Refresh(); !errors.Is(err, ErrRefresh) {
		t.Fatalf("strict refresh error = %v, want %v", err, ErrRefresh)
	}
	if requests.Load() != 1 || spawned.Load() != 0 {
		t.Fatalf("strict requests=%d spawned=%d, want 1 foreground request and no spawn", requests.Load(), spawned.Load())
	}
	if _, err := os.Stat(syncStatePath()); !os.IsNotExist(err) {
		t.Fatalf("strict mode wrote sync-state.json: %v", err)
	}
}

func TestSyncSettingsDefaultsAndParsing(t *testing.T) {
	isolateTestUserConfig(t)
	t.Setenv(config.SyncModeEnv, "")
	defaults := config.DefaultSettings()
	if defaults.EffectiveSyncMode() != config.SyncModeLocalFirst ||
		defaults.EffectiveSyncInterval() != 10*time.Minute ||
		defaults.EffectiveStaleAfter() != 7*24*time.Hour {
		t.Fatalf("defaults = %s/%s/%s", defaults.EffectiveSyncMode(), defaults.EffectiveSyncInterval(), defaults.EffectiveStaleAfter())
	}
	if err := config.WritePrivateFile(config.Dir()+"/settings.json", []byte(`{"sync_mode":"strict","sync_interval":"90s","stale_after":"3d"}`)); err != nil {
		t.Fatal(err)
	}
	loaded := config.LoadSettings()
	if loaded.EffectiveSyncMode() != config.SyncModeStrict || loaded.EffectiveSyncInterval() != 90*time.Second ||
		loaded.EffectiveStaleAfter() != 72*time.Hour {
		t.Fatalf("loaded = %s/%s/%s", loaded.EffectiveSyncMode(), loaded.EffectiveSyncInterval(), loaded.EffectiveStaleAfter())
	}
	loaded.SyncInterval, loaded.StaleAfter = "garbage", "-1h"
	if loaded.EffectiveSyncInterval() != 10*time.Minute || loaded.EffectiveStaleAfter() != 7*24*time.Hour {
		t.Fatal("invalid durations must fall back to defaults")
	}
	if err := config.SaveSettings(config.LoadSettings()); err != nil {
		t.Fatal(err)
	}
	reloaded := config.LoadSettings()
	if reloaded.SyncMode != config.SyncModeStrict || reloaded.SyncInterval != "90s" {
		t.Fatalf("saving settings dropped sync fields: %+v", reloaded)
	}
}

func TestImplausibleScheduleDoesNotDisableSyncForever(t *testing.T) {
	_, opts, spawned := localFirstSetup(t)
	if err := saveSyncState(SyncState{
		NextAttemptAt: localFirstTestNow.Add(365 * 24 * time.Hour).Format(time.RFC3339),
		InFlightUntil: localFirstTestNow.Add(24 * time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(opts).Refresh(); err != nil || spawned.Load() != 1 {
		t.Fatalf("a schedule a year away must be ignored: spawned=%d err=%v", spawned.Load(), err)
	}
}
