package main

import (
	"net/http/httptest"
	"testing"
	"time"

	"ssm/internal/cloud"
	"ssm/internal/config"
	"ssm/internal/synctransaction"
)

func TestRefreshVaultFailureNeverSilentlyEnablesOffline(t *testing.T) {
	setTestHome(t, t.TempDir())
	server := httptest.NewServer(nil)
	url := server.URL
	server.Close()
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: url, Token: "test-token"}); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveSettings(config.DefaultSettings()); err != nil {
		t.Fatal(err)
	}

	oldOffline := offlineMode
	offlineMode = false
	t.Cleanup(func() { offlineMode = oldOffline })
	if _, err := syncTransaction(false).Refresh(); err == nil {
		t.Fatal("unreachable sync endpoint was silently ignored")
	}
	if offlineMode {
		t.Fatal("refresh failure silently enabled offline mode")
	}
}

func TestRefreshVaultExplicitOfflineSkipsNetwork(t *testing.T) {
	setTestHome(t, t.TempDir())
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: "http://127.0.0.1:1", Token: "test-token"}); err != nil {
		t.Fatal(err)
	}
	oldOffline := offlineMode
	offlineMode = true
	t.Cleanup(func() { offlineMode = oldOffline })
	if _, err := syncTransaction(false).Refresh(); err != nil {
		t.Fatalf("explicit offline refresh: %v", err)
	}
}

func TestSyncCacheAgeUsesLatestSuccessfulOperation(t *testing.T) {
	setTestHome(t, t.TempDir())
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	settings := config.DefaultSettings()
	settings.LastPull = now.Add(-10 * time.Minute).Format(time.RFC3339)
	settings.LastPush = now.Add(-2 * time.Minute).Format(time.RFC3339)
	if err := config.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	facts := synctransaction.New(synctransaction.Options{Offline: true, Now: func() time.Time { return now }}).Facts()
	if facts.LastSync != settings.LastPush || facts.CacheAge != 120 {
		t.Fatalf("last=%q age=%d", facts.LastSync, facts.CacheAge)
	}
}
