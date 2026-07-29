package update

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"ssm/internal/cloud"
	"ssm/internal/config"
	"ssm/internal/synctransaction"
)

func TestMigrationPreflightInspectsLocalSyncStateWithoutNetwork(t *testing.T) {
	tests := []struct {
		name            string
		setup           func(*testing.T, string)
		wantStatus      string
		wantDescription string
	}{
		{
			name:            "unconfigured",
			wantStatus:      "passed",
			wantDescription: "Synchronization is unconfigured; no invalid cloud configuration was found.",
		},
		{
			name: "configured",
			setup: func(t *testing.T, serverURL string) {
				t.Helper()
				if err := cloud.SaveCloud(&cloud.CloudConfig{Server: serverURL, Token: "test-token"}); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus:      "passed",
			wantDescription: "Cloud configuration is readable and valid.",
		},
		{
			name: "invalid",
			setup: func(t *testing.T, _ string) {
				t.Helper()
				if err := config.WritePrivateFile(filepath.Join(config.Dir(), "cloud.json"), []byte("{")); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus:      "failed",
			wantDescription: "Cloud configuration is invalid or unreadable.",
		},
		{
			name: "unreadable",
			setup: func(t *testing.T, _ string) {
				t.Helper()
				if err := os.MkdirAll(config.Dir(), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(config.Dir(), "cloud.json"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus:      "failed",
			wantDescription: "Cloud configuration is invalid or unreadable.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreUpdateTestHooks(t)
			setMigrationTestHome(t)
			setMigrationTestExecutable(t)
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests.Add(1)
			}))
			defer server.Close()
			if tt.setup != nil {
				tt.setup(t, server.URL)
			}

			checks := migrationPreflight(migrationTestRelease(), "")
			configuration := migrationCheck(t, checks, "cloud_configuration")
			if configuration.Status != tt.wantStatus || configuration.Description != tt.wantDescription {
				t.Fatalf("cloud_configuration = %#v", configuration)
			}
			if divergence := migrationCheck(t, checks, "untracked_divergence"); divergence.Status != "passed" {
				t.Fatalf("untracked_divergence = %#v", divergence)
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("migration preflight sync requests = %d, want 0", got)
			}
		})
	}
}

func TestMigrationPreflightFailsForPreservedSyncConflictWithoutNetwork(t *testing.T) {
	restoreUpdateTestHooks(t)
	setMigrationTestHome(t)
	setMigrationTestExecutable(t)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		switch request.Method {
		case http.MethodHead:
			w.Header().Set("ETag", `"remote-diverged"`)
		case http.MethodPut:
			w.Header().Set("ETag", `"cached-remote"`)
		default:
			t.Fatalf("unexpected sync request method %s", request.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "test-token"}); err != nil {
		t.Fatal(err)
	}
	if _, err := synctransaction.New(synctransaction.Options{}).PushBlob([]byte("opaque baseline")); err != nil {
		t.Fatalf("establish cached remote identity: %v", err)
	}
	if _, err := synctransaction.New(synctransaction.Options{}).PushBlob([]byte("opaque candidate")); !errors.Is(err, synctransaction.ErrConflict) {
		t.Fatalf("preserve conflict error = %v, want %v", err, synctransaction.ErrConflict)
	}
	requests.Store(0)

	checks := migrationPreflight(migrationTestRelease(), "")
	if configuration := migrationCheck(t, checks, "cloud_configuration"); configuration.Status != "passed" {
		t.Fatalf("cloud_configuration = %#v", configuration)
	}
	divergence := migrationCheck(t, checks, "untracked_divergence")
	if divergence.Status != "failed" || divergence.Description != "A recorded local/remote synchronization conflict exists." {
		t.Fatalf("untracked_divergence = %#v", divergence)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("migration preflight sync requests = %d, want 0", got)
	}
}

func setMigrationTestHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
}

func setMigrationTestExecutable(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssm")
	if err := os.WriteFile(path, []byte("current executable"), 0o755); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return path, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }
}

func migrationTestRelease() Release {
	release := Release{}
	release.Assets = []struct {
		Name string `json:"name"`
	}{{Name: assetName()}}
	return release
}

func migrationCheck(t *testing.T, checks []MigrationCheck, id string) MigrationCheck {
	t.Helper()
	for _, check := range checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("migration check %q was not returned", id)
	return MigrationCheck{}
}
