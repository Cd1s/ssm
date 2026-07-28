package synctransaction

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

func TestInspectLocalConfigurationStatesWithoutNetwork(t *testing.T) {
	tests := []struct {
		name              string
		offline           bool
		setup             func(*testing.T, string)
		wantConfiguration ConfigurationState
		wantRemote        RemoteState
		wantErr           error
		forbidden         []string
	}{
		{
			name:              "unconfigured",
			wantConfiguration: ConfigurationUnconfigured,
			wantRemote:        RemoteNotConfigured,
		},
		{
			name: "configured",
			setup: func(t *testing.T, serverURL string) {
				t.Helper()
				if err := cloud.SaveCloud(&cloud.CloudConfig{Server: serverURL, Token: "test-token"}); err != nil {
					t.Fatal(err)
				}
			},
			wantConfiguration: ConfigurationConfigured,
			wantRemote:        RemoteNotChecked,
		},
		{
			name: "invalid",
			setup: func(t *testing.T, _ string) {
				t.Helper()
				if err := config.WritePrivateFile(filepath.Join(config.Dir(), "cloud.json"), []byte("{")); err != nil {
					t.Fatal(err)
				}
			},
			wantConfiguration: ConfigurationInvalid,
			wantRemote:        RemoteNotChecked,
			wantErr:           ErrConfiguration,
		},
		{
			name: "invalid required fields are redacted",
			setup: func(t *testing.T, _ string) {
				t.Helper()
				if err := cloud.SaveCloud(&cloud.CloudConfig{
					Server: "secret-server-without-a-url",
					Token:  "secret-test-token",
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantConfiguration: ConfigurationInvalid,
			wantRemote:        RemoteNotChecked,
			wantErr:           ErrConfiguration,
			forbidden:         []string{"secret-server-without-a-url", "secret-test-token"},
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
			wantConfiguration: ConfigurationInvalid,
			wantRemote:        RemoteNotChecked,
			wantErr:           ErrConfiguration,
		},
		{
			name:    "offline ignores invalid configuration",
			offline: true,
			setup: func(t *testing.T, _ string) {
				t.Helper()
				if err := config.WritePrivateFile(filepath.Join(config.Dir(), "cloud.json"), []byte("{")); err != nil {
					t.Fatal(err)
				}
			},
			wantConfiguration: ConfigurationOffline,
			wantRemote:        RemoteNotChecked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests.Add(1)
			}))
			defer server.Close()
			if tt.setup != nil {
				tt.setup(t, server.URL)
			}

			facts, err := New(Options{Offline: tt.offline}).InspectLocal()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("InspectLocal error = %v, want %v", err, tt.wantErr)
			}
			if facts.Configuration != tt.wantConfiguration || facts.Remote != tt.wantRemote || facts.Offline != tt.offline {
				t.Fatalf("InspectLocal facts = %+v", facts)
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("InspectLocal requests = %d, want 0", got)
			}
			observed := fmt.Sprintf("%+v %v", facts, err)
			for _, secret := range tt.forbidden {
				if strings.Contains(observed, secret) {
					t.Fatalf("InspectLocal exposed configuration contents in %q", observed)
				}
			}
		})
	}
}

func TestInspectLocalReturnsConflictWithoutMutationOrSecrets(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	const token = "secret-test-token"
	const opaqueVault = "opaque-encrypted-vault-fixture"
	if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: token}); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePrivateFile(config.Path(), []byte(opaqueVault)); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePrivateFile(remoteIdentityPath(), []byte("cached-remote\n")); err != nil {
		t.Fatal(err)
	}
	wantConflict := SyncConflict{
		DetectedAt: "2026-07-28T14:00:00Z",
		LocalETag:  "opaque-local",
		RemoteETag: "opaque-remote",
		CachedETag: "opaque-cached",
	}
	if err := preserveConflict(wantConflict); err != nil {
		t.Fatal(err)
	}
	before := localStateSnapshot(t)

	facts, err := New(Options{}).InspectLocal()
	if err != nil {
		t.Fatalf("InspectLocal: %v", err)
	}
	if facts.Configuration != ConfigurationConfigured || !reflect.DeepEqual(facts.Conflict, &wantConflict) {
		t.Fatalf("InspectLocal facts = %+v", facts)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("InspectLocal requests = %d, want 0", got)
	}
	if after := localStateSnapshot(t); !reflect.DeepEqual(after, before) {
		t.Fatalf("InspectLocal changed local state: before=%v after=%v", before, after)
	}
	observed := fmt.Sprintf("%+v %v", facts, err)
	for _, secret := range []string{server.URL, token, opaqueVault} {
		if strings.Contains(observed, secret) {
			t.Fatalf("InspectLocal exposed sensitive contents in %q", observed)
		}
	}
}

func localStateSnapshot(t *testing.T) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	err := filepath.WalkDir(config.Dir(), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(config.Dir(), path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			snapshot[relative+"/"] = ""
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // test snapshots only its private temporary config directory
		if err != nil {
			return err
		}
		snapshot[relative] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
