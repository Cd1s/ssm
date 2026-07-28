package synctransaction

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ssm/internal/cloud"
	"ssm/internal/config"
)

func TestSyncTransactionPolicy(t *testing.T) {
	t.Run("configuration and offline state", func(t *testing.T) {
		tests := []struct {
			name      string
			offline   bool
			cloud     []byte
			cloudDir  bool
			cloudMode os.FileMode
			wantState ConfigurationState
			wantErr   error
		}{
			{name: "offline ignores malformed configuration", offline: true, cloud: []byte("{"), wantState: ConfigurationOffline},
			{name: "absent configuration is unconfigured", wantState: ConfigurationUnconfigured},
			{name: "malformed configuration is invalid", cloud: []byte("{"), wantState: ConfigurationInvalid, wantErr: ErrConfiguration},
			{name: "unreadable configuration is invalid", cloudDir: true, wantState: ConfigurationInvalid, wantErr: ErrConfiguration},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
				if tt.cloud != nil || tt.cloudDir {
					dir := filepath.Join(home, ".config", "ssm")
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
					cloudPath := filepath.Join(dir, "cloud.json")
					if tt.cloudDir {
						if err := os.Mkdir(cloudPath, 0700); err != nil {
							t.Fatal(err)
						}
					} else {
						mode := tt.cloudMode
						if mode == 0 {
							mode = 0600
						}
						if err := os.WriteFile(cloudPath, tt.cloud, mode); err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"auto_sync":false}`), 0600); err != nil {
						t.Fatal(err)
					}
				}

				tx := New(Options{Offline: tt.offline})
				facts, err := tx.Refresh()
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Refresh error = %v, want %v", err, tt.wantErr)
				}
				if facts.Configuration != tt.wantState {
					t.Fatalf("configuration = %q, want %q", facts.Configuration, tt.wantState)
				}
			})
		}
	})

	t.Run("disabled automatic sync validates configuration without network access", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			requests++
		}))
		defer server.Close()
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "opaque"}); err != nil {
			t.Fatal(err)
		}
		settings := config.DefaultSettings()
		settings.AutoSync = false
		if err := config.SaveSettings(settings); err != nil {
			t.Fatal(err)
		}

		facts, err := New(Options{}).Refresh()
		if err != nil {
			t.Fatalf("Refresh error = %v", err)
		}
		if requests != 0 {
			t.Fatalf("automatic sync disabled requests = %d, want 0", requests)
		}
		if facts.Configuration != ConfigurationConfigured || facts.Remote != RemoteAutoSyncDisabled {
			t.Fatalf("facts = %+v", facts)
		}
	})

	t.Run("explicit sync requires present configuration", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

		facts, err := New(Options{}).Sync()
		if !errors.Is(err, ErrUnconfigured) {
			t.Fatalf("Sync error = %v, want %v", err, ErrUnconfigured)
		}
		if facts.Configuration != ConfigurationUnconfigured || facts.Remote != RemoteNotConfigured {
			t.Fatalf("facts = %+v", facts)
		}
	})

	t.Run("refresh and explicit pull preserve two-sided divergence without GET", func(t *testing.T) {
		operations := []struct {
			name string
			run  func(*Transaction) (Facts, error)
		}{
			{name: "refresh", run: func(tx *Transaction) (Facts, error) { return tx.Refresh() }},
			{name: "pull", run: func(tx *Transaction) (Facts, error) { return tx.Pull() }},
		}
		for _, operation := range operations {
			t.Run(operation.name, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
				localBlob := []byte("locally changed encrypted blob")
				if err := config.WritePrivateFile(config.Path(), localBlob); err != nil {
					t.Fatal(err)
				}
				if err := config.WritePrivateFile(filepath.Join(config.Dir(), "remote.etag"), []byte("previous-remote-etag\n")); err != nil {
					t.Fatal(err)
				}
				headCount, getCount := 0, 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("ETag", `"new-remote-etag"`)
					switch r.Method {
					case http.MethodHead:
						headCount++
					case http.MethodGet:
						getCount++
						_, _ = w.Write([]byte("remote encrypted blob"))
					}
				}))
				defer server.Close()
				if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "opaque"}); err != nil {
					t.Fatal(err)
				}

				facts, err := operation.run(New(Options{}))
				if !errors.Is(err, ErrConflict) || facts.Changed {
					t.Fatalf("changed=%t err=%v", facts.Changed, err)
				}
				if headCount != 1 || getCount != 0 {
					t.Fatalf("requests: HEAD=%d GET=%d, want HEAD=1 GET=0", headCount, getCount)
				}
				data, readErr := os.ReadFile(config.Path())
				if readErr != nil || string(data) != string(localBlob) {
					t.Fatalf("local vault changed: data=%q err=%v", data, readErr)
				}
				conflict := loadConflict()
				if conflict == nil ||
					conflict.LocalETag == "" ||
					conflict.LocalETag != facts.LocalETag ||
					conflict.RemoteETag != "new-remote-etag" ||
					conflict.CachedETag != "previous-remote-etag" {
					t.Fatalf("conflict = %+v; facts = %+v", conflict, facts)
				}
			})
		}
	})

	t.Run("changed remote blob commits before one invalidation", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		remoteBlob := []byte("opaque remote encrypted blob")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `"remote-current"`)
			if r.Method == http.MethodGet {
				_, _ = w.Write(remoteBlob)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "opaque"}); err != nil {
			t.Fatal(err)
		}
		invalidations := 0
		facts, err := New(Options{Invalidate: func() {
			data, readErr := os.ReadFile(config.Path())
			if readErr != nil || string(data) != string(remoteBlob) {
				t.Fatalf("invalidation preceded opaque commit: data=%q err=%v", data, readErr)
			}
			invalidations++
		}}).Refresh()
		if err != nil || !facts.Changed {
			t.Fatalf("changed=%t err=%v", facts.Changed, err)
		}
		if invalidations != 1 {
			t.Fatalf("invalidations=%d, want 1", invalidations)
		}
	})

	t.Run("pull metadata records the confirmed GET identity and transaction time", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		now := time.Date(2026, 7, 28, 12, 34, 56, 0, time.UTC)
		remoteBlob := []byte("opaque confirmed remote blob")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodHead:
				w.Header().Set("ETag", `"head-observation"`)
			case http.MethodGet:
				w.Header().Set("ETag", `"get-commit"`)
				_, _ = w.Write(remoteBlob)
			default:
				t.Fatalf("unexpected method %s", r.Method)
			}
		}))
		defer server.Close()
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "opaque"}); err != nil {
			t.Fatal(err)
		}

		facts, err := New(Options{Now: func() time.Time { return now }}).Refresh()
		if err != nil {
			t.Fatal(err)
		}
		wantTime := now.Format(time.RFC3339)
		if facts.RemoteETag != "get-commit" || facts.LastPull != wantTime || facts.LastSync != wantTime {
			t.Fatalf("facts = %+v", facts)
		}
	})

	t.Run("push conflict identifies the candidate encrypted blob and performs no PUT", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		baselineBlob := []byte("opaque cached baseline")
		candidateBlob := []byte("opaque candidate publication")
		if err := config.WritePrivateFile(config.Path(), baselineBlob); err != nil {
			t.Fatal(err)
		}
		cachedIdentity := opaqueIdentity(baselineBlob)
		if err := config.WritePrivateFile(filepath.Join(config.Dir(), "remote.etag"), []byte(cachedIdentity+"\n")); err != nil {
			t.Fatal(err)
		}
		headCount, putCount := 0, 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodHead:
				headCount++
				w.Header().Set("ETag", `"remote-diverged"`)
			case http.MethodPut:
				putCount++
			}
		}))
		defer server.Close()
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "opaque"}); err != nil {
			t.Fatal(err)
		}

		facts, err := New(Options{}).PushBlob(candidateBlob)
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("PushBlob error = %v, want %v", err, ErrConflict)
		}
		if headCount != 1 || putCount != 0 {
			t.Fatalf("requests: HEAD=%d PUT=%d, want HEAD=1 PUT=0", headCount, putCount)
		}
		wantCandidate := opaqueIdentity(candidateBlob)
		if facts.Conflict == nil ||
			facts.Conflict.LocalETag != wantCandidate ||
			facts.Conflict.RemoteETag != "remote-diverged" ||
			facts.Conflict.CachedETag != cachedIdentity {
			t.Fatalf("facts = %+v", facts)
		}
	})

	t.Run("push metadata records only the confirmed PUT identity and transaction time", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		now := time.Date(2026, 7, 28, 13, 45, 1, 0, time.UTC)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut {
				t.Fatalf("unexpected method %s", r.Method)
			}
			w.Header().Set("ETag", `"put-commit"`)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "opaque"}); err != nil {
			t.Fatal(err)
		}

		facts, err := New(Options{Now: func() time.Time { return now }}).PushBlob([]byte("opaque pushed blob"))
		if err != nil {
			t.Fatal(err)
		}
		wantTime := now.Format(time.RFC3339)
		if facts.RemoteETag != "put-commit" || facts.LastPush != wantTime || facts.LastSync != wantTime {
			t.Fatalf("facts = %+v", facts)
		}
	})

	t.Run("failed GET leaves cached identity timestamps and snapshot unchanged", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		localBlob := []byte("opaque local snapshot")
		if err := config.WritePrivateFile(config.Path(), localBlob); err != nil {
			t.Fatal(err)
		}
		cachedIdentity := opaqueIdentity(localBlob)
		if err := config.WritePrivateFile(remoteIdentityPath(), []byte(cachedIdentity+"\n")); err != nil {
			t.Fatal(err)
		}
		settings := config.DefaultSettings()
		settings.LastPull = "2026-07-20T01:02:03Z"
		if err := config.SaveSettings(settings); err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodHead:
				w.Header().Set("ETag", `"remote-after-cache"`)
			case http.MethodGet:
				http.Error(w, `{"error":"fixture failure"}`, http.StatusInternalServerError)
			}
		}))
		defer server.Close()
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "opaque"}); err != nil {
			t.Fatal(err)
		}

		invalidations := 0
		_, err := New(Options{Invalidate: func() { invalidations++ }}).Refresh()
		if !errors.Is(err, ErrRefresh) {
			t.Fatalf("Refresh error = %v, want %v", err, ErrRefresh)
		}
		facts := New(Options{}).Facts()
		if facts.RemoteETag != cachedIdentity || facts.LastPull != settings.LastPull || invalidations != 0 {
			t.Fatalf("facts=%+v invalidations=%d", facts, invalidations)
		}
		after, readErr := os.ReadFile(config.Path())
		if readErr != nil || string(after) != string(localBlob) {
			t.Fatalf("local snapshot changed: data=%q err=%v", after, readErr)
		}
	})

	t.Run("failed PUT leaves cached identity and push timestamp unchanged", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		candidateBlob := []byte("opaque candidate")
		cachedIdentity := opaqueIdentity(candidateBlob)
		if err := config.WritePrivateFile(remoteIdentityPath(), []byte(cachedIdentity+"\n")); err != nil {
			t.Fatal(err)
		}
		settings := config.DefaultSettings()
		settings.LastPush = "2026-07-21T01:02:03Z"
		if err := config.SaveSettings(settings); err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodHead:
				w.Header().Set("ETag", `"`+cachedIdentity+`"`)
			case http.MethodPut:
				http.Error(w, `{"error":"fixture failure"}`, http.StatusInternalServerError)
			}
		}))
		defer server.Close()
		if err := cloud.SaveCloud(&cloud.CloudConfig{Server: server.URL, Token: "opaque"}); err != nil {
			t.Fatal(err)
		}

		_, err := New(Options{}).PushBlob(candidateBlob)
		if !errors.Is(err, ErrRefresh) {
			t.Fatalf("PushBlob error = %v, want %v", err, ErrRefresh)
		}
		facts := New(Options{}).Facts()
		if facts.RemoteETag != cachedIdentity || facts.LastPush != settings.LastPush {
			t.Fatalf("facts = %+v", facts)
		}
	})
}
