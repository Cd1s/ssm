package cloud

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/config"
)

func TestSaveCloudCreatesConfigDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := &CloudConfig{Server: "https://sync.example.test", Token: "token", Email: "agent@example.test"}
	if err := SaveCloud(cfg); err != nil {
		t.Fatalf("SaveCloud: %v", err)
	}

	path := filepath.Join(home, ".config", "ssm", "cloud.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cloud config: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("cloud config mode = %o, want 600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat cloud config dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("cloud config dir mode = %o, want 700", dirInfo.Mode().Perm())
	}
}

func TestPullWritesVaultAndRemoteETagPrivately(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	blob := []byte("opaque encrypted bytes")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sync" {
			t.Fatalf("path = %q, want /sync", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization header was not set")
		}
		w.Header().Set("ETag", `"remote-etag"`)
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	if err := Pull(&CloudConfig{Server: srv.URL, Token: "token"}); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	for _, path := range []string{
		filepath.Join(home, ".config", "ssm", "connections.enc"),
		filepath.Join(home, ".config", "ssm", "remote.etag"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
	}
}

func TestLocalAndCachedETagExposeOnlyBlobIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	blob := []byte("opaque encrypted bytes")
	if err := config.WritePrivateFile(config.Path(), blob); err != nil {
		t.Fatal(err)
	}
	if err := saveRemoteETag(hashBytes(blob)); err != nil {
		t.Fatal(err)
	}
	local, err := LocalVaultETag()
	if err != nil {
		t.Fatal(err)
	}
	if local == "" || local != CachedRemoteETag() || strings.Contains(local, string(blob)) {
		t.Fatalf("local=%q cached=%q", local, CachedRemoteETag())
	}
}

func TestPullIfChangedStopsOnDivergedLocalAndRemoteVaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	localBlob := []byte("locally changed encrypted blob")
	if err := config.WritePrivateFile(config.Path(), localBlob); err != nil {
		t.Fatal(err)
	}
	if err := saveRemoteETag("previous-remote-etag"); err != nil {
		t.Fatal(err)
	}
	getCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"new-remote-etag"`)
		if r.Method == http.MethodGet {
			getCalled = true
			_, _ = w.Write([]byte("remote encrypted blob"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	changed, err := PullIfChanged(&CloudConfig{Server: server.URL, Token: "test-token"})
	if err == nil || changed {
		t.Fatalf("changed=%t err=%v", changed, err)
	}
	if getCalled {
		t.Fatal("remote blob was downloaded despite a two-sided conflict")
	}
	data, readErr := os.ReadFile(config.Path())
	if readErr != nil || string(data) != string(localBlob) {
		t.Fatalf("local vault changed: data=%q err=%v", data, readErr)
	}
	conflict := LoadSyncConflict()
	if conflict == nil || conflict.LocalETag == "" || conflict.RemoteETag != "new-remote-etag" || conflict.CachedETag != "previous-remote-etag" {
		t.Fatalf("conflict = %+v", conflict)
	}
}

func TestPullRejectsEmptyBlobWithoutOverwritingVault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	existing := []byte("existing encrypted bytes")
	vaultPath := filepath.Join(home, ".config", "ssm", "connections.enc")
	if err := os.MkdirAll(filepath.Dir(vaultPath), 0700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(vaultPath, existing, 0600); err != nil {
		t.Fatalf("write existing vault: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := Pull(&CloudConfig{Server: srv.URL, Token: "token"})
	if err == nil {
		t.Fatal("expected empty sync blob error")
	}
	if got := err.Error(); got != "sync blob is empty" {
		t.Fatalf("error = %q, want empty blob error", got)
	}
	data, readErr := os.ReadFile(vaultPath)
	if readErr != nil {
		t.Fatalf("read vault: %v", readErr)
	}
	if string(data) != string(existing) {
		t.Fatalf("vault overwritten on empty pull: %q", data)
	}
}

func TestPullRejectsOversizedBlobWithoutWritingVault(t *testing.T) {
	oldMax := maxPullBlobBytes
	maxPullBlobBytes = 8
	t.Cleanup(func() { maxPullBlobBytes = oldMax })

	home := t.TempDir()
	t.Setenv("HOME", home)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("too many bytes"))
	}))
	defer srv.Close()

	err := Pull(&CloudConfig{Server: srv.URL, Token: "token"})
	if err == nil {
		t.Fatal("expected oversized sync blob error")
	}
	if got := err.Error(); got != "sync blob too large" {
		t.Fatalf("error = %q, want oversized blob error", got)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".config", "ssm", "connections.enc")); !os.IsNotExist(statErr) {
		t.Fatalf("vault was written or stat failed unexpectedly: %v", statErr)
	}
}

func TestCloudRequestsTrimServerTrailingSlash(t *testing.T) {
	var paths []string
	var contentTypes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		contentTypes = append(contentTypes, r.Header.Get("Content-Type"))
		switch r.URL.Path {
		case "/auth/login", "/auth/register":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "token"})
		case "/auth/status":
			_ = json.NewEncoder(w).Encode(map[string]bool{"verified": true})
		case "/sync":
			w.Header().Set("ETag", `"etag"`)
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	server := srv.URL + "/"
	if _, err := Login(server, "agent@example.test", "long-password"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := Register(server, "agent@example.test", "long-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if ok := CheckVerified(&CloudConfig{Server: server, Token: "token"}); !ok {
		t.Fatal("CheckVerified returned false")
	}
	if _, err := RemoteETag(&CloudConfig{Server: server, Token: "token"}); err != nil {
		t.Fatalf("RemoteETag: %v", err)
	}

	for _, path := range paths {
		if len(path) > 1 && path[:2] == "//" {
			t.Fatalf("path %q has double slash", path)
		}
	}
	for i, contentType := range contentTypes[:2] {
		if contentType != "application/json" {
			t.Fatalf("request %d content type = %q, want application/json", i, contentType)
		}
	}
}

func TestCloudUsesConfiguredHTTPClient(t *testing.T) {
	oldClient := httpClient
	defer func() { httpClient = oldClient }()

	httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/auth/login" {
			t.Fatalf("path = %q, want /auth/login", req.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"token":"token"}`)),
		}, nil
	})}

	token, err := Login("https://sync.example.test/", "agent@example.test", "long-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if token != "token" {
		t.Fatalf("token = %q, want token", token)
	}
}

func TestCloudRequestsRequireToken(t *testing.T) {
	cfg := &CloudConfig{Server: "https://sync.example.test"}
	for name, fn := range map[string]func() error{
		"push": func() error {
			return Push(cfg)
		},
		"pull": func() error {
			return Pull(cfg)
		},
		"remote-etag": func() error {
			_, err := RemoteETag(cfg)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := fn()
			if err == nil {
				t.Fatal("expected missing token error")
			}
			if strings.Contains(err.Error(), "Bearer") {
				t.Fatalf("error exposes auth header: %v", err)
			}
		})
	}
}

func TestParseErrorFallsBackForEmptyServerError(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Body:       io.NopCloser(strings.NewReader(`{"error":""}`)),
	}
	err := parseError(resp)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got != "server error (401)" {
		t.Fatalf("error = %q, want status fallback", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
