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

	"ssm/internal/privatepath"
)

func setTestHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestSaveCloudCreatesConfigDir(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	cfg := &CloudConfig{Server: "https://sync.example.test", Token: "token", Email: "agent@example.test"}
	if err := SaveCloud(cfg); err != nil {
		t.Fatalf("SaveCloud: %v", err)
	}

	path := filepath.Join(home, ".config", "ssm", "cloud.json")
	if err := privatepath.VerifyFile(path); err != nil {
		t.Fatalf("cloud config is not private: %v", err)
	}
	if err := privatepath.VerifyDirectory(filepath.Dir(path)); err != nil {
		t.Fatalf("cloud config directory is not private: %v", err)
	}
}

func TestPullWritesOpaqueVaultPrivatelyAndReturnsConfirmedIdentity(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
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

	etag, err := Pull(&CloudConfig{Server: srv.URL, Token: "token"})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if etag != "remote-etag" {
		t.Fatalf("etag = %q, want remote-etag", etag)
	}
	path := filepath.Join(home, ".config", "ssm", "connections.enc")
	if err := privatepath.VerifyFile(path); err != nil {
		t.Fatalf("%s is not private: %v", path, err)
	}
}

func TestPullRejectsEmptyBlobWithoutOverwritingVault(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
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

	_, err := Pull(&CloudConfig{Server: srv.URL, Token: "token"})
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
	setTestHome(t, home)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("too many bytes"))
	}))
	defer srv.Close()

	_, err := Pull(&CloudConfig{Server: srv.URL, Token: "token"})
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
			_, err := PushBlob(cfg, []byte("opaque"))
			return err
		},
		"pull": func() error {
			_, err := Pull(cfg)
			return err
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
