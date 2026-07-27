package syncserver

import (
	"bytes"
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

func TestRegisterLoginPushPullRoundTrip(t *testing.T) {
	srv, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	registerToken := authCall(t, httpSrv.URL+"/auth/register", "agent@example.test", "long-password")
	if registerToken == "" {
		t.Fatal("empty register token")
	}

	statusReq, err := http.NewRequest(http.MethodGet, httpSrv.URL+"/auth/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	statusReq.Header.Set("Authorization", "Bearer "+registerToken)
	statusResp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	defer statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d", statusResp.StatusCode)
	}

	loginToken := authCall(t, httpSrv.URL+"/auth/login", "agent@example.test", "long-password")
	if loginToken == "" || loginToken == registerToken {
		t.Fatalf("expected rotated login token")
	}

	blob := []byte("opaque encrypted bytes")
	pushReq, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/sync", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	pushReq.Header.Set("Authorization", "Bearer "+loginToken)
	pushResp, err := http.DefaultClient.Do(pushReq)
	if err != nil {
		t.Fatal(err)
	}
	pushETag := pushResp.Header.Get("ETag")
	if pushETag == "" {
		t.Fatal("missing push ETag")
	}
	defer pushResp.Body.Close()
	if pushResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(pushResp.Body)
		t.Fatalf("push status = %d body=%s", pushResp.StatusCode, body)
	}

	pullReq, err := http.NewRequest(http.MethodGet, httpSrv.URL+"/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	pullReq.Header.Set("Authorization", "Bearer "+loginToken)
	pullResp, err := http.DefaultClient.Do(pullReq)
	if err != nil {
		t.Fatal(err)
	}
	defer pullResp.Body.Close()
	got, err := io.ReadAll(pullResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if pullResp.StatusCode != http.StatusOK {
		t.Fatalf("pull status = %d body=%s", pullResp.StatusCode, got)
	}
	if pullResp.Header.Get("ETag") != pushETag {
		t.Fatalf("pull ETag = %q, want %q", pullResp.Header.Get("ETag"), pushETag)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("blob mismatch: got %q want %q", got, blob)
	}

	headReq, err := http.NewRequest(http.MethodHead, httpSrv.URL+"/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	headReq.Header.Set("Authorization", "Bearer "+loginToken)
	headResp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		t.Fatal(err)
	}
	defer headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Fatalf("head status = %d", headResp.StatusCode)
	}
	if headResp.Header.Get("ETag") != pushETag {
		t.Fatalf("head ETag = %q, want %q", headResp.Header.Get("ETag"), pushETag)
	}
}

func TestHealth(t *testing.T) {
	srv, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	resp, err := http.Get(httpSrv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestServerStoresPrivateFiles(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	token := authCall(t, httpSrv.URL+"/auth/register", "agent@example.test", "long-password")
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/sync", bytes.NewReader([]byte("blob")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push status = %d", resp.StatusCode)
	}

	for _, path := range []string{
		dir,
		filepath.Join(dir, "vaults"),
	} {
		if err := privatepath.VerifyDirectory(path); err != nil {
			t.Fatalf("%s is not private: %v", path, err)
		}
	}
	if err := privatepath.VerifyFile(filepath.Join(dir, "users.json")); err != nil {
		t.Fatalf("users database is not private: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(dir, "vaults"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("vault count = %d", len(entries))
	}
	vaultPath := filepath.Join(dir, "vaults", entries[0].Name())
	if err := privatepath.VerifyFile(vaultPath); err != nil {
		t.Fatalf("vault is not private: %v", err)
	}
	for _, root := range []string{dir, filepath.Join(dir, "vaults")} {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".") && strings.HasSuffix(entry.Name(), ".tmp") {
				t.Fatalf("leftover temp file in %s: %s", root, entry.Name())
			}
		}
	}
}

func TestRegisterRejectsMalformedAndShortAuthRequests(t *testing.T) {
	srv, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	cases := []struct {
		name string
		body string
		want int
	}{
		{name: "invalid json", body: `{`, want: http.StatusBadRequest},
		{name: "invalid email", body: `{"email":"agent","password":"long-password"}`, want: http.StatusBadRequest},
		{name: "short password", body: `{"email":"agent@example.test","password":"short"}`, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(httpSrv.URL+"/auth/register", "application/json", bytes.NewBufferString(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				data, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d body=%s, want %d", resp.StatusCode, data, tc.want)
			}
		})
	}
}

func TestSyncRequiresBearerToken(t *testing.T) {
	srv, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	req, err := http.NewRequest(http.MethodHead, httpSrv.URL+"/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestSyncRejectsEmptyBearerToken(t *testing.T) {
	srv, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	req, err := http.NewRequest(http.MethodGet, httpSrv.URL+"/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer ")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestSyncRejectsOversizedBlobWithoutWritingVault(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	token := authCall(t, httpSrv.URL+"/auth/register", "agent@example.test", "long-password")
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/sync", io.LimitReader(zeroReader{}, maxBlobBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "vaults"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("vaults written after oversized push: %d", len(entries))
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestConstantTimeEqualRejectsEmptyAndMismatchedValues(t *testing.T) {
	if constantTimeEqual("", "") {
		t.Fatal("empty values must not match")
	}
	if constantTimeEqual("abc", "abd") {
		t.Fatal("different values matched")
	}
	if constantTimeEqual("abc", "ab") {
		t.Fatal("different lengths matched")
	}
	if !constantTimeEqual("abc", "abc") {
		t.Fatal("identical non-empty values did not match")
	}
}

func authCall(t *testing.T, url, email, password string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s status = %d body=%s", url, resp.StatusCode, data)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Token
}
