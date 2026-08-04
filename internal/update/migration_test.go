package update

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"ssm/internal/config"
)

func TestCrossMajorRequiresExplicitAuthorization(t *testing.T) {
	restoreUpdateTestHooks(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")
	exe := migrationTestExecutable(t, []byte("v1 executable"))
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		if r.URL.Path != "/repos/owner/repo/releases" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprintf(w, `[{"tag_name":"v2.0.0","name":"SSM v2","body":"review BC-1 through BC-10","assets":%s}]`, migrationReleaseAssetsJSON(t))
	}))
	defer server.Close()
	apiBaseURL = server.URL
	httpClient = server.Client()

	review, err := ReviewMajor("v1.4.4", false, "")
	if err != nil {
		t.Fatalf("review without authorization: %v", err)
	}
	if review.Authorized || review.Installed || review.AuthorizationState != "not_authorized" || review.Target != "v2.0.0" {
		t.Fatalf("review = %#v", review)
	}
	if len(review.BreakingChanges) != 10 || len(review.AutomatedChecks) != 5 || len(review.ManualChecks) != 3 {
		t.Fatalf("incomplete migration evidence: %#v", review)
	}
	assertMigrationFile(t, exe, []byte("v1 executable"))
	if len(requests) != 1 || requests[0] != "/repos/owner/repo/releases" {
		t.Fatalf("non-authorized review requested assets: %q", requests)
	}

	review, err = ReviewMajor("v1.4.4", true, "")
	if err != nil {
		t.Fatalf("authorized review: %v", err)
	}
	if !review.Authorized || review.Installed || review.AuthorizationState != "authorized" {
		t.Fatalf("authorized pre-replacement review = %#v", review)
	}
	assertMigrationFile(t, exe, []byte("v1 executable"))
	if len(requests) != 2 || requests[1] != "/repos/owner/repo/releases" {
		t.Fatalf("authorization downloaded an asset: %q", requests)
	}
}

func TestAuthorizedMajorReviewThenVerifiedReplacement(t *testing.T) {
	restoreUpdateTestHooks(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")
	exe := migrationTestExecutable(t, []byte("authorized v1 executable"))
	payload := []byte("verified v2 executable")
	httpClient = migrationHTTPClient(t, "v2.0.0", payload, true)

	review, err := ReviewMajor("v1.4.4", true, "")
	if err != nil {
		t.Fatalf("authorized major review: %v", err)
	}
	if !review.OK || !review.Authorized || review.Target != "v2.0.0" || review.Installed {
		t.Fatalf("authorized review = %#v", review)
	}
	callbackCalled := false
	err = DownloadVersionBeforeReplace(review.Target, false, func() error {
		callbackCalled = true
		assertMigrationFile(t, exe, []byte("authorized v1 executable"))
		return nil
	})
	if err != nil {
		t.Fatalf("verified major replacement: %v", err)
	}
	if !callbackCalled {
		t.Fatal("migration review callback did not run before replacement")
	}
	assertMigrationFile(t, exe, payload)
}

func TestFailedMigrationPreflightPreservesExecutableAndEncryptedState(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T) string
		check string
	}{
		{
			name: "invalid cloud configuration",
			setup: func(t *testing.T) string {
				t.Helper()
				if err := config.WritePrivateFile(filepath.Join(config.Dir(), "cloud.json"), []byte("{")); err != nil {
					t.Fatal(err)
				}
				return ""
			},
			check: "cloud_configuration",
		},
		{
			name: "pending transaction",
			setup: func(t *testing.T) string {
				t.Helper()
				const password = "test migration password"
				if err := config.Save(&config.Vault{PendingMutations: []config.PendingMutation{{ID: "tx_pending"}}}, password); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "master.pass")
				if err := os.WriteFile(path, []byte(password+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			check: "pending_recovery",
		},
		{
			name: "preserved divergence",
			setup: func(t *testing.T) string {
				t.Helper()
				if err := config.WritePrivateFile(filepath.Join(config.Dir(), "sync-conflict.json"), []byte(`{"local_etag":"a","remote_etag":"b"}`)); err != nil {
					t.Fatal(err)
				}
				return ""
			},
			check: "untracked_divergence",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			restoreUpdateTestHooks(t)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("SSM_UPDATE_REPO", "owner/repo")
			exe := migrationTestExecutable(t, []byte("preserved executable"))
			masterPassPath := test.setup(t)
			stateBefore := migrationStateSnapshot(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/owner/repo/releases" {
					t.Fatalf("preflight requested unexpected path %q", r.URL.Path)
				}
				_, _ = fmt.Fprintf(w, `[{"tag_name":"v2.0.0","body":"migration notes","assets":%s}]`, migrationReleaseAssetsJSON(t))
			}))
			defer server.Close()
			apiBaseURL = server.URL
			httpClient = server.Client()

			review, err := ReviewMajor("v1.4.4", true, masterPassPath)
			if err == nil {
				t.Fatalf("unsafe preflight passed: %#v", review)
			}
			failed := false
			for _, check := range review.AutomatedChecks {
				if check.ID == test.check && check.Status == "failed" {
					failed = true
				}
			}
			if !failed {
				t.Fatalf("check %q did not fail: %#v", test.check, review.AutomatedChecks)
			}
			assertMigrationFile(t, exe, []byte("preserved executable"))
			stateAfter := migrationStateSnapshot(t)
			if !bytes.Equal(stateAfter, stateBefore) {
				t.Fatal("encrypted/config state changed during failed preflight")
			}
		})
	}
}

func TestDanglingRecoveryIntentFailsPreflight(t *testing.T) {
	restoreUpdateTestHooks(t)
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(config.Dir(), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(config.Dir(), "publishing-intent.json")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing-intent"), path); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	check := checkPendingRecovery("")
	if check.Status != "failed" {
		t.Fatalf("dangling recovery intent check = %#v", check)
	}
}

func migrationTestExecutable(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssm")
	if err := os.WriteFile(path, content, 0751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return path, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }
	return path
}

func migrationReleaseAssetsJSON(t *testing.T) string {
	t.Helper()
	names := []string{
		"ssm-linux-amd64", "ssm-linux-arm64", "ssm-darwin-amd64", "ssm-darwin-arm64",
		"ssm-windows-amd64.exe", "ssm-windows-arm64.exe",
		"ssm-linux-amd64.sigstore.json", "ssm-linux-arm64.sigstore.json",
		"ssm-darwin-amd64.sigstore.json", "ssm-darwin-arm64.sigstore.json",
		"ssm-windows-amd64.exe.sigstore.json", "ssm-windows-arm64.exe.sigstore.json",
		"install.sh", "checksums.txt",
	}
	assets := make([]map[string]string, 0, len(names))
	for _, name := range names {
		assets = append(assets, map[string]string{"name": name})
	}
	encoded, err := json.Marshal(assets)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func migrationStateSnapshot(t *testing.T) []byte {
	t.Helper()
	var snapshot []byte
	for _, name := range []string{"connections.enc", "cloud.json", "sync-conflict.json"} {
		data, err := os.ReadFile(filepath.Join(config.Dir(), name)) //nolint:gosec // names are fixed test fixtures beneath a test-owned config directory
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		snapshot = append(snapshot, []byte(name)...)
		snapshot = append(snapshot, 0)
		snapshot = append(snapshot, data...)
		snapshot = append(snapshot, 0)
	}
	return snapshot
}

func assertMigrationFile(t *testing.T, path string, content []byte) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // callers pass test-owned executable paths
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, content) || info.Mode().Perm() != 0751 {
		t.Fatalf("file bytes/mode changed: content=%q mode=%o", data, info.Mode().Perm())
	}
}
