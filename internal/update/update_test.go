package update

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		latest  string
		current string
		want    bool
	}{
		{"v1.0.1", "1.0.0", true},
		{"v1.0.0", "1.0.0", false},
		{"1.2.0", "1.1.9", true},
		{"v0.9.9", "1.0.0", false},
	}
	for _, tc := range cases {
		if got := newerVersion(tc.latest, tc.current); got != tc.want {
			t.Fatalf("newerVersion(%q, %q) = %v, want %v", tc.latest, tc.current, got, tc.want)
		}
	}
}

func TestReleaseRepoCanBeDisabledByEnvironment(t *testing.T) {
	for _, value := range []string{"off", "none", "disabled", " OFF "} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("SSM_UPDATE_REPO", value)
			if got := releaseRepo(); got != "" {
				t.Fatalf("releaseRepo() = %q, want disabled", got)
			}
		})
	}
}

func TestAutoDisabledDoesNotWriteCooldownFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSM_UPDATE_REPO", "off")

	if err := Auto("1.0.0"); err != nil {
		t.Fatalf("Auto: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "ssm", ".update-available")); !os.IsNotExist(err) {
		t.Fatalf("update flag exists or stat failed unexpectedly: %v", err)
	}
}

func TestMarkCheckedWritesPrivateCooldownFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	markChecked("v9.9.9")

	path := filepath.Join(home, ".config", "ssm", ".update-available")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat update flag: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("update flag mode = %o, want 600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat update flag dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("update flag dir mode = %o, want 700", dirInfo.Mode().Perm())
	}
}

func TestChecksumForAsset(t *testing.T) {
	data := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ssm-linux-amd64\n")

	got, err := checksumForAsset(data, "ssm-linux-amd64")
	if err != nil {
		t.Fatalf("checksumForAsset: %v", err)
	}
	if got != strings.Repeat("a", sha256.Size*2) {
		t.Fatalf("checksum = %q", got)
	}
}

func TestAssetNameForSupportedPlatforms(t *testing.T) {
	for _, test := range []struct {
		goos   string
		goarch string
		want   string
	}{
		{goos: "linux", goarch: "amd64", want: "ssm-linux-amd64"},
		{goos: "linux", goarch: "arm64", want: "ssm-linux-arm64"},
		{goos: "darwin", goarch: "amd64", want: "ssm-darwin-amd64"},
		{goos: "darwin", goarch: "arm64", want: "ssm-darwin-arm64"},
		{goos: "windows", goarch: "amd64", want: "ssm-windows-amd64.exe"},
		{goos: "windows", goarch: "arm64", want: "ssm-windows-arm64.exe"},
	} {
		t.Run(test.goos+"-"+test.goarch, func(t *testing.T) {
			if got := AssetNameFor(test.goos, test.goarch); got != test.want {
				t.Fatalf("AssetNameFor(%q, %q) = %q, want %q", test.goos, test.goarch, got, test.want)
			}
		})
	}
}

func TestChecksumForAssetRequiresMatchingAsset(t *testing.T) {
	_, err := checksumForAsset([]byte(strings.Repeat("a", sha256.Size*2)+"  other\n"), "ssm-linux-amd64")
	if err == nil {
		t.Fatal("expected missing checksum error")
	}
}

func TestCopyAndVerifyRejectsChecksumMismatch(t *testing.T) {
	var out strings.Builder
	err := copyAndVerify(&out, strings.NewReader("payload"), sha256.New(), strings.Repeat("0", sha256.Size*2))
	if err == nil {
		t.Fatal("expected checksum mismatch")
	}
}

func TestDownloadVersionVerifiesChecksumBeforeReplace(t *testing.T) {
	restoreUpdateTestHooks(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	exe := filepath.Join(t.TempDir(), "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/releases/download/v9.9.9/checksums.txt":
			fmt.Fprintf(w, "%s  %s\n", strings.Repeat("0", sha256.Size*2), assetName())
		case "/owner/repo/releases/download/v9.9.9/" + assetName():
			_, _ = w.Write([]byte("new"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	downloadBaseURL = server.URL
	httpClient = server.Client()

	err := DownloadVersion("v9.9.9", false)
	if err == nil {
		t.Fatal("expected checksum mismatch")
	}
	data, readErr := os.ReadFile(exe)
	if readErr != nil {
		t.Fatalf("read executable: %v", readErr)
	}
	if string(data) != "old" {
		t.Fatalf("executable was replaced despite checksum mismatch: %q", data)
	}
}

func TestDownloadVersionReplacesAfterChecksumMatch(t *testing.T) {
	restoreUpdateTestHooks(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	exe := filepath.Join(t.TempDir(), "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("new")
	sum := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/releases/download/v9.9.9/checksums.txt":
			fmt.Fprintf(w, "%x  %s\n", sum, assetName())
		case "/owner/repo/releases/download/v9.9.9/" + assetName():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	downloadBaseURL = server.URL
	httpClient = server.Client()

	if err := DownloadVersion("v9.9.9", false); err != nil {
		t.Fatalf("DownloadVersion: %v", err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatalf("read executable: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("executable = %q, want %q", data, payload)
	}
}

func TestCheckLatestUsesInjectedHTTPClient(t *testing.T) {
	restoreUpdateTestHooks(t)
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/releases/latest" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9"}`))
	}))
	defer server.Close()
	apiBaseURL = server.URL
	httpClient = server.Client()

	got, err := checkLatest()
	if err != nil {
		t.Fatalf("checkLatest: %v", err)
	}
	if got != "v9.9.9" {
		t.Fatalf("latest = %q", got)
	}
}

func restoreUpdateTestHooks(t *testing.T) {
	t.Helper()
	oldHTTPClient := httpClient
	oldAPIBaseURL := apiBaseURL
	oldDownloadBaseURL := downloadBaseURL
	oldExecutablePath := executablePath
	oldEvalSymlinks := evalSymlinks
	t.Cleanup(func() {
		httpClient = oldHTTPClient
		apiBaseURL = oldAPIBaseURL
		downloadBaseURL = oldDownloadBaseURL
		executablePath = oldExecutablePath
		evalSymlinks = oldEvalSymlinks
	})
	httpClient = &http.Client{}
	apiBaseURL = "https://api.github.com"
	downloadBaseURL = "https://github.com"
	executablePath = os.Executable
	evalSymlinks = filepath.EvalSymlinks
}
