package update

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/config"
	"ssm/internal/privatepath"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func setTestHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

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

func TestSameMajorSelection(t *testing.T) {
	releases := []Release{
		{TagName: "v3.1.0"},
		{TagName: "v2.0.0"},
		{TagName: "v2.1.0"},
		{TagName: "v1.6.0"},
		{TagName: "v1.5.9"},
		{TagName: "v1.7.0-rc.1", Prerelease: true},
		{TagName: "malformed"},
		{TagName: "v0.9.0"},
	}
	got, crossMajor := SelectRelease(releases, "v1.5.0")
	if got == nil || got.TagName != "v1.6.0" {
		t.Fatalf("same-major release = %#v, want v1.6.0", got)
	}
	if crossMajor == nil || crossMajor.TagName != "v3.1.0" {
		t.Fatalf("cross-major release = %#v, want highest newer semantic version v3.1.0", crossMajor)
	}

	for _, current := range []string{"", "dev", "v1.5", "v1.5.0-rc.1", "v1.5.0+build"} {
		t.Run(current, func(t *testing.T) {
			same, major := SelectRelease(releases, current)
			if same != nil || major != nil {
				t.Fatalf("SelectRelease for unsupported current %q = %#v, %#v; want nil, nil", current, same, major)
			}
		})
	}
}

func TestMajorPreflightUsesExplicitMasterPassFile(t *testing.T) {
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	const password = "explicit-master-pass"
	if err := config.Save(&config.Vault{}, password); err != nil {
		t.Fatal(err)
	}
	passPath := filepath.Join(t.TempDir(), "master-pass")
	if err := os.WriteFile(passPath, []byte(password+"\n"), 0o600); err != nil { //nolint:gosec // test-owned credential fixture requires private mode
		t.Fatal(err)
	}
	t.Setenv("SSM_MASTER_PASS_FILE", "")
	check := checkPendingRecovery(passPath)
	if check.Status != "passed" {
		t.Fatalf("explicit master-pass preflight = %#v", check)
	}
}

func TestCrossMajorRequiresExplicitAuthorization(t *testing.T) {
	restoreUpdateTestHooks(t)
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")
	exe := filepath.Join(t.TempDir(), "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil { //nolint:gosec // test-owned executable must retain executable mode
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }
	payload := []byte("new-major")
	httpClient = migrationHTTPClient(t, "v2.0.0", payload, true)

	review, err := ReviewMajor("v1.4.3", false, "")
	if err != nil {
		t.Fatalf("non-authorized review: %v", err)
	}
	if review.Authorized || review.Installed || review.Target != "v2.0.0" || len(review.BreakingChanges) != 10 {
		t.Fatalf("review = %#v", review)
	}
	assertExecutableBytes(t, exe, "old")

	httpClient = migrationHTTPClient(t, "v2.0.0", payload, true)
	review, err = ReviewMajor("v1.4.3", true, "")
	if err != nil {
		t.Fatalf("authorized migration review: %v", err)
	}
	if !review.Authorized || review.Installed {
		t.Fatalf("authorized pre-replacement review = %#v", review)
	}
	assertExecutableBytes(t, exe, "old")

	callbackCalled := false
	err = DownloadVersionBeforeReplace(review.Target, false, func() error {
		callbackCalled = true
		assertExecutableBytes(t, exe, "old")
		return nil
	})
	if err != nil {
		t.Fatalf("authorized migration install: %v", err)
	}
	if !callbackCalled {
		t.Fatal("pre-replacement review callback was not called")
	}
	assertExecutableBytes(t, exe, string(payload))
}

func TestFailedMigrationPreservesExecutable(t *testing.T) {
	restoreUpdateTestHooks(t)
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")
	exe := filepath.Join(t.TempDir(), "ssm")
	if err := os.WriteFile(exe, []byte("byte-for-byte-old"), 0o751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation coverage
		t.Fatal(err)
	}
	before, err := os.ReadFile(exe) //nolint:gosec // path is constrained to t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }
	httpClient = migrationHTTPClient(t, "v2.0.0", []byte("replacement"), false)

	review, err := ReviewMajor("v1.4.3", true, "")
	if err != nil || !review.Authorized || review.Installed {
		t.Fatalf("migration review=%#v err=%v", review, err)
	}
	callbackCalled := false
	err = DownloadVersionBeforeReplace(review.Target, false, func() error {
		callbackCalled = true
		return nil
	})
	if err == nil || callbackCalled {
		t.Fatalf("failed migration callback=%t err=%v", callbackCalled, err)
	}
	after, readErr := os.ReadFile(exe) //nolint:gosec // path is constrained to t.TempDir
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(before) {
		t.Fatalf("executable changed: got %q want %q", after, before)
	}
}

func migrationHTTPClient(t *testing.T, version string, payload []byte, validDigest bool) *http.Client {
	t.Helper()
	digest := sha256.Sum256(payload)
	sum := fmt.Sprintf("%x", digest)
	if !validDigest {
		sum = strings.Repeat("0", sha256.Size*2)
	}
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		var body string
		switch path {
		case "/repos/owner/repo/releases":
			body = fmt.Sprintf(`[{"tag_name":%q,"name":"SSM v2","body":"v2 migration release notes","assets":[{"name":%q}]}]`, version, assetName())
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			body = fmt.Sprintf("%s  %s\n", sum, assetName())
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			body = string(payload)
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
}

func assertExecutableBytes(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // callers pass only test-owned executable paths beneath t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("executable = %q, want %q", data, want)
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
	setTestHome(t, home)
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
	setTestHome(t, home)

	markChecked("v9.9.9")

	path := filepath.Join(home, ".config", "ssm", ".update-available")
	if err := privatepath.VerifyFile(path); err != nil {
		t.Fatalf("update flag is not private: %v", err)
	}
	if err := privatepath.VerifyDirectory(filepath.Dir(path)); err != nil {
		t.Fatalf("update flag directory is not private: %v", err)
	}
}

func TestAutoPreservesCrossMajorAvailabilityAfterSameMajorInstall(t *testing.T) {
	restoreUpdateTestHooks(t)
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")
	exe := filepath.Join(t.TempDir(), "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil { //nolint:gosec // test-owned executable must retain executable mode
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }
	payload := []byte("same-major")
	digest := sha256.Sum256(payload)
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body string
		switch request.URL.Path {
		case "/repos/owner/repo/releases":
			body = fmt.Sprintf(`[{"tag_name":"v2.0.0"},{"tag_name":"v1.5.0","assets":[{"name":%q}]}]`, assetName())
		case "/owner/repo/releases/download/v1.5.0/checksums.txt":
			body = fmt.Sprintf("%x  %s\n", digest, assetName())
		case "/owner/repo/releases/download/v1.5.0/" + assetName():
			body = string(payload)
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body))}, nil
	})}

	if err := Auto("v1.4.3"); err != nil {
		t.Fatalf("Auto: %v", err)
	}
	assertExecutableBytes(t, exe, string(payload))
	flag, err := os.ReadFile(flagPath()) //nolint:gosec // flagPath is rooted in the test HOME
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(flag), "v2.0.0\n") {
		t.Fatalf("cross-major flag = %q, want v2.0.0", flag)
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
	setTestHome(t, home)
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
	setTestHome(t, home)
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
