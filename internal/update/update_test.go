package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ssm/internal/provenance"
	"ssm/internal/provenancefixture"
	"ssm/internal/releaseasset"
)

func TestAutoV2LatestDoesNotRequestAssetsOrReplace(t *testing.T) {
	restoreUpdateTestHooks(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	original := []byte("v1 executable bytes")
	exe := filepath.Join(t.TempDir(), "ssm")
	if err := os.WriteFile(exe, original, 0755); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	assetRequests := 0
	replacement := []byte("unattended v2 replacement")
	replacementDigest := sha256.Sum256(replacement)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/releases/latest":
			_, _ = w.Write([]byte(`{"tag_name":"v2.0.0"}`))
		case "/repos/owner/repo/releases":
			_, _ = w.Write([]byte(`[{"tag_name":"v2.0.0"}]`))
		case "/owner/repo/releases/download/v2.0.0/checksums.txt":
			assetRequests++
			_, _ = fmt.Fprintf(w, "%x  %s\n", replacementDigest, assetName())
		case "/owner/repo/releases/download/v2.0.0/" + assetName():
			assetRequests++
			_, _ = w.Write(replacement)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	apiBaseURL = server.URL
	downloadBaseURL = server.URL
	httpClient = server.Client()

	if err := Auto("1.4.4"); err != nil {
		t.Fatalf("Auto: %v", err)
	}
	if assetRequests != 0 {
		t.Fatalf("v2 asset requests = %d, want 0", assetRequests)
	}
	installed, err := os.ReadFile(exe) //nolint:gosec // exe is a test-owned executable path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, original) {
		t.Fatalf("executable changed to %q", installed)
	}
}

func TestSameMajorSelection(t *testing.T) {
	releases := []Release{
		{TagName: "v3.0.0"},
		{TagName: "v2.0.0"},
		{TagName: "v2.1.0"},
		{TagName: "v1.4.5"},
		{TagName: "v1.9.0", Prerelease: true},
		{TagName: "v1.4.6"},
		{TagName: "v1.04.7"},
		{TagName: "not-a-version"},
	}
	sameMajor, crossMajor := SelectRelease(releases, "1.4.4")
	if sameMajor == nil || sameMajor.TagName != "v1.4.6" {
		t.Fatalf("same-major release = %#v", sameMajor)
	}
	if crossMajor == nil || crossMajor.TagName != "v2.1.0" {
		t.Fatalf("cross-major release = %#v", crossMajor)
	}
}

func TestOrdinaryDownloadReportsV2WithoutAssetRequestOrReplacement(t *testing.T) {
	restoreUpdateTestHooks(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	original := []byte("ordinary v1 executable")
	exe := filepath.Join(t.TempDir(), "ssm")
	if err := os.WriteFile(exe, original, 0755); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	assetRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/releases":
			_, _ = w.Write([]byte(`[{"tag_name":"v2.0.0"}]`))
		default:
			assetRequests++
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	apiBaseURL = server.URL
	downloadBaseURL = server.URL
	httpClient = server.Client()

	result, err := Download("1.4.4")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if result.Installed != "" || result.CrossMajorAvailable != "v2.0.0" {
		t.Fatalf("ordinary result = %#v", result)
	}
	if assetRequests != 0 {
		t.Fatalf("v2 asset requests = %d, want 0", assetRequests)
	}
	installed, err := os.ReadFile(exe) //nolint:gosec // exe is a test-owned executable path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, original) {
		t.Fatalf("executable changed to %q", installed)
	}
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

func TestDownloadVersionReplacesAfterChecksumAndProvenanceMatch(t *testing.T) {
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
	claims, err := provenancefixture.DefaultClaims(assetName(), "v9.9.9", payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{TrustedMaterial: fixture.TrustedMaterial})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/releases/download/v9.9.9/checksums.txt":
			fmt.Fprintf(w, "%x  %s\n", sum, assetName())
		case "/owner/repo/releases/download/v9.9.9/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write(fixture.Bundle)
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
	oldVerifyProvenance := verifyProvenance
	oldUnixReplacementTestHook := unixReplacementTestHook
	t.Cleanup(func() {
		httpClient = oldHTTPClient
		apiBaseURL = oldAPIBaseURL
		downloadBaseURL = oldDownloadBaseURL
		executablePath = oldExecutablePath
		evalSymlinks = oldEvalSymlinks
		verifyProvenance = oldVerifyProvenance
		unixReplacementTestHook = oldUnixReplacementTestHook
	})
	httpClient = &http.Client{}
	apiBaseURL = "https://api.github.com"
	downloadBaseURL = "https://github.com"
	executablePath = os.Executable
	evalSymlinks = filepath.EvalSymlinks
	verifyProvenance = provenance.VerifyPublicGoodBundle
	unixReplacementTestHook = nil
}
