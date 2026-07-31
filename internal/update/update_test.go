package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	bundlev1 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"ssm/internal/config"
	"ssm/internal/privatepath"
	"ssm/internal/provenance"
	"ssm/internal/provenancefixture"
	"ssm/internal/releaseasset"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(data []byte) (int, error) {
	return f(data)
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

func TestCleanupPreviousExecutableSurfacesResolutionFailures(t *testing.T) {
	if runtime.GOOS != "windows" {
		restoreUpdateTestHooks(t)
		resolverCalled := false
		executablePath = func() (string, error) {
			resolverCalled = true
			return "", errors.New("executable path unavailable")
		}
		evalSymlinks = func(string) (string, error) {
			resolverCalled = true
			return "", errors.New("canonical path unavailable")
		}
		if err := CleanupPreviousExecutable(); err != nil {
			t.Fatalf("non-Windows cleanup = %v, want no-op", err)
		}
		if resolverCalled {
			t.Fatal("non-Windows cleanup resolved the executable path")
		}
		return
	}

	t.Run("executable path", func(t *testing.T) {
		restoreUpdateTestHooks(t)
		executablePath = func() (string, error) {
			return "", errors.New("executable path unavailable")
		}

		err := CleanupPreviousExecutable()
		if err == nil || !strings.Contains(err.Error(), "find current executable") {
			t.Fatalf("cleanup error = %v, want executable-path failure", err)
		}
	})

	t.Run("canonical path", func(t *testing.T) {
		restoreUpdateTestHooks(t)
		executablePath = func() (string, error) {
			return filepath.Join(t.TempDir(), "ssm"), nil
		}
		evalSymlinks = func(string) (string, error) {
			return "", errors.New("canonical path unavailable")
		}

		err := CleanupPreviousExecutable()
		if err == nil || !strings.Contains(err.Error(), "resolve current executable") {
			t.Fatalf("cleanup error = %v, want canonical-path failure", err)
		}
	})
}

func TestWindowsRecoveryFailureDispositionIsStableThroughWrapping(t *testing.T) {
	ordinary := errors.New("ordinary update failure")
	if IsRecoveryRequired(ordinary) || IsRecoveryBlocked(ordinary) {
		t.Fatal("ordinary update failure acquired a Windows recovery disposition")
	}

	recovery := fmt.Errorf("replacement failed: %w", requireRecovery(errors.New("rollback refused")))
	if !IsRecoveryRequired(recovery) || IsRecoveryBlocked(recovery) {
		t.Fatal("authenticated rollback refusal lost its recovery-required disposition")
	}
	if got := blockOnRecoveryEvidence(recovery); got != recovery {
		t.Fatal("recovery-required disposition was replaced while propagating cleanup failure")
	}

	blocked := fmt.Errorf("cleanup failed: %w", blockOnRecoveryEvidence(errors.New("record mismatch")))
	if IsRecoveryRequired(blocked) || !IsRecoveryBlocked(blocked) {
		t.Fatal("untrusted recovery evidence acquired the wrong disposition")
	}

	preserved := fmt.Errorf("cleanup failed: %w", preserveCanonical(errors.New("record removal refused")))
	if IsRecoveryRequired(preserved) || IsRecoveryBlocked(preserved) {
		t.Fatal("exact-canonical cleanup failure acquired a pending-recovery disposition")
	}
	if got := blockOnRecoveryEvidence(preserved); got != preserved {
		t.Fatal("exact-canonical cleanup failure lost its ordinary disposition")
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
	claims, err := provenancefixture.DefaultClaims(assetName(), version, payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}
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
			body = fmt.Sprintf(
				`[{"tag_name":%q,"name":"SSM v2","body":"v2 migration release notes","assets":[%s]}]`,
				version,
				releaseAssetMetadataJSON(),
			)
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			body = fmt.Sprintf("%s  %s\n", sum, assetName())
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			body = string(fixture.Bundle)
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

func assertExecutablePreserved(t *testing.T, path string, want []byte, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // callers pass only test-owned executable paths beneath t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) || info.Mode().Perm() != mode {
		t.Fatalf(
			"executable was not preserved: bytes_equal=%t mode=%o want_mode=%o",
			bytes.Equal(data, want),
			info.Mode().Perm(),
			mode,
		)
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
	claims, err := provenancefixture.DefaultClaims(assetName(), "v1.5.0", payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}
	digest := sha256.Sum256(payload)
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body string
		switch request.URL.Path {
		case "/repos/owner/repo/releases":
			body = fmt.Sprintf(`[{"tag_name":"v2.0.0"},{"tag_name":"v1.5.0","assets":[%s]}]`, releaseAssetMetadataJSON())
		case "/owner/repo/releases/download/v1.5.0/checksums.txt":
			body = fmt.Sprintf("%x  %s\n", digest, assetName())
		case "/owner/repo/releases/download/v1.5.0/" + releaseasset.ProvenanceName(assetName()):
			body = string(fixture.Bundle)
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

func TestReleaseAssetSelectionIsStrict(t *testing.T) {
	valid := Release{TagName: "v1.5.0"}
	for _, name := range releaseasset.ExpectedReleaseNames() {
		valid.Assets = append(valid.Assets, struct {
			Name string `json:"name"`
		}{Name: name})
	}
	if err := validateReleaseAssets(valid); err != nil {
		t.Fatalf("valid release asset manifest: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*Release)
	}{
		{
			name: "missing provenance",
			mutate: func(release *Release) {
				missing := releaseasset.ProvenanceName(releaseasset.Name("linux", "amd64"))
				for index, asset := range release.Assets {
					if asset.Name == missing {
						release.Assets = append(release.Assets[:index], release.Assets[index+1:]...)
						return
					}
				}
				t.Fatalf("test release lacks provenance fixture %q", missing)
			},
		},
		{
			name: "misnamed asset",
			mutate: func(release *Release) {
				release.Assets[0].Name += ".zip"
			},
		},
		{
			name: "duplicate asset",
			mutate: func(release *Release) {
				release.Assets = append(release.Assets, release.Assets[0])
			},
		},
		{
			name: "unsupported asset",
			mutate: func(release *Release) {
				release.Assets = append(release.Assets, struct {
					Name string `json:"name"`
				}{Name: "ssm-freebsd-amd64"})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			release := valid
			release.Assets = append([]struct {
				Name string `json:"name"`
			}(nil), valid.Assets...)
			test.mutate(&release)
			if err := validateReleaseAssets(release); err == nil {
				t.Fatal("invalid release asset manifest was accepted")
			}
		})
	}
}

func TestInvalidSelectedReleaseDoesNotFallBackOrDownload(t *testing.T) {
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	validAssets := make([]string, 0, len(releaseasset.ExpectedReleaseNames()))
	for _, name := range releaseasset.ExpectedReleaseNames() {
		validAssets = append(validAssets, fmt.Sprintf(`{"name":%q}`, name))
	}
	var paths []string
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		paths = append(paths, request.URL.Path)
		body := fmt.Sprintf(
			`[{"tag_name":"v1.6.0","assets":[{"name":"ssm-linux-amd64.zip"}]},{"tag_name":"v1.5.0","assets":[%s]}]`,
			strings.Join(validAssets, ","),
		)
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})}

	if _, err := Download("v1.4.3"); err == nil {
		t.Fatal("invalid selected release fell back or proceeded to download")
	}
	if want := []string{"/repos/owner/repo/releases"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("invalid selected release request paths = %q, want %q", paths, want)
	}
}

func TestOversizedReleaseMetadataPreservesExecutable(t *testing.T) {
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	exe := filepath.Join(t.TempDir(), "ssm")
	original := []byte("original executable bytes")
	if err := os.WriteFile(exe, original, 0o751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
		t.Fatal(err)
	}
	before, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	const version = "v1.5.0"
	payload := []byte("replacement bytes")
	claims, err := provenancefixture.DefaultClaims(assetName(), version, payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}
	metadata := fmt.Sprintf(
		`[{"tag_name":%q,"assets":[%s]}]`,
		version,
		releaseAssetMetadataJSON(),
	)
	metadata += strings.Repeat(" ", (1<<20)+1-len(metadata))
	digest := sha256.Sum256(payload)
	var paths []string
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		paths = append(paths, request.URL.Path)
		var body []byte
		switch request.URL.Path {
		case "/repos/owner/repo/releases":
			body = []byte(metadata)
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			body = []byte(fmt.Sprintf("%x  %s\n", digest, assetName()))
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			body = fixture.Bundle
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			body = payload
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Status:     "404 Not Found",
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(bytes.NewReader(body)),
		}, nil
	})}

	if _, err := Download("v1.4.3"); err == nil {
		t.Fatal("oversized release metadata authorized replacement")
	}
	assertExecutablePreserved(t, exe, original, before.Mode().Perm())
	if want := []string{"/repos/owner/repo/releases"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("oversized metadata request paths = %q, want metadata only %q", paths, want)
	}
}

func TestChecksumForAssetRequiresMatchingAsset(t *testing.T) {
	_, err := checksumForAsset([]byte(strings.Repeat("a", sha256.Size*2)+"  other\n"), "ssm-linux-amd64")
	if err == nil {
		t.Fatal("expected missing checksum error")
	}
}

func TestChecksumForAssetRejectsDuplicate(t *testing.T) {
	line := strings.Repeat("a", sha256.Size*2) + "  ssm-linux-amd64\n"
	if _, err := checksumForAsset([]byte(line+line), "ssm-linux-amd64"); err == nil {
		t.Fatal("duplicate checksum records were accepted")
	}
}

func TestOversizedChecksumPreservesExecutable(t *testing.T) {
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	exe := filepath.Join(t.TempDir(), "ssm")
	original := []byte("original executable bytes")
	if err := os.WriteFile(exe, original, 0o751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
		t.Fatal(err)
	}
	before, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	const version = "v9.9.9"
	payload := []byte("replacement bytes")
	claims, err := provenancefixture.DefaultClaims(assetName(), version, payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}
	digest := sha256.Sum256(payload)
	checksums := fmt.Sprintf("%x  %s\n", digest, assetName()) + strings.Repeat(" ", (16<<10)+1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			_, _ = io.WriteString(w, checksums)
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write(fixture.Bundle)
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	downloadBaseURL = server.URL
	httpClient = server.Client()

	if err := DownloadVersion(version, false); err == nil {
		t.Fatal("oversized checksum data authorized replacement")
	}
	assertExecutablePreserved(t, exe, original, before.Mode().Perm())
}

func TestOversizedProvenanceBundlePreservesExecutable(t *testing.T) {
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	exe := filepath.Join(t.TempDir(), "ssm")
	original := []byte("original executable bytes")
	if err := os.WriteFile(exe, original, 0o751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
		t.Fatal(err)
	}
	before, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	const version = "v9.9.9"
	payload := []byte("replacement bytes")
	claims, err := provenancefixture.DefaultClaims(assetName(), version, payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}
	oversizedBundle := append([]byte(nil), fixture.Bundle...)
	oversizedBundle = append(oversizedBundle, bytes.Repeat([]byte(" "), (1<<20)+1-len(oversizedBundle))...)
	digest := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%x  %s\n", digest, assetName())
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write(oversizedBundle)
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	downloadBaseURL = server.URL
	httpClient = server.Client()

	if err := DownloadVersion(version, false); err == nil {
		t.Fatal("oversized provenance bundle authorized replacement")
	}
	assertExecutablePreserved(t, exe, original, before.Mode().Perm())
}

func TestOversizedBinaryContentLengthPreservesExecutable(t *testing.T) {
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	original := []byte("original executable bytes")
	if err := os.WriteFile(exe, original, 0o751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
		t.Fatal(err)
	}
	before, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }
	verifyProvenance = func(context.Context, []byte, provenance.Request) error {
		t.Fatal("provenance verifier ran for an oversized binary")
		return nil
	}

	const (
		version         = "v9.9.9"
		testBinaryLimit = 64 << 20
	)
	bodyRead := false
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body io.ReadCloser
		contentLength := int64(-1)
		switch request.URL.Path {
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			body = io.NopCloser(strings.NewReader(strings.Repeat("0", sha256.Size*2) + "  " + assetName() + "\n"))
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			body = io.NopCloser(strings.NewReader("{}"))
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			contentLength = testBinaryLimit + 1
			body = io.NopCloser(readerFunc(func([]byte) (int, error) {
				bodyRead = true
				return 0, io.EOF
			}))
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Status:     "404 Not Found",
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Body:          body,
			ContentLength: contentLength,
		}, nil
	})}

	err = DownloadVersion(version, false)
	if err == nil || !strings.Contains(err.Error(), "exceeds 67108864-byte limit") {
		t.Fatalf("oversized declared binary error = %v, want size-limit rejection", err)
	}
	if bodyRead {
		t.Fatal("updater read a binary whose declared length exceeded the limit")
	}
	assertExecutablePreserved(t, exe, original, before.Mode().Perm())
	staged, globErr := filepath.Glob(filepath.Join(directory, ".ssm.*.new"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(staged) != 0 {
		t.Fatalf("oversized binary retained staged artifacts: %q", staged)
	}
}

func TestRedirectedChunkedOversizedBinaryPreservesExecutable(t *testing.T) {
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	original := []byte("original executable bytes")
	if err := os.WriteFile(exe, original, 0o751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
		t.Fatal(err)
	}
	before, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }
	verifyProvenance = func(context.Context, []byte, provenance.Request) error {
		t.Fatal("provenance verifier ran for an oversized binary")
		return nil
	}

	const (
		version         = "v9.9.9"
		testBinaryLimit = 64 << 20
	)
	remaining := int64(testBinaryLimit + 8192)
	var readBytes int64
	sawRedirect := false
	sawChunkedBody := false
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body: io.NopCloser(strings.NewReader(
					strings.Repeat("0", sha256.Size*2) + "  " + assetName() + "\n",
				)),
				ContentLength: -1,
			}, nil
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			return &http.Response{
				StatusCode:    http.StatusOK,
				Status:        "200 OK",
				Body:          io.NopCloser(strings.NewReader("{}")),
				ContentLength: -1,
			}, nil
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			sawRedirect = true
			return &http.Response{
				StatusCode: http.StatusFound,
				Status:     "302 Found",
				Header: http.Header{
					"Location": []string{"https://downloads.example/final-binary"},
				},
				Body: io.NopCloser(strings.NewReader("")),
			}, nil
		case "/final-binary":
			sawChunkedBody = true
			return &http.Response{
				StatusCode:       http.StatusOK,
				Status:           "200 OK",
				ContentLength:    -1,
				TransferEncoding: []string{"chunked"},
				Body: io.NopCloser(readerFunc(func(data []byte) (int, error) {
					if remaining == 0 {
						return 0, io.EOF
					}
					if int64(len(data)) > remaining {
						data = data[:remaining]
					}
					for i := range data {
						data[i] = 'x'
					}
					n := len(data)
					remaining -= int64(n)
					readBytes += int64(n)
					return n, nil
				})),
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Status:     "404 Not Found",
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}
	})}
	downloadBaseURL = "https://releases.example"

	err = DownloadVersion(version, false)
	if err == nil || !strings.Contains(err.Error(), "exceeds 67108864-byte limit") {
		t.Fatalf("oversized chunked binary error = %v, want size-limit rejection", err)
	}
	if !sawRedirect || !sawChunkedBody {
		t.Fatalf("redirected chunked fixture redirect=%t final_body=%t", sawRedirect, sawChunkedBody)
	}
	if readBytes != testBinaryLimit+1 {
		t.Fatalf("oversized chunked binary bytes read = %d, want %d", readBytes, testBinaryLimit+1)
	}
	assertExecutablePreserved(t, exe, original, before.Mode().Perm())
	staged, globErr := filepath.Glob(filepath.Join(directory, ".ssm.*.new"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(staged) != 0 {
		t.Fatalf("oversized binary retained staged artifacts: %q", staged)
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
	if err := os.WriteFile(exe, []byte("old"), 0755); err != nil { //nolint:gosec // test-owned executable fixture requires executable permissions
		t.Fatalf("write executable: %v", err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }
	verifyProvenance = func(context.Context, []byte, provenance.Request) error {
		t.Fatal("provenance verifier ran after checksum mismatch")
		return nil
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/releases/download/v9.9.9/checksums.txt":
			_, _ = fmt.Fprintf(w, "%s  %s\n", strings.Repeat("0", sha256.Size*2), assetName())
		case "/owner/repo/releases/download/v9.9.9/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write([]byte("{}"))
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
	data, readErr := os.ReadFile(exe) //nolint:gosec // path is constrained to t.TempDir
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
	if err := os.WriteFile(exe, []byte("old"), 0755); err != nil { //nolint:gosec // test-owned executable fixture requires executable permissions
		t.Fatalf("write executable: %v", err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("new")
	claims, err := provenancefixture.DefaultClaims(assetName(), "v9.9.9", payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}
	sum := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/releases/download/v9.9.9/checksums.txt":
			_, _ = fmt.Fprintf(w, "%x  %s\n", sum, assetName())
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
	data, err := os.ReadFile(exe) //nolint:gosec // path is constrained to t.TempDir
	if err != nil {
		t.Fatalf("read executable: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("executable = %q, want %q", data, payload)
	}
}

func TestProvenanceIdentityMatrix(t *testing.T) {
	t.Run("adjacent checksum without provenance", func(t *testing.T) {
		restoreUpdateTestHooks(t)
		setTestHome(t, t.TempDir())
		t.Setenv("SSM_UPDATE_REPO", "owner/repo")

		exe := filepath.Join(t.TempDir(), "ssm")
		if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil { //nolint:gosec // test-owned executable fixture
			t.Fatal(err)
		}
		executablePath = func() (string, error) { return exe, nil }
		evalSymlinks = func(path string) (string, error) { return path, nil }

		payload := []byte("checksum-only replacement")
		sum := sha256.Sum256(payload)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/owner/repo/releases/download/v9.9.9/checksums.txt":
				_, _ = fmt.Fprintf(w, "%x  %s\n", sum, assetName())
			case "/owner/repo/releases/download/v9.9.9/" + assetName():
				_, _ = w.Write(payload)
			default:
				http.NotFound(w, request)
			}
		}))
		defer server.Close()
		downloadBaseURL = server.URL
		httpClient = server.Client()

		if err := DownloadVersion("v9.9.9", false); err == nil {
			t.Fatal("checksum-only replacement succeeded without provenance")
		}
		assertExecutableBytes(t, exe, "old")
	})

	for _, test := range []struct {
		name   string
		bundle []byte
	}{
		{name: "empty provenance", bundle: []byte{}},
		{name: "malformed provenance", bundle: []byte("{")},
	} {
		t.Run(test.name, func(t *testing.T) {
			restoreUpdateTestHooks(t)
			setTestHome(t, t.TempDir())
			t.Setenv("SSM_UPDATE_REPO", "owner/repo")

			exe := filepath.Join(t.TempDir(), "ssm")
			if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil { //nolint:gosec // test-owned executable fixture
				t.Fatal(err)
			}
			executablePath = func() (string, error) { return exe, nil }
			evalSymlinks = func(path string) (string, error) { return path, nil }

			payload := []byte("replacement with invalid provenance")
			sum := sha256.Sum256(payload)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/owner/repo/releases/download/v9.9.9/checksums.txt":
					_, _ = fmt.Fprintf(w, "%x  %s\n", sum, assetName())
				case "/owner/repo/releases/download/v9.9.9/" + releaseasset.ProvenanceName(assetName()):
					_, _ = w.Write(test.bundle)
				case "/owner/repo/releases/download/v9.9.9/" + assetName():
					_, _ = w.Write(payload)
				default:
					http.NotFound(w, request)
				}
			}))
			defer server.Close()
			downloadBaseURL = server.URL
			httpClient = server.Client()

			if err := DownloadVersion("v9.9.9", false); err == nil {
				t.Fatalf("replacement succeeded with %s", test.name)
			}
			assertExecutableBytes(t, exe, "old")
		})
	}

	for _, test := range []struct {
		name              string
		mutate            func(*provenancefixture.Claims)
		tamperSignature   bool
		identityNotBefore time.Time
		identityNotAfter  time.Time
		wantSuccess       bool
	}{
		{name: "accepted release tag identity", wantSuccess: true},
		{
			name: "unversioned main identity replay",
			mutate: func(claims *provenancefixture.Claims) {
				claims.Ref = "refs/heads/main"
			},
		},
		{
			name: "older release tag downgrade",
			mutate: func(claims *provenancefixture.Claims) {
				claims.Ref = "refs/tags/v9.9.8"
			},
		},
		{name: "cryptographically unverifiable provenance", tamperSignature: true},
		{
			name: "wrong repository",
			mutate: func(claims *provenancefixture.Claims) {
				claims.Repository = "attacker/ssm"
			},
		},
		{
			name: "wrong workflow",
			mutate: func(claims *provenancefixture.Claims) {
				claims.Workflow = ".github/workflows/unreviewed.yml"
			},
		},
		{
			name: "wrong issuer",
			mutate: func(claims *provenancefixture.Claims) {
				claims.Issuer = "https://issuer.example.invalid"
			},
		},
		{
			name: "wrong runner",
			mutate: func(claims *provenancefixture.Claims) {
				claims.Runner = "self-hosted"
			},
		},
		{
			name: "wrong predicate",
			mutate: func(claims *provenancefixture.Claims) {
				claims.PredicateType = "https://example.invalid/unreviewed-predicate/v1"
			},
		},
		{
			name: "additional subject",
			mutate: func(claims *provenancefixture.Claims) {
				claims.AdditionalSubjectNames = []string{"unreviewed-release-asset"}
			},
		},
		{
			name: "additional digest algorithm",
			mutate: func(claims *provenancefixture.Claims) {
				claims.AdditionalDigestValues = map[string]string{"sha512": strings.Repeat("a", 128)}
			},
		},
		{
			name: "non-SHA-256-only digest",
			mutate: func(claims *provenancefixture.Claims) {
				claims.ExcludeSHA256SubjectHash = true
				claims.AdditionalDigestValues = map[string]string{"sha512": strings.Repeat("b", 128)}
			},
		},
		{
			name: "not yet valid certificate",
			mutate: func(claims *provenancefixture.Claims) {
				claims.NotBefore = time.Now().Add(time.Hour)
				claims.NotAfter = time.Now().Add(2 * time.Hour)
			},
		},
		{
			name: "expired certificate",
			mutate: func(claims *provenancefixture.Claims) {
				claims.NotBefore = time.Now().Add(-2 * time.Hour)
				claims.NotAfter = time.Now().Add(-time.Hour)
			},
		},
		{
			name:              "not yet active identity rotation state",
			identityNotBefore: time.Now().Add(time.Hour),
		},
		{
			name:             "expired identity rotation state",
			identityNotAfter: time.Now().Add(-time.Hour),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			restoreUpdateTestHooks(t)
			setTestHome(t, t.TempDir())
			t.Setenv("SSM_UPDATE_REPO", "owner/repo")

			exe := filepath.Join(t.TempDir(), "ssm")
			if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil { //nolint:gosec // test-owned executable fixture
				t.Fatal(err)
			}
			executablePath = func() (string, error) { return exe, nil }
			evalSymlinks = func(path string) (string, error) { return path, nil }

			const version = "v9.9.9"
			payload := []byte("synthetic keyless replacement")
			claims, err := provenancefixture.DefaultClaims(assetName(), version, payload)
			if err != nil {
				t.Fatal(err)
			}
			if test.mutate != nil {
				test.mutate(&claims)
			}
			fixture, err := provenancefixture.Generate(claims)
			if err != nil {
				t.Fatal(err)
			}
			bundle := fixture.Bundle
			if test.tamperSignature {
				bundle = tamperProvenanceSignature(t, bundle)
			}
			identities, err := provenance.AcceptedIdentities(version)
			if err != nil {
				t.Fatal(err)
			}
			if !test.identityNotBefore.IsZero() {
				for index := range identities {
					identities[index].NotBefore = test.identityNotBefore
				}
			}
			if !test.identityNotAfter.IsZero() {
				for index := range identities {
					identities[index].NotAfter = test.identityNotAfter
				}
			}
			verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
				return provenance.VerifyBundle(bundle, request, provenance.Options{
					TrustedMaterial: fixture.TrustedMaterial,
					Identities:      identities,
				})
			}

			sum := sha256.Sum256(payload)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/owner/repo/releases/download/" + version + "/checksums.txt":
					_, _ = fmt.Fprintf(w, "%x  %s\n", sum, assetName())
				case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
					_, _ = w.Write(bundle)
				case "/owner/repo/releases/download/" + version + "/" + assetName():
					_, _ = w.Write(payload)
				default:
					http.NotFound(w, request)
				}
			}))
			defer server.Close()
			downloadBaseURL = server.URL
			httpClient = server.Client()

			err = DownloadVersion(version, false)
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("accepted provenance failed: %v", err)
				}
				assertExecutableBytes(t, exe, string(payload))
				return
			}
			if err == nil {
				t.Fatal("unaccepted provenance replaced the executable")
			}
			assertExecutableBytes(t, exe, "old")
		})
	}
}

func TestProvenanceDigestBinding(t *testing.T) {
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	exe := filepath.Join(t.TempDir(), "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	const version = "v9.9.9"
	downloaded := []byte("downloaded release bytes")
	claims, err := provenancefixture.DefaultClaims(assetName(), version, []byte("different attested bytes"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}

	releaseDigest := sha256.Sum256(downloaded)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%x  %s\n", releaseDigest, assetName())
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write(fixture.Bundle)
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			_, _ = w.Write(downloaded)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	downloadBaseURL = server.URL
	httpClient = server.Client()

	if err := DownloadVersion(version, false); err == nil {
		t.Fatal("downloaded digest matched release data but not provenance")
	}
	assertExecutableBytes(t, exe, "old")
}

func TestTrustFailurePreservesExecutable(t *testing.T) {
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	exe := filepath.Join(t.TempDir(), "ssm")
	original := []byte("byte-for-byte original executable")
	if err := os.WriteFile(exe, original, 0o751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
		t.Fatal(err)
	}
	before, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	const version = "v9.9.9"
	payload := []byte("replacement with wrong signed subject")
	claims, err := provenancefixture.DefaultClaims("ssm-linux-unsupported", version, payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}

	sum := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%x  %s\n", sum, assetName())
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write(fixture.Bundle)
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	downloadBaseURL = server.URL
	httpClient = server.Client()

	callbackCalled := false
	err = DownloadVersionBeforeReplace(version, false, func() error {
		callbackCalled = true
		return nil
	})
	if err == nil || callbackCalled {
		t.Fatalf("trust failure error=%v callback_called=%t", err, callbackCalled)
	}
	after, err := os.ReadFile(exe) //nolint:gosec // path is constrained to t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) || afterInfo.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf(
			"trust failure changed executable: bytes_equal=%t mode=%o want_mode=%o",
			bytes.Equal(after, original),
			afterInfo.Mode().Perm(),
			before.Mode().Perm(),
		)
	}
}

func TestUnixVerifiedReplacementRejectsCallbackSubstitution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated replacement")
	version := serveAuthenticatedUpdate(t, payload)

	callbackCalled := false
	err := DownloadVersionBeforeReplace(version, false, func() error {
		callbackCalled = true
		matches, globErr := filepath.Glob(filepath.Join(directory, ".ssm.*.new"))
		if globErr != nil || len(matches) != 1 {
			return fmt.Errorf("find authenticated stage: matches=%v err=%w", matches, globErr)
		}
		if renameErr := os.Rename(matches[0], matches[0]+".authenticated"); renameErr != nil {
			return fmt.Errorf("move authenticated stage: %w", renameErr)
		}
		if writeErr := os.WriteFile(matches[0], []byte("callback substitute"), 0o751); writeErr != nil { //nolint:gosec // adversarial test-owned replacement
			return fmt.Errorf("write callback substitute: %w", writeErr)
		}
		return nil
	})
	if !callbackCalled {
		t.Fatal("verified replacement did not reach callback")
	}
	if err == nil || !strings.Contains(err.Error(), "authenticated bytes") {
		t.Fatalf("callback substitution error = %v, want authenticated-byte rejection", err)
	}
	assertExecutablePreserved(t, exe, []byte("old"), 0o751)
}

func TestUnixVerifiedReplacementPreservesOriginalModeAcrossCallbackStagingChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable mode is the authoritative replacement mode
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated replacement with preserved mode")
	version := serveAuthenticatedUpdate(t, payload)

	callbackCalled := false
	err := DownloadVersionBeforeReplace(version, false, func() error {
		callbackCalled = true
		matches, globErr := filepath.Glob(filepath.Join(directory, ".ssm.*.new"))
		if globErr != nil || len(matches) != 1 {
			return fmt.Errorf("find authenticated stage: matches=%v err=%w", matches, globErr)
		}
		if chmodErr := os.Chmod(matches[0], 0o777); chmodErr != nil { //nolint:gosec // adversarial test-owned mode mutation is intentional
			return fmt.Errorf("change authenticated staging mode: %w", chmodErr)
		}
		return nil
	})
	if err != nil || !callbackCalled {
		t.Fatalf("verified replacement error=%v callback_called=%t", err, callbackCalled)
	}
	assertExecutablePreserved(t, exe, payload, 0o751)
}

func TestUnixVerifiedReplacementPreservesExecuteOnlyOriginalMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o700); err != nil { //nolint:gosec // mode is restricted below after fixture creation
		t.Fatal(err)
	}
	if err := os.Chmod(exe, 0o111); err != nil { //nolint:gosec // test-owned restrictive executable mode is the behavior under test
		t.Skipf("execute-only executable mode is not supported: %v", err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated execute-only replacement")
	version := serveAuthenticatedUpdate(t, payload)

	callbackCalled := false
	err := DownloadVersionBeforeReplace(version, false, func() error {
		callbackCalled = true
		return nil
	})
	if err != nil || !callbackCalled {
		t.Fatalf("execute-only replacement error=%v callback_called=%t", err, callbackCalled)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o111 {
		t.Fatalf("execute-only replacement mode = %o, want 111", info.Mode().Perm())
	}
	if err := os.Chmod(exe, 0o511); err != nil { //nolint:gosec // test-owned fixture is made readable only for byte verification
		t.Fatalf("make execute-only replacement readable for byte verification: %v", err)
	}
	assertExecutableBytes(t, exe, string(payload))
}

func TestUnixVerifiedReplacementUsesOpenedStageAcrossPathRename(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated opened replacement")
	version := serveAuthenticatedUpdate(t, payload)

	hookCalled := false
	unixReplacementTestHook = func(phase, staged, _ string) error {
		if phase != "source_open" {
			return nil
		}
		hookCalled = true
		if err := os.Rename(staged, staged+".opened"); err != nil {
			return fmt.Errorf("rename opened stage pathname: %w", err)
		}
		if err := os.WriteFile(staged, []byte("concurrent pathname replacement"), 0o751); err != nil { //nolint:gosec // adversarial test-owned replacement
			return fmt.Errorf("replace opened stage pathname: %w", err)
		}
		return nil
	}

	if err := DownloadVersion(version, false); err != nil {
		t.Fatalf("opened-stage replacement failed: %v", err)
	}
	if !hookCalled {
		t.Fatal("opened-stage pathname race did not reach the replacement seam")
	}
	assertExecutableBytes(t, exe, string(payload))
}

func TestUnixVerifiedReplacementRejectsInPlaceCopyMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated replacement before in-place mutation")
	version := serveAuthenticatedUpdate(t, payload)

	hookCalled := false
	unixReplacementTestHook = func(phase, _, install string) error {
		if phase != "copy_ready" {
			return nil
		}
		hookCalled = true
		file, err := os.OpenFile(install, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // adversarial test-owned mutation
		if err != nil {
			return fmt.Errorf("open authenticated copy for mutation: %w", err)
		}
		if _, err := file.Write([]byte("\nin-place mutation\n")); err != nil {
			_ = file.Close()
			return fmt.Errorf("mutate authenticated copy: %w", err)
		}
		return file.Close()
	}

	err := DownloadVersion(version, false)
	if !hookCalled {
		t.Fatal("in-place mutation did not reach the authenticated-copy race seam")
	}
	if err == nil || !strings.Contains(err.Error(), "authenticated bytes") {
		t.Fatalf("in-place copy mutation error = %v, want authenticated-byte rejection", err)
	}
	assertExecutableBytes(t, exe, "old")
}

func TestUnixVerifiedReplacementRejectsAuthenticatedCopyHardLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("authenticated replacement before hard link")
	version := serveAuthenticatedUpdate(t, payload)

	hookCalled := false
	unixReplacementTestHook = func(phase, _, install string) error {
		if phase != "copy_ready" {
			return nil
		}
		hookCalled = true
		if err := os.Link(install, install+".alias"); err != nil {
			return fmt.Errorf("create authenticated-copy hard link: %w", err)
		}
		return nil
	}

	err := DownloadVersion(version, false)
	if !hookCalled {
		t.Fatal("hard-link mutation did not reach the authenticated-copy race seam")
	}
	if err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("authenticated-copy hard-link error = %v, want hard-link rejection", err)
	}
	assertExecutableBytes(t, exe, "old")
}

func TestUnixVerifiedReplacementRejectsCallbackObjectMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix replacement contract")
	}
	for _, test := range []struct {
		name   string
		mutate func(string) error
	}{
		{
			name: "same path in place",
			mutate: func(stage string) error {
				file, err := os.OpenFile(stage, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // adversarial test-owned mutation
				if err != nil {
					return err
				}
				if _, err := file.Write([]byte("\ncallback mutation\n")); err != nil {
					_ = file.Close()
					return err
				}
				return file.Close()
			},
		},
		{
			name: "through hard link",
			mutate: func(stage string) error {
				alias := stage + ".alias"
				if err := os.Link(stage, alias); err != nil {
					return err
				}
				file, err := os.OpenFile(alias, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // adversarial test-owned mutation
				if err != nil {
					return err
				}
				if _, err := file.Write([]byte("\nhard-link mutation\n")); err != nil {
					_ = file.Close()
					return err
				}
				return file.Close()
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			restoreUpdateTestHooks(t)
			setTestHome(t, t.TempDir())
			t.Setenv("SSM_UPDATE_REPO", "owner/repo")

			directory := t.TempDir()
			exe := filepath.Join(directory, "ssm")
			if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable fixture
				t.Fatal(err)
			}
			executablePath = func() (string, error) { return exe, nil }
			evalSymlinks = func(path string) (string, error) { return path, nil }

			payload := []byte("authenticated replacement before callback mutation")
			version := serveAuthenticatedUpdate(t, payload)

			err := DownloadVersionBeforeReplace(version, false, func() error {
				matches, globErr := filepath.Glob(filepath.Join(directory, ".ssm.*.new"))
				if globErr != nil || len(matches) != 1 {
					return fmt.Errorf("find authenticated stage: matches=%v err=%w", matches, globErr)
				}
				return test.mutate(matches[0])
			})
			if err == nil || !strings.Contains(err.Error(), "authenticated bytes") {
				t.Fatalf("callback object mutation error = %v, want authenticated-byte rejection", err)
			}
			assertExecutableBytes(t, exe, "old")
		})
	}
}

func TestVerifiedReplacementPreservesPermissionsAndTarget(t *testing.T) {
	restoreUpdateTestHooks(t)
	setTestHome(t, t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	directory := t.TempDir()
	exe := filepath.Join(directory, "ssm")
	sentinel := filepath.Join(directory, "sentinel")
	if err := os.WriteFile(exe, []byte("old"), 0o751); err != nil { //nolint:gosec // test-owned executable mode is part of replacement coverage
		t.Fatal(err)
	}
	before, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil { //nolint:gosec // test-owned sibling proves target scope
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	const version = "v9.9.9"
	payload := []byte("verified replacement")
	claims, err := provenancefixture.DefaultClaims(assetName(), version, payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}

	sum := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%x  %s\n", sum, assetName())
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write(fixture.Bundle)
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	downloadBaseURL = server.URL
	httpClient = server.Client()

	callbackCalled := false
	err = DownloadVersionBeforeReplace(version, false, func() error {
		callbackCalled = true
		assertExecutableBytes(t, exe, "old")
		return nil
	})
	if err != nil || !callbackCalled {
		t.Fatalf("verified replacement error=%v callback_called=%t", err, callbackCalled)
	}
	assertExecutableBytes(t, exe, string(payload))
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("verified replacement mode = %o, want %o", info.Mode().Perm(), before.Mode().Perm())
	}
	assertExecutableBytes(t, sentinel, "preserve")
}

func serveAuthenticatedUpdate(t *testing.T, payload []byte) string {
	t.Helper()
	const version = "v9.9.9"
	claims, err := provenancefixture.DefaultClaims(assetName(), version, payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := provenancefixture.Generate(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
		return provenance.VerifyBundle(bundle, request, provenance.Options{
			TrustedMaterial: fixture.TrustedMaterial,
		})
	}
	sum := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%x  %s\n", sum, assetName())
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write(fixture.Bundle)
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	downloadBaseURL = server.URL
	httpClient = server.Client()
	return version
}

func tamperProvenanceSignature(t *testing.T, bundle []byte) []byte {
	t.Helper()
	protobufBundle := &bundlev1.Bundle{}
	if err := protojson.Unmarshal(bundle, protobufBundle); err != nil {
		t.Fatal(err)
	}
	envelope := protobufBundle.GetDsseEnvelope()
	if envelope == nil || len(envelope.Signatures) != 1 || len(envelope.Signatures[0].Sig) == 0 {
		t.Fatal("synthetic provenance has no signature to tamper")
	}
	envelope.Signatures[0].Sig[0] ^= 0xff
	tampered, err := protojson.Marshal(protobufBundle)
	if err != nil {
		t.Fatal(err)
	}
	return tampered
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

func releaseAssetMetadataJSON() string {
	assets := make([]string, 0, len(releaseasset.ExpectedReleaseNames()))
	for _, name := range releaseasset.ExpectedReleaseNames() {
		assets = append(assets, fmt.Sprintf(`{"name":%q}`, name))
	}
	return strings.Join(assets, ",")
}
