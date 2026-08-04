package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
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

func TestChecksumOnlyReplacementIsRejectedAndPreservesExecutable(t *testing.T) {
	restoreUpdateTestHooks(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")

	original := []byte("checksum-only original executable")
	exe := filepath.Join(t.TempDir(), "ssm")
	if err := os.WriteFile(exe, original, 0751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
		t.Fatal(err)
	}
	if err := os.Chmod(exe, 0751); err != nil { //nolint:gosec // test-owned executable mode is part of preservation proof
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	evalSymlinks = func(path string) (string, error) { return path, nil }

	payload := []byte("checksum-only replacement")
	digest := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/releases/download/v1.4.5/checksums.txt":
			_, _ = fmt.Fprintf(w, "%x  %s\n", digest, assetName())
		case "/owner/repo/releases/download/v1.4.5/" + assetName():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	downloadBaseURL = server.URL
	httpClient = server.Client()

	if err := DownloadVersion("v1.4.5", false); err == nil {
		t.Fatal("checksum-only replacement succeeded without provenance")
	}
	installed, err := os.ReadFile(exe) //nolint:gosec // exe is a test-owned executable path
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, original) || info.Mode().Perm() != 0751 {
		t.Fatalf("checksum-only failure changed executable: bytes=%q mode=%o", installed, info.Mode().Perm())
	}
}

func TestProvenanceIdentityMatrix(t *testing.T) {
	for _, test := range []struct {
		name        string
		mutate      func(*provenancefixture.Claims)
		wantSuccess bool
	}{
		{name: "accepted exact release tag", wantSuccess: true},
		{name: "branch replay", mutate: func(claims *provenancefixture.Claims) { claims.Ref = "refs/heads/main" }},
		{name: "different tag replay", mutate: func(claims *provenancefixture.Claims) { claims.Ref = "refs/tags/v1.4.4" }},
		{name: "wrong repository", mutate: func(claims *provenancefixture.Claims) { claims.Repository = "attacker/ssm" }},
		{name: "wrong workflow", mutate: func(claims *provenancefixture.Claims) { claims.Workflow = ".github/workflows/other.yml" }},
		{name: "wrong issuer", mutate: func(claims *provenancefixture.Claims) { claims.Issuer = "https://issuer.invalid" }},
		{name: "self hosted runner", mutate: func(claims *provenancefixture.Claims) { claims.Runner = "self-hosted" }},
		{name: "wrong predicate", mutate: func(claims *provenancefixture.Claims) { claims.PredicateType = "https://predicate.invalid" }},
		{name: "wrong subject", mutate: func(claims *provenancefixture.Claims) { claims.SubjectName = "other-asset" }},
		{name: "additional subject", mutate: func(claims *provenancefixture.Claims) { claims.AdditionalSubjectNames = []string{"extra"} }},
		{name: "additional digest", mutate: func(claims *provenancefixture.Claims) {
			claims.AdditionalDigestValues = map[string]string{"sha512": strings.Repeat("a", 128)}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			restoreUpdateTestHooks(t)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("SSM_UPDATE_REPO", "owner/repo")
			exe := migrationTestExecutable(t, []byte("old trusted executable"))
			const version = "v1.4.5"
			payload := []byte("provenance verified replacement")
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
			verifyProvenance = func(_ context.Context, bundle []byte, request provenance.Request) error {
				return provenance.VerifyBundle(bundle, request, provenance.Options{TrustedMaterial: fixture.TrustedMaterial})
			}
			serveTrustedUpdate(t, version, payload, fixture.Bundle)

			err = DownloadVersion(version, false)
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("accepted identity failed: %v", err)
				}
				assertMigrationFile(t, exe, payload)
				return
			}
			if err == nil {
				t.Fatal("unaccepted identity replaced the executable")
			}
			assertMigrationFile(t, exe, []byte("old trusted executable"))
		})
	}
}

func TestProvenanceDigestBinding(t *testing.T) {
	restoreUpdateTestHooks(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")
	exe := migrationTestExecutable(t, []byte("digest-bound original"))
	const version = "v1.4.5"
	downloaded := []byte("downloaded bytes")
	claims, err := provenancefixture.DefaultClaims(assetName(), version, []byte("different attested bytes"))
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
	serveTrustedUpdate(t, version, downloaded, fixture.Bundle)
	if err := DownloadVersion(version, false); err == nil {
		t.Fatal("release checksum authorized bytes with a different attested digest")
	}
	assertMigrationFile(t, exe, []byte("digest-bound original"))
}

func TestSameMajorUpdateUsesExactManifestAndProvenance(t *testing.T) {
	restoreUpdateTestHooks(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSM_UPDATE_REPO", "owner/repo")
	exe := migrationTestExecutable(t, []byte("same-major original"))
	const version = "v1.4.5"
	payload := []byte("same-major trusted replacement")
	claims, err := provenancefixture.DefaultClaims(assetName(), version, payload)
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
	digest := sha256.Sum256(payload)
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/repos/owner/repo/releases":
			_, _ = fmt.Fprintf(w, `[{"tag_name":"v2.0.0","assets":%s},{"tag_name":"v1.4.5","assets":%s}]`, migrationReleaseAssetsJSON(t), migrationReleaseAssetsJSON(t))
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%x  %s\n", digest, assetName())
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write(fixture.Bundle)
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	apiBaseURL = server.URL
	downloadBaseURL = server.URL
	httpClient = server.Client()

	result, err := Download("v1.4.4")
	if err != nil {
		t.Fatalf("same-major Download: %v", err)
	}
	if result.Installed != version || result.CrossMajorAvailable != "v2.0.0" {
		t.Fatalf("result = %#v", result)
	}
	assertMigrationFile(t, exe, payload)
	for _, path := range paths {
		if strings.Contains(path, "/v2.0.0/") {
			t.Fatalf("ordinary update requested v2 asset: %q", paths)
		}
	}
}

func TestReleaseAssetSelectionIsStrict(t *testing.T) {
	valid := Release{TagName: "v1.4.5"}
	for _, name := range releaseasset.ExpectedReleaseNames() {
		valid.Assets = append(valid.Assets, struct {
			Name string `json:"name"`
		}{Name: name})
	}
	if err := validateReleaseAssets(valid); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Release)
	}{
		{name: "missing", mutate: func(release *Release) { release.Assets = release.Assets[1:] }},
		{name: "duplicate", mutate: func(release *Release) { release.Assets = append(release.Assets, release.Assets[0]) }},
		{name: "extra", mutate: func(release *Release) {
			release.Assets = append(release.Assets, struct {
				Name string `json:"name"`
			}{Name: "extra"})
		}},
		{name: "malformed", mutate: func(release *Release) { release.Assets[0].Name += ".zip" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			release := valid
			release.Assets = append([]struct {
				Name string `json:"name"`
			}(nil), valid.Assets...)
			test.mutate(&release)
			if err := validateReleaseAssets(release); err == nil {
				t.Fatal("invalid release manifest accepted")
			}
		})
	}
}

func serveTrustedUpdate(t *testing.T, version string, payload, bundle []byte) {
	t.Helper()
	digest := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%x  %s\n", digest, assetName())
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			_, _ = w.Write(bundle)
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	downloadBaseURL = server.URL
	httpClient = server.Client()
}

// migrationHTTPClient is shared with the native Windows callback-race suite.
// It serves only the exact asset triplet needed after migration preflight.
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
		return provenance.VerifyBundle(bundle, request, provenance.Options{TrustedMaterial: fixture.TrustedMaterial})
	}
	digest := sha256.Sum256(payload)
	checksum := fmt.Sprintf("%x", digest)
	if !validDigest {
		checksum = strings.Repeat("0", sha256.Size*2)
	}
	return &http.Client{Transport: bridgeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body []byte
		switch request.URL.Path {
		case "/repos/owner/repo/releases":
			body = []byte(fmt.Sprintf(
				`[{"tag_name":%q,"name":"SSM v2","body":"v2 migration release notes","assets":%s}]`,
				version,
				migrationReleaseAssetsJSON(t),
			))
		case "/owner/repo/releases/download/" + version + "/checksums.txt":
			body = []byte(fmt.Sprintf("%s  %s\n", checksum, assetName()))
		case "/owner/repo/releases/download/" + version + "/" + releaseasset.ProvenanceName(assetName()):
			body = fixture.Bundle
		case "/owner/repo/releases/download/" + version + "/" + assetName():
			body = payload
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(body))}, nil
	})}
}
