//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"ssm/internal/releaseasset"
)

func TestReleaseRunsInstallerSyntaxAsAnAction(t *testing.T) {
	release, ok := findProfile(verificationManifest(), "release")
	if !ok {
		t.Fatal("release profile not found")
	}
	var syntax Check
	for _, check := range release.Checks {
		if check.ID == "install-shell-syntax" {
			syntax = check
			break
		}
	}
	wantAction := commandAction("sh", []string{"-n", "install.sh"}, nil, "")
	if !reflect.DeepEqual(syntax.Action, wantAction) {
		t.Fatalf("installer syntax action = %+v, want %+v", syntax.Action, wantAction)
	}
	if syntax.Requirement != requirementRequired {
		t.Fatalf("installer syntax requirement = %q, want required", syntax.Requirement)
	}

	repo := t.TempDir()
	writeTestFile(t, filepath.Join(repo, "install.sh"), "#!/bin/sh\nif then\n")
	result := executeAction(context.Background(), syntax.Action, actionContext{
		RepoRoot:    repo,
		Environment: newTestProcessEnvironment(t),
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	})
	if result.Status != statusFailed {
		t.Fatalf("malformed installer syntax status = %q, want failed", result.Status)
	}
}

func TestInstallerTrustFailurePreservesExecutable(t *testing.T) {
	result := runInstallerFixture(t, installerFixtureOptions{
		metadata: installerReleaseMetadata(releaseasset.ExpectedReleaseNames()),
		bundle:   []byte("{}\n"),
		ghPolicy: "fail",
	})
	if result.err == nil {
		t.Fatalf("installer accepted failed provenance verification; output=%q", result.output)
	}
	assertInstallerExecutablePreserved(t, result)
	if !result.ghCalled {
		t.Fatalf("installer did not reach the failing provenance verifier; output=%q", result.output)
	}
}

func TestInstallerStagesWithBSDMktemp(t *testing.T) {
	result := runInstallerFixture(t, installerFixtureOptions{
		metadata:  installerReleaseMetadata(releaseasset.ExpectedReleaseNames()),
		bundle:    []byte("{}\n"),
		ghPolicy:  "success",
		bsdMktemp: true,
	})
	if result.err != nil {
		t.Fatalf("installer failed with BSD mktemp behavior: %v; output=%q", result.err, result.output)
	}
	installed, err := os.ReadFile(result.executable) //nolint:gosec // path is constrained to the fixture's t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, result.replacement) {
		t.Fatalf("installed executable differs from verified fixture; output=%q", result.output)
	}
	info, err := os.Stat(result.executable)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("installed executable mode = %o, want 755", info.Mode().Perm())
	}
	linkTarget, err := os.Readlink(result.alias)
	if err != nil {
		t.Fatal(err)
	}
	if linkTarget != result.executable {
		t.Fatalf("sshctl link target = %q, want %q", linkTarget, result.executable)
	}
	if !strings.HasPrefix(result.stagingTemplate, filepath.Dir(result.executable)+string(os.PathSeparator)) ||
		!strings.HasSuffix(result.stagingTemplate, "XXXXXX") {
		t.Fatalf("BSD mktemp staging template = %q, want same-directory template ending in XXXXXX", result.stagingTemplate)
	}
	staged, err := filepath.Glob(filepath.Join(filepath.Dir(result.executable), ".ssm.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(staged) != 0 {
		t.Fatalf("installer retained staging files: %q", staged)
	}
}

func TestInstallerRejectsProvenanceReplayAndDowngrade(t *testing.T) {
	for _, test := range []struct {
		name     string
		ghPolicy string
	}{
		{name: "unversioned main replay", ghPolicy: "main-only"},
		{name: "older tag downgrade", ghPolicy: "older-tag-only"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := runInstallerFixture(t, installerFixtureOptions{
				metadata: installerReleaseMetadata(releaseasset.ExpectedReleaseNames()),
				bundle:   []byte("{}\n"),
				ghPolicy: test.ghPolicy,
			})
			if result.err == nil {
				t.Fatalf("installer accepted provenance replay or downgrade; output=%q", result.output)
			}
			assertInstallerExecutablePreserved(t, result)
		})
	}
}

func TestInstallerRequiresExactReleaseManifest(t *testing.T) {
	valid := releaseasset.ExpectedReleaseNames()
	for _, test := range []struct {
		name   string
		mutate func([]string) []string
	}{
		{
			name: "missing asset",
			mutate: func(names []string) []string {
				return names[1:]
			},
		},
		{
			name: "duplicate asset",
			mutate: func(names []string) []string {
				return append(names, names[0])
			},
		},
		{
			name: "misnamed asset",
			mutate: func(names []string) []string {
				names[0] += ".zip"
				return names
			},
		},
		{
			name: "unsupported extra asset",
			mutate: func(names []string) []string {
				return append(names, "ssm-freebsd-amd64")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			names := test.mutate(append([]string(nil), valid...))
			result := runInstallerFixture(t, installerFixtureOptions{
				metadata: installerReleaseMetadata(names),
				bundle:   []byte("{}\n"),
				ghPolicy: "success",
			})
			if result.err == nil {
				t.Fatalf("installer accepted invalid release manifest; output=%q", result.output)
			}
			assertInstallerExecutablePreserved(t, result)
			if result.ghCalled {
				t.Fatalf("installer verified provenance before rejecting manifest; output=%q", result.output)
			}
		})
	}
}

func TestInstallerRejectsUnknownLengthOversizedDownloadsBeforeReplacement(t *testing.T) {
	for _, test := range []struct {
		name    string
		limit   int
		options installerFixtureOptions
	}{
		{
			name:  "release metadata",
			limit: 1 << 20,
			options: installerFixtureOptions{
				metadata:        installerReleaseMetadata(releaseasset.ExpectedReleaseNames()),
				bundle:          []byte("{}\n"),
				ghPolicy:        "success",
				metadataPadding: (1 << 20) + 1,
				unknownLength:   true,
				redirect:        true,
			},
		},
		{
			name:  "binary",
			limit: 64 << 20,
			options: installerFixtureOptions{
				metadata:      installerReleaseMetadata(releaseasset.ExpectedReleaseNames()),
				bundle:        []byte("{}\n"),
				ghPolicy:      "success",
				binaryPadding: (64 << 20) + 1,
				unknownLength: true,
				redirect:      true,
			},
		},
		{
			name:  "checksums",
			limit: 16 << 10,
			options: installerFixtureOptions{
				metadata:         installerReleaseMetadata(releaseasset.ExpectedReleaseNames()),
				bundle:           []byte("{}\n"),
				ghPolicy:         "success",
				checksumsPadding: (16 << 10) + 1,
				unknownLength:    true,
				redirect:         true,
			},
		},
		{
			name:  "provenance bundle",
			limit: 1 << 20,
			options: installerFixtureOptions{
				metadata:      installerReleaseMetadata(releaseasset.ExpectedReleaseNames()),
				bundle:        []byte("{}\n"),
				ghPolicy:      "success",
				bundlePadding: (1 << 20) + 1,
				unknownLength: true,
				redirect:      true,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := runInstallerFixture(t, test.options)
			if result.err == nil {
				t.Fatalf("installer accepted oversized %s; output=%q", test.name, result.output)
			}
			assertInstallerExecutablePreserved(t, result)
			if result.ghCalled {
				t.Fatalf("installer passed oversized %s to provenance verification; output=%q", test.name, result.output)
			}
			if !result.redirected {
				t.Fatalf("installer did not follow the simulated redirect for %s; output=%q", test.name, result.output)
			}
			if len(result.downloadSizes) == 0 {
				t.Fatalf("installer did not inspect bounded temporary output for %s; output=%q", test.name, result.output)
			}
			if got, want := result.downloadSizes[len(result.downloadSizes)-1], fmt.Sprint(test.limit+1); got != want {
				t.Fatalf(
					"oversized %s temporary bytes = %s, want bounded max+1 size %s; all_sizes=%q output=%q",
					test.name,
					got,
					want,
					result.downloadSizes,
					result.output,
				)
			}
		})
	}
}

func TestInstallerPinsProvenanceTrustPolicy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	installer := string(data)
	for description, required := range map[string]string{
		"adjacent provenance asset": `provenance="$asset.sigstore.json"`,
		"bundle verification":       `--bundle "$bundle"`,
		"repository":                "--repo Cd1s/ssm",
		"tag identity":              `tag_identity="https://github.com/Cd1s/ssm/.github/workflows/release.yml@refs/tags/$release_tag"`,
		"exact subject name":        `.statement.subject[0].name == \"$asset\"`,
		"one SHA-256 digest":        `(.statement.subject[0].digest | keys) == [\"sha256\"]`,
		"identity acceptance date":  `. >= \"2026-07-30T00:00:00Z\"`,
		"OIDC issuer":               "--cert-oidc-issuer https://token.actions.githubusercontent.com",
		"SLSA predicate":            "--predicate-type https://slsa.dev/provenance/v1",
		"hosted runner":             "--deny-self-hosted-runners",
		"binary size ceiling":       "binary_limit=67108864",
		"streaming size ceiling":    `head -c "$((download_limit + 1))"`,
		"atomic destination":        `mv -f "$staged" "$prefix/ssm"`,
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("installer lacks pinned %s policy %q", description, required)
		}
	}
	for _, forbidden := range []string{
		"--skip",
		"SKIP_",
		"NO_VERIFY",
		"checksum fallback",
		"--cert-identity-regex",
		"--signer-repo",
		"--signer-workflow",
		"refs/heads/main",
	} {
		if strings.Contains(installer, forbidden) {
			t.Errorf("installer contains forbidden provenance bypass %q", forbidden)
		}
	}
}

type installerResult struct {
	output          []byte
	err             error
	executable      string
	alias           string
	original        []byte
	mode            os.FileMode
	replacement     []byte
	ghCalled        bool
	redirected      bool
	downloadSizes   []string
	stagingTemplate string
}

type installerFixtureOptions struct {
	metadata         []byte
	bundle           []byte
	ghPolicy         string
	bsdMktemp        bool
	metadataPadding  int
	checksumsPadding int
	bundlePadding    int
	binaryPadding    int
	unknownLength    bool
	redirect         bool
}

func runInstallerFixture(t *testing.T, options installerFixtureOptions) installerResult {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(prefix, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(prefix, "ssm")
	original := []byte("original executable bytes")
	if err := os.WriteFile(executable, original, 0o751); err != nil { //nolint:gosec // test-owned installation target
		t.Fatal(err)
	}
	before, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}

	fixtureOS := runtime.GOOS
	fixtureArch := runtime.GOARCH
	if options.bsdMktemp {
		fixtureOS = "darwin"
		fixtureArch = "arm64"
	}
	asset := "ssm-" + fixtureOS + "-" + fixtureArch
	payload := []byte("#!/bin/sh\nexit 0\n")
	payload = append(payload, bytes.Repeat([]byte(" "), options.binaryPadding)...)
	digest := sha256.Sum256(payload)
	metadata := append([]byte(nil), options.metadata...)
	metadata = append(metadata, bytes.Repeat([]byte(" "), options.metadataPadding)...)
	checksums := []byte(fmt.Sprintf("%x  %s\n", digest, asset))
	checksums = append(checksums, bytes.Repeat([]byte(" "), options.checksumsPadding)...)
	bundle := append([]byte(nil), options.bundle...)
	bundle = append(bundle, bytes.Repeat([]byte(" "), options.bundlePadding)...)
	fixtureDir := t.TempDir()
	metadataPath := filepath.Join(fixtureDir, "metadata.json")
	checksumsPath := filepath.Join(fixtureDir, "checksums.txt")
	bundlePath := filepath.Join(fixtureDir, "bundle.json")
	payloadPath := filepath.Join(fixtureDir, "payload")
	for path, data := range map[string][]byte{
		metadataPath:  metadata,
		checksumsPath: checksums,
		bundlePath:    bundle,
		payloadPath:   payload,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // all paths and contents are test-owned fixtures
			t.Fatal(err)
		}
	}

	fakeBin := t.TempDir()
	realTee, err := exec.LookPath("tee")
	if err != nil {
		t.Fatal(err)
	}
	realWC, err := exec.LookPath("wc")
	if err != nil {
		t.Fatal(err)
	}
	downloadSizeMarker := filepath.Join(t.TempDir(), "download-sizes")
	redirectMarker := filepath.Join(t.TempDir(), "redirects")
	curlPath := filepath.Join(fakeBin, "curl")
	writeTestFile(t, curlPath, `#!/bin/sh
set -eu
url=""
output=""
write_format=""
follow_redirects=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    -w) write_format="$2"; shift 2 ;;
    --max-filesize) shift 2 ;;
    -*)
      case "$1" in
        *L*) follow_redirects=true ;;
      esac
      shift
      ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  https://api.github.com/*) source="$METADATA_FIXTURE" ;;
  */checksums.txt) source="$CHECKSUMS_FIXTURE" ;;
  *.sigstore.json) source="$BUNDLE_FIXTURE" ;;
  */"$INSTALLER_ASSET") source="$PAYLOAD_FIXTURE" ;;
  *) exit 90 ;;
esac
if [ "$REDIRECT_FIXTURE" = true ]; then
  [ "$follow_redirects" = true ] || exit 91
  printf '%s\n' "$url" >>"$REDIRECT_MARKER"
fi
if [ "$UNKNOWN_LENGTH_FIXTURE" = true ]; then
  if [ -n "$output" ]; then
    dd if="$source" of="$output" bs=1024 2>/dev/null
  else
    dd if="$source" bs=1024 2>/dev/null
  fi
elif [ -n "$output" ]; then
  cp "$source" "$output"
else
  dd if="$source" bs=1024 2>/dev/null
fi
if [ -n "$write_format" ]; then
  printf 'https://github.com/Cd1s/ssm/releases/tag/v9.9.9'
fi
`)
	if err := os.Chmod(curlPath, 0o700); err != nil { //nolint:gosec // test-owned command shim
		t.Fatal(err)
	}
	wcPath := filepath.Join(fakeBin, "wc")
	writeTestFile(t, wcPath, `#!/bin/sh
set -eu
capture="$WC_CAPTURE.$$"
trap 'rm -f "$capture"' EXIT
"$REAL_TEE" "$capture" | "$REAL_WC" "$@"
"$REAL_WC" -c <"$capture" >>"$DOWNLOAD_SIZE_MARKER"
`)
	if err := os.Chmod(wcPath, 0o700); err != nil { //nolint:gosec // test-owned command shim
		t.Fatal(err)
	}
	ghMarker := filepath.Join(t.TempDir(), "gh-called")
	ghPath := filepath.Join(fakeBin, "gh")
	writeTestFile(t, ghPath, `#!/bin/sh
set -eu
printf called >"$GH_MARKER"
identity=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --cert-identity) identity="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case "$GH_POLICY" in
  success) printf 'true\n' ;;
  fail) exit 92 ;;
  main-only)
    case "$identity" in
      *@refs/heads/main) printf 'true\n' ;;
      *) printf 'false\n' ;;
    esac
    ;;
  older-tag-only)
    case "$identity" in
      *@refs/tags/v9.9.8) printf 'true\n' ;;
      *) printf 'false\n' ;;
    esac
    ;;
  *) exit 92 ;;
esac
`)
	if err := os.Chmod(ghPath, 0o700); err != nil { //nolint:gosec // test-owned command shim
		t.Fatal(err)
	}
	realMktemp, err := exec.LookPath("mktemp")
	if err != nil {
		t.Fatal(err)
	}
	mktempMarker := filepath.Join(t.TempDir(), "mktemp-template")
	mktempPath := filepath.Join(fakeBin, "mktemp")
	writeTestFile(t, mktempPath, `#!/bin/sh
set -eu
if [ "$#" -eq 0 ]; then
  exec "$REAL_MKTEMP"
fi
template="$1"
printf '%s\n' "$template" >"$MKTEMP_MARKER"
if [ "$BSD_MKTEMP_FIXTURE" = true ]; then
  case "$template" in
    *XXXXXX) ;;
    *) exit 93 ;;
  esac
fi
exec "$REAL_MKTEMP" "$template"
`)
	if err := os.Chmod(mktempPath, 0o700); err != nil { //nolint:gosec // test-owned command shim
		t.Fatal(err)
	}
	realUname, err := exec.LookPath("uname")
	if err != nil {
		t.Fatal(err)
	}
	unamePath := filepath.Join(fakeBin, "uname")
	writeTestFile(t, unamePath, `#!/bin/sh
set -eu
if [ "$DARWIN_FIXTURE" = true ]; then
  case "${1:-}" in
    -s) printf 'Darwin\n'; exit 0 ;;
    -m) printf 'arm64\n'; exit 0 ;;
  esac
fi
exec "$REAL_UNAME" "$@"
`)
	if err := os.Chmod(unamePath, 0o700); err != nil { //nolint:gosec // test-owned command shim
		t.Fatal(err)
	}

	command := exec.Command("sh", filepath.Join("..", "..", "install.sh")) //nolint:gosec // fixed tracked installer executes only against test-owned paths and command shims
	command.Env = append(
		newTestProcessEnvironment(t),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SSM_PREFIX="+prefix,
		"SSM_CONFIG_DIR="+filepath.Join(t.TempDir(), "config"),
		"METADATA_FIXTURE="+metadataPath,
		"CHECKSUMS_FIXTURE="+checksumsPath,
		"BUNDLE_FIXTURE="+bundlePath,
		"PAYLOAD_FIXTURE="+payloadPath,
		"INSTALLER_ASSET="+asset,
		"GH_MARKER="+ghMarker,
		"GH_POLICY="+options.ghPolicy,
		"UNKNOWN_LENGTH_FIXTURE="+fmt.Sprint(options.unknownLength),
		"REDIRECT_FIXTURE="+fmt.Sprint(options.redirect),
		"REDIRECT_MARKER="+redirectMarker,
		"REAL_TEE="+realTee,
		"REAL_WC="+realWC,
		"REAL_MKTEMP="+realMktemp,
		"MKTEMP_MARKER="+mktempMarker,
		"BSD_MKTEMP_FIXTURE="+fmt.Sprint(options.bsdMktemp),
		"REAL_UNAME="+realUname,
		"DARWIN_FIXTURE="+fmt.Sprint(options.bsdMktemp),
		"WC_CAPTURE="+filepath.Join(t.TempDir(), "wc-capture"),
		"DOWNLOAD_SIZE_MARKER="+downloadSizeMarker,
	)
	output, runErr := command.CombinedOutput()
	_, markerErr := os.Stat(ghMarker)
	_, redirectErr := os.Stat(redirectMarker)
	sizeData, sizeErr := os.ReadFile(downloadSizeMarker) //nolint:gosec // test-owned observation marker
	if sizeErr != nil && !os.IsNotExist(sizeErr) {
		t.Fatal(sizeErr)
	}
	templateData, templateErr := os.ReadFile(mktempMarker) //nolint:gosec // test-owned observation marker
	if templateErr != nil && !os.IsNotExist(templateErr) {
		t.Fatal(templateErr)
	}
	return installerResult{
		output:          output,
		err:             runErr,
		executable:      executable,
		alias:           filepath.Join(prefix, "sshctl"),
		original:        original,
		mode:            before.Mode().Perm(),
		replacement:     payload,
		ghCalled:        markerErr == nil,
		redirected:      redirectErr == nil,
		downloadSizes:   strings.Fields(string(sizeData)),
		stagingTemplate: strings.TrimSpace(string(templateData)),
	}
}

func installerReleaseMetadata(names []string) []byte {
	assets := make([]string, 0, len(names))
	for _, name := range names {
		assets = append(assets, fmt.Sprintf(`{"name":%q}`, name))
	}
	return []byte(fmt.Sprintf(`{"tag_name":"v9.9.9","assets":[%s]}`, strings.Join(assets, ",")))
}

func assertInstallerExecutablePreserved(t *testing.T, result installerResult) {
	t.Helper()
	after, err := os.ReadFile(result.executable) //nolint:gosec // path is constrained to the fixture's t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(result.executable)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, result.original) || info.Mode().Perm() != result.mode {
		t.Fatalf(
			"installer failure changed executable: bytes_equal=%t mode=%o want_mode=%o output=%q",
			bytes.Equal(after, result.original),
			info.Mode().Perm(),
			result.mode,
			result.output,
		)
	}
}
