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

func TestInstallerRejectsOversizedDownloadsBeforeReplacement(t *testing.T) {
	for _, test := range []struct {
		name    string
		options installerFixtureOptions
	}{
		{
			name: "release metadata",
			options: installerFixtureOptions{
				metadata:        installerReleaseMetadata(releaseasset.ExpectedReleaseNames()),
				bundle:          []byte("{}\n"),
				ghPolicy:        "success",
				metadataPadding: (1 << 20) + 1,
			},
		},
		{
			name: "checksums",
			options: installerFixtureOptions{
				metadata:         installerReleaseMetadata(releaseasset.ExpectedReleaseNames()),
				bundle:           []byte("{}\n"),
				ghPolicy:         "success",
				checksumsPadding: (16 << 10) + 1,
			},
		},
		{
			name: "provenance bundle",
			options: installerFixtureOptions{
				metadata:      installerReleaseMetadata(releaseasset.ExpectedReleaseNames()),
				bundle:        []byte("{}\n"),
				ghPolicy:      "success",
				bundlePadding: (1 << 20) + 1,
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
	output     []byte
	err        error
	executable string
	original   []byte
	mode       os.FileMode
	ghCalled   bool
}

type installerFixtureOptions struct {
	metadata         []byte
	bundle           []byte
	ghPolicy         string
	metadataPadding  int
	checksumsPadding int
	bundlePadding    int
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

	asset := "ssm-" + runtime.GOOS + "-" + runtime.GOARCH
	payload := []byte("#!/bin/sh\nexit 0\n")
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
	curlPath := filepath.Join(fakeBin, "curl")
	writeTestFile(t, curlPath, `#!/bin/sh
set -eu
url=""
output=""
write_format=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    -w) write_format="$2"; shift 2 ;;
    --max-filesize) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  https://api.github.com/*) cp "$METADATA_FIXTURE" "$output" ;;
  */releases/latest) : ;;
  */checksums.txt) cp "$CHECKSUMS_FIXTURE" "$output" ;;
  *.sigstore.json) cp "$BUNDLE_FIXTURE" "$output" ;;
  */"$INSTALLER_ASSET") cp "$PAYLOAD_FIXTURE" "$output" ;;
  *) exit 90 ;;
esac
if [ -n "$write_format" ]; then
  printf 'https://github.com/Cd1s/ssm/releases/tag/v9.9.9'
fi
`)
	if err := os.Chmod(curlPath, 0o700); err != nil { //nolint:gosec // test-owned command shim
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
	)
	output, runErr := command.CombinedOutput()
	_, markerErr := os.Stat(ghMarker)
	return installerResult{
		output:     output,
		err:        runErr,
		executable: executable,
		original:   original,
		mode:       before.Mode().Perm(),
		ghCalled:   markerErr == nil,
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
