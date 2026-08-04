//go:build !windows

package releaseasset

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBridgeInstallerRejectsChecksumOnlyAndPreservesExecutable(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(prefix, 0700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(prefix, "ssm")
	original := []byte("original v1 executable")
	if err := os.WriteFile(executable, original, 0751); err != nil { //nolint:gosec // test-owned installed executable
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0751); err != nil { //nolint:gosec // exact original mode is part of preservation proof
		t.Fatal(err)
	}
	payload := []byte("#!/bin/sh\nexit 0\n")
	digest := sha256.Sum256(payload)
	fixtures := t.TempDir()
	payloadPath := filepath.Join(fixtures, "ssm-linux-amd64")
	checksumsPath := filepath.Join(fixtures, "checksums.txt")
	bundlePath := filepath.Join(fixtures, "bundle.json")
	metadataPath := filepath.Join(fixtures, "metadata.json")
	assets := make([]map[string]string, 0, len(ExpectedReleaseNames()))
	for _, name := range ExpectedReleaseNames() {
		assets = append(assets, map[string]string{"name": name})
	}
	metadata, err := json.Marshal(map[string]any{"tag_name": "v1.4.4", "assets": assets})
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		payloadPath:   payload,
		checksumsPath: []byte(fmt.Sprintf("%x  ssm-linux-amd64\n", digest)),
		bundlePath:    []byte("{}\n"),
		metadataPath:  metadata,
	} {
		if err := os.WriteFile(path, data, 0600); err != nil { //nolint:gosec // test-owned release fixture
			t.Fatal(err)
		}
	}

	fakeBin := t.TempDir()
	ghMarker := filepath.Join(t.TempDir(), "gh-called")
	writeExecutable(t, filepath.Join(fakeBin, "uname"), `#!/bin/sh
case "$1" in
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
  *) exit 2 ;;
esac
`)
	writeExecutable(t, filepath.Join(fakeBin, "curl"), `#!/bin/sh
set -eu
url=""
output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    --max-filesize) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  https://api.github.com/*) source="$METADATA_FIXTURE" ;;
  */checksums.txt) source="$CHECKSUMS_FIXTURE" ;;
  *.sigstore.json) source="$BUNDLE_FIXTURE" ;;
  */ssm-linux-amd64) source="$PAYLOAD_FIXTURE" ;;
  *) exit 90 ;;
esac
if [ -n "$output" ]; then cp "$source" "$output"; else cp "$source" /dev/stdout; fi
`)
	writeExecutable(t, filepath.Join(fakeBin, "gh"), `#!/bin/sh
printf called >"$GH_MARKER"
exit 92
`)

	command := exec.Command("sh", filepath.Join("..", "..", "install.sh")) //nolint:gosec // fixed repository installer path
	command.Env = append(os.Environ(),
		"HOME="+t.TempDir(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SSM_PREFIX="+prefix,
		"SSM_CONFIG_DIR="+filepath.Join(t.TempDir(), "config"),
		"PAYLOAD_FIXTURE="+payloadPath,
		"CHECKSUMS_FIXTURE="+checksumsPath,
		"BUNDLE_FIXTURE="+bundlePath,
		"METADATA_FIXTURE="+metadataPath,
		"GH_MARKER="+ghMarker,
	)
	output, runErr := command.CombinedOutput()
	if runErr == nil {
		t.Fatalf("installer accepted checksum-only release; output=%q", output)
	}
	installed, err := os.ReadFile(executable) //nolint:gosec // test-owned installed executable
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, original) || info.Mode().Perm() != 0751 {
		t.Fatalf("installer trust failure changed executable: bytes=%q mode=%o output=%q", installed, info.Mode().Perm(), output)
	}
	if _, err := os.Stat(ghMarker); err != nil {
		t.Fatalf("installer did not invoke pinned provenance verifier: %v; output=%q", err, output)
	}
}

func TestLegacyBridgeInstallerNamesChecksumsAndLayoutRemainCompatible(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "bin")
	configDir := filepath.Join(t.TempDir(), "config")
	payload := []byte("#!/bin/sh\nprintf 'ssm 1.4.4\\n'\n")
	digest := sha256.Sum256(payload)
	fixtures := t.TempDir()
	payloadPath := filepath.Join(fixtures, "ssm-linux-amd64")
	checksumsPath := filepath.Join(fixtures, "checksums.txt")
	bundlePath := filepath.Join(fixtures, "ssm-linux-amd64.sigstore.json")
	metadataPath := filepath.Join(fixtures, "metadata.json")
	assets := make([]map[string]string, 0, len(ExpectedReleaseNames()))
	for _, name := range ExpectedReleaseNames() {
		assets = append(assets, map[string]string{"name": name})
	}
	metadata, err := json.Marshal(map[string]any{"tag_name": "v1.4.4", "assets": assets})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checksumsPath, []byte(fmt.Sprintf("%x  ssm-linux-amd64\n", digest)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, metadata, 0600); err != nil {
		t.Fatal(err)
	}

	fakeBin := t.TempDir()
	requestLog := filepath.Join(t.TempDir(), "requests")
	writeExecutable(t, filepath.Join(fakeBin, "uname"), `#!/bin/sh
case "$1" in
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
  *) exit 2 ;;
esac
`)
	writeExecutable(t, filepath.Join(fakeBin, "curl"), `#!/bin/sh
set -eu
url=""
output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    --max-filesize) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" >>"$REQUEST_LOG"
case "$url" in
  https://api.github.com/*) source="$METADATA_FIXTURE" ;;
  */checksums.txt) source="$CHECKSUMS_FIXTURE" ;;
  *.sigstore.json) source="$BUNDLE_FIXTURE" ;;
  */ssm-linux-amd64) source="$PAYLOAD_FIXTURE" ;;
  *) exit 90 ;;
esac
if [ -n "$output" ]; then cp "$source" "$output"; else cp "$source" /dev/stdout; fi
`)
	writeExecutable(t, filepath.Join(fakeBin, "gh"), `#!/bin/sh
set -eu
identity=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --cert-identity) identity="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ "$identity" = "https://github.com/Cd1s/ssm/.github/workflows/release.yml@refs/tags/v1.4.4" ]
printf 'true\n'
`)

	command := exec.Command("sh", filepath.Join("..", "..", "install.sh")) //nolint:gosec // fixed repository installer path
	command.Env = append(os.Environ(),
		"HOME="+t.TempDir(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SSM_PREFIX="+prefix,
		"SSM_CONFIG_DIR="+configDir,
		"PAYLOAD_FIXTURE="+payloadPath,
		"CHECKSUMS_FIXTURE="+checksumsPath,
		"BUNDLE_FIXTURE="+bundlePath,
		"METADATA_FIXTURE="+metadataPath,
		"REQUEST_LOG="+requestLog,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("legacy installer: %v; output=%q", err, output)
	}
	installed, err := os.ReadFile(filepath.Join(prefix, "ssm")) //nolint:gosec // prefix is a test-owned temporary directory
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, payload) {
		t.Fatalf("installed bytes = %q", installed)
	}
	info, err := os.Stat(filepath.Join(prefix, "ssm"))
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("installed mode=%v err=%v", info.Mode().Perm(), err)
	}
	alias, err := os.Readlink(filepath.Join(prefix, "sshctl"))
	if err != nil || alias != filepath.Join(prefix, "ssm") {
		t.Fatalf("sshctl alias=%q err=%v", alias, err)
	}
	requests, err := os.ReadFile(requestLog) //nolint:gosec // requestLog is beneath a test-owned temporary directory
	if err != nil {
		t.Fatal(err)
	}
	wantRequests := "https://api.github.com/repos/Cd1s/ssm/releases/latest\n" +
		"https://github.com/Cd1s/ssm/releases/download/v1.4.4/ssm-linux-amd64\n" +
		"https://github.com/Cd1s/ssm/releases/download/v1.4.4/checksums.txt\n" +
		"https://github.com/Cd1s/ssm/releases/download/v1.4.4/ssm-linux-amd64.sigstore.json\n"
	if string(requests) != wantRequests {
		t.Fatalf("legacy installer requests=%q, want %q", requests, wantRequests)
	}
	repo, err := os.ReadFile(filepath.Join(configDir, "update_repo")) //nolint:gosec // configDir is a test-owned temporary directory
	if err != nil || strings.TrimSpace(string(repo)) != "Cd1s/ssm" {
		t.Fatalf("update_repo=%q err=%v", repo, err)
	}
}

func TestBridgeInstallerPinsSelectedTagProvenancePolicy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	installer := string(data)
	for description, required := range map[string]string{
		"adjacent provenance asset": `provenance="$asset.sigstore.json"`,
		"exact manifest":            "exact supported 14-asset manifest",
		"bundle verification":       `--bundle "$bundle"`,
		"repository":                "--repo Cd1s/ssm",
		"selected tag identity":     `@refs/tags/$release_tag`,
		"OIDC issuer":               "--cert-oidc-issuer https://token.actions.githubusercontent.com",
		"SLSA predicate":            "--predicate-type https://slsa.dev/provenance/v1",
		"hosted runner":             "--deny-self-hosted-runners",
		"one exact subject":         `.statement.subject | length) == 1`,
		"one SHA-256 digest":        `digest | keys) == [\"sha256\"]`,
		"same-directory staging":    `mktemp "$prefix/.ssm.new.XXXXXX"`,
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("installer lacks pinned %s policy %q", description, required)
		}
	}
	for _, forbidden := range []string{"--skip", "SKIP_", "NO_VERIFY", "--cert-identity-regex", "refs/heads/main"} {
		if strings.Contains(installer, forbidden) {
			t.Errorf("installer contains forbidden trust bypass %q", forbidden)
		}
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0700); err != nil { //nolint:gosec // test-owned helper must be executable
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0700); err != nil { //nolint:gosec // test-owned helper must be executable
		t.Fatal(err)
	}
}
