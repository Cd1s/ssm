//go:build !windows

package releaseasset

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyBridgeInstallerNamesChecksumsAndLayoutRemainCompatible(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "bin")
	configDir := filepath.Join(t.TempDir(), "config")
	payload := []byte("#!/bin/sh\nprintf 'ssm 1.4.4\\n'\n")
	digest := sha256.Sum256(payload)
	fixtures := t.TempDir()
	payloadPath := filepath.Join(fixtures, "ssm-linux-amd64")
	checksumsPath := filepath.Join(fixtures, "checksums.txt")
	if err := os.WriteFile(payloadPath, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checksumsPath, []byte(fmt.Sprintf("%x  ssm-linux-amd64\n", digest)), 0600); err != nil {
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
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" >>"$REQUEST_LOG"
case "$url" in
  */ssm-linux-amd64) cp "$PAYLOAD_FIXTURE" "$output" ;;
  */checksums.txt) cp "$CHECKSUMS_FIXTURE" "$output" ;;
  *) exit 90 ;;
esac
`)

	command := exec.Command("sh", filepath.Join("..", "..", "install.sh")) //nolint:gosec // fixed repository installer path
	command.Env = append(os.Environ(),
		"HOME="+t.TempDir(),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SSM_PREFIX="+prefix,
		"SSM_CONFIG_DIR="+configDir,
		"PAYLOAD_FIXTURE="+payloadPath,
		"CHECKSUMS_FIXTURE="+checksumsPath,
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
	wantRequests := "https://github.com/Cd1s/ssm/releases/latest/download/ssm-linux-amd64\n" +
		"https://github.com/Cd1s/ssm/releases/latest/download/checksums.txt\n"
	if string(requests) != wantRequests {
		t.Fatalf("legacy installer requests=%q, want %q", requests, wantRequests)
	}
	repo, err := os.ReadFile(filepath.Join(configDir, "update_repo")) //nolint:gosec // configDir is a test-owned temporary directory
	if err != nil || strings.TrimSpace(string(repo)) != "Cd1s/ssm" {
		t.Fatalf("update_repo=%q err=%v", repo, err)
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
