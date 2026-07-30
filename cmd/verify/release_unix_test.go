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
	payload := []byte("#!/bin/sh\necho synthetic replacement\n")
	digest := sha256.Sum256(payload)
	fakeBin := t.TempDir()
	curlPath := filepath.Join(fakeBin, "curl")
	writeTestFile(t, curlPath, fmt.Sprintf(`#!/bin/sh
set -eu
url=""
output=""
write_format=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    -w) write_format="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  */releases/latest) : ;;
  */checksums.txt) printf '%x  %s\n' >"$output" ;;
  *.sigstore.json) printf '{}\n' >"$output" ;;
  */%s) printf '#!/bin/sh\necho synthetic replacement\n' >"$output" ;;
  *) exit 90 ;;
esac
if [ -n "$write_format" ]; then
  printf 'https://github.com/Cd1s/ssm/releases/tag/v9.9.9'
fi
`, digest, asset, asset))
	if err := os.Chmod(curlPath, 0o700); err != nil { //nolint:gosec // test-owned command shim
		t.Fatal(err)
	}
	ghPath := filepath.Join(fakeBin, "gh")
	ghMarker := filepath.Join(t.TempDir(), "gh-called")
	writeTestFile(t, ghPath, "#!/bin/sh\nset -eu\nprintf called >\"$GH_MARKER\"\nexit 42\n")
	if err := os.Chmod(ghPath, 0o700); err != nil { //nolint:gosec // test-owned command shim
		t.Fatal(err)
	}

	command := exec.Command("sh", filepath.Join("..", "..", "install.sh")) //nolint:gosec // fixed tracked installer executes only against test-owned paths and command shims
	command.Env = append(
		newTestProcessEnvironment(t),
		"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SSM_PREFIX="+prefix,
		"SSM_CONFIG_DIR="+filepath.Join(t.TempDir(), "config"),
		"GH_MARKER="+ghMarker,
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("installer accepted failed provenance verification; output=%q", output)
	}
	after, readErr := os.ReadFile(executable) //nolint:gosec // test-owned installation target
	if readErr != nil {
		t.Fatal(readErr)
	}
	afterInfo, statErr := os.Stat(executable)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !bytes.Equal(after, original) || afterInfo.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf(
			"installer trust failure changed executable: bytes_equal=%t mode=%o want_mode=%o output=%q",
			bytes.Equal(after, original),
			afterInfo.Mode().Perm(),
			before.Mode().Perm(),
			output,
		)
	}
	if marker, markerErr := os.ReadFile(ghMarker); markerErr != nil || string(marker) != "called" { //nolint:gosec // marker is constrained to t.TempDir
		t.Fatalf("installer did not reach the failing provenance verifier: marker=%q error=%v", marker, markerErr)
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
		"main identity":             `main_identity="https://github.com/Cd1s/ssm/.github/workflows/release.yml@refs/heads/main"`,
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
	} {
		if strings.Contains(installer, forbidden) {
			t.Errorf("installer contains forbidden provenance bypass %q", forbidden)
		}
	}
}
