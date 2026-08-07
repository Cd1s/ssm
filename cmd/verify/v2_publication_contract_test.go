package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestV2ReleaseWorkflowCannotPromoteGitHubLatest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for description, required := range map[string]string{
		"v2-only tag trigger":        "      - \"v2.*\"\n",
		"v2-only identity grammar":   `if [[ ! "$tag" =~ ^v2\.[0-9]+\.[0-9]+$ ]]; then`,
		"same-tag serialization":     "  group: release-${{ github.repository }}-${{ github.ref }}\n",
		"no concurrent cancellation": "  cancel-in-progress: false\n",
		"exact section extraction":   "            found && /^## / { exit }\n",
		"create-only helper":         "./scripts/release-create-only.sh",
		"reviewed previous latest":   "            v2.0.1 \\\n",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("v2 release workflow lacks %s %q", description, required)
		}
	}
	if strings.Contains(workflow, "make_latest: true") || strings.Contains(workflow, `make_latest: "true"`) {
		t.Fatal("v2 release workflow can still promote itself to GitHub latest")
	}
	if strings.Contains(workflow, "overwrite_files: true") {
		t.Fatal("v2 release workflow can still overwrite existing GitHub release assets")
	}
	if got := strings.Count(workflow, `./scripts/release-create-only.sh assert-absent "$tag"`); got != 1 {
		t.Errorf("v2 release workflow must reject drafts and published releases during preflight exactly once; got %d helper calls", got)
	}
	if got := strings.Count(workflow, `./scripts/release-create-only.sh publish`); got != 1 {
		t.Errorf("v2 release workflow must use the create-only publisher exactly once; got %d helper calls", got)
	}
	if strings.Contains(workflow, "softprops/action-gh-release") {
		t.Fatal("v2 release workflow still uses an update-or-create release action")
	}
	if strings.Contains(workflow, "if git ls-remote --exit-code") {
		t.Fatal("v2 release identity still treats an unresolved remote tag as optional")
	}
	if strings.Contains(workflow, "found && /^## v[0-9]/ { exit }") {
		t.Fatal("v2 release body can include unrelated level-two historical sections")
	}
	script := releaseWorkflowIdentityScript(t, workflow)
	if !strings.Contains(script, `tag $tag does not resolve to a remote commit`) {
		t.Fatal("v2 release identity does not fail closed when the selected remote tag is unresolved")
	}
}

func TestCreateOnlyReleaseScriptRefusesExistingDraft(t *testing.T) {
	root := filepath.Join("..", "..")
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "gh.log")
	fakeGH := filepath.Join(bin, "gh")
	fake := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$GH_FAKE_LOG"
case "$*" in
  *"releases?per_page=100"*) printf '%s\n' '[{"id":364597135,"tag_name":"v1.4.4"},{"id":5252,"tag_name":"v2.0.0"}]' ;;
  *) exit 97 ;;
esac
`
	if err := os.WriteFile(fakeGH, []byte(fake), 0o755); err != nil { //nolint:gosec // test-owned fake CLI must be executable
		t.Fatal(err)
	}
	command := exec.Command("bash", filepath.Join(root, "scripts", "release-create-only.sh"), "assert-absent", "v2.0.0") //nolint:gosec // repository script and fixed arguments
	command.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "GH_FAKE_LOG="+logPath, "GITHUB_REPOSITORY=Cd1s/ssm", "GH_TOKEN=test-only")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("existing draft was accepted: %s", output)
	}
	if !strings.Contains(string(output), "already exists; refusing to mutate or overwrite it") {
		t.Fatalf("existing draft refusal output = %q", output)
	}
	calls, readErr := os.ReadFile(logPath) //nolint:gosec // test-owned temporary log path
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(calls), "--method POST") || strings.Contains(string(calls), "release upload") {
		t.Fatalf("existing draft reached a mutating API call: %s", calls)
	}
}

func TestCreateOnlyReleaseScriptRejectsMalformedReleaseInventory(t *testing.T) {
	root := filepath.Join("..", "..")
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "gh.log")
	fakeGH := filepath.Join(bin, "gh")
	fake := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$GH_FAKE_LOG"
case "$*" in
  *"releases?per_page=100"*) printf '%s\n' '[{"id":1}]' ;;
  *) exit 97 ;;
esac
`
	if err := os.WriteFile(fakeGH, []byte(fake), 0o755); err != nil { //nolint:gosec // test-owned fake CLI must be executable
		t.Fatal(err)
	}
	command := exec.Command("bash", filepath.Join(root, "scripts", "release-create-only.sh"), "assert-absent", "v2.0.0") //nolint:gosec // repository script and fixed arguments
	command.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "GH_FAKE_LOG="+logPath, "GITHUB_REPOSITORY=Cd1s/ssm", "GH_TOKEN=test-only")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("malformed release inventory was accepted: %s", output)
	}
	if !strings.Contains(string(output), "Release inventory is malformed") {
		t.Fatalf("malformed inventory refusal output = %q", output)
	}
	calls, readErr := os.ReadFile(logPath) //nolint:gosec // test-owned temporary log path
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(calls), "--method POST") {
		t.Fatalf("malformed inventory reached a mutating API call: %s", calls)
	}
}

func TestCreateOnlyReleaseScriptContract(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "release-create-only.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for description, required := range map[string]string{
		"draft-visible exhaustive lookup":   `gh api --paginate`,
		"authenticated release listing":     `releases?per_page=100`,
		"one create-only REST call":         `gh api --method POST`,
		"literal ID-bound upload URL":       `https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$created_release_id/assets?name=`,
		"strict inventory schema":           `Release inventory is malformed`,
		"exact upload content type":         `application/octet-stream`,
		"exact upload size":                 `.size == $size`,
		"exact upload digest":               `.digest == $digest`,
		"stable creation":                   `draft: false`,
		"non-prerelease creation":           `prerelease: false`,
		"non-latest creation":               `make_latest: "false"`,
		"created release binding":           `created_release_id`,
		"post-create uniqueness binding":    `assert_only_created_release`,
		"bounded visibility reconciliation": `release_visibility_max_attempts=10`,
		"bounded visibility delay":          `release_visibility_default_delay_seconds=2`,
		"read-only visibility wait":         `await_only_created_release_visibility`,
		"reviewed latest input":             `local expected_latest_tag="$4"`,
		"exact latest preservation":         `--arg tag "$expected_latest_tag"`,
		"latest release has valid ID":       `(.id | type == "number" and . > 0)`,
		"created release is never latest":   `.id != $created_release_id`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("create-only publisher lacks %s %q", description, required)
		}
	}
	if got := strings.Count(text, `"repos/$GITHUB_REPOSITORY/releases"`); got != 1 {
		t.Errorf("create-only publisher has %d exact Release-create endpoint literals, want 1", got)
	}
	for _, forbidden := range []string{
		"softprops/action-gh-release", "gh release upload", "--hostname uploads.github.com", "--clobber", "--method PATCH", "--method DELETE", "release edit", `make_latest: "true"`, `required_latest_tag=`,
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("create-only publisher contains forbidden update/reuse behavior %q", forbidden)
		}
	}
}

func TestCreateOnlyReleaseScriptRejectsInvalidExpectedLatestBeforeMutation(t *testing.T) {
	root := filepath.Join("..", "..")
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "gh.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fakeGH := filepath.Join(bin, "gh")
	fake := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$GH_FAKE_LOG"
exit 97
`
	if err := os.WriteFile(fakeGH, []byte(fake), 0o755); err != nil { //nolint:gosec // test-owned fake CLI must be executable
		t.Fatal(err)
	}

	for _, test := range []struct {
		name           string
		expectedLatest string
		want           string
	}{
		{name: "malformed", expectedLatest: "2.0.0", want: "expected latest tag must be an exact stable v-tag"},
		{name: "same as target", expectedLatest: "v2.0.1", want: "expected latest tag must differ from target tag"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := createOnlyPublishArguments(t, "v2.0.1", test.expectedLatest)
			command := exec.Command("bash", append([]string{filepath.Join(root, "scripts", "release-create-only.sh")}, args...)...) //nolint:gosec // repository script and test-owned fixture paths
			command.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "GH_FAKE_LOG="+logPath, "GITHUB_REPOSITORY=Cd1s/ssm", "GH_TOKEN=test-only", "RUNNER_TEMP="+t.TempDir())
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("invalid expected latest was accepted: %s", output)
			}
			if !strings.Contains(string(output), test.want) {
				t.Fatalf("invalid expected latest output = %q, want %q", output, test.want)
			}
		})
	}
	calls, err := os.ReadFile(logPath) //nolint:gosec // test-owned temporary log path
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("invalid expected latest reached GitHub: %s", calls)
	}
}

func TestCreateOnlyReleaseScriptStopsWhenCreateConflicts(t *testing.T) {
	root := filepath.Join("..", "..")
	bin := t.TempDir()
	fixture := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "gh.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fakeGH := filepath.Join(bin, "gh")
	fake := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$GH_FAKE_LOG"
case "$*" in
  api\ --paginate*) printf '%s\n' '[]' ;;
  api\ repos/Cd1s/ssm/releases/latest*) printf '%s\n' '{"id":364882535,"tag_name":"v2.0.0","draft":false,"prerelease":false}' ;;
  api\ --method\ POST*) exit 42 ;;
  *) exit 97 ;;
esac
`
	if err := os.WriteFile(fakeGH, []byte(fake), 0o755); err != nil { //nolint:gosec // test-owned fake CLI must be executable
		t.Fatal(err)
	}
	assets := v2ReleaseAssetNames()
	args := []string{"publish", "v2.0.1", strings.Repeat("a", 40)}
	body := filepath.Join(fixture, "release-body.md")
	if err := os.WriteFile(body, []byte("reviewed release notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args = append(args, body, "v2.0.0")
	for _, name := range assets {
		path := filepath.Join(fixture, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, path)
	}
	command := exec.Command("bash", append([]string{filepath.Join(root, "scripts", "release-create-only.sh")}, args...)...) //nolint:gosec // repository script and test-owned fixture paths
	command.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "GH_FAKE_LOG="+logPath, "GITHUB_REPOSITORY=Cd1s/ssm", "GH_TOKEN=test-only", "RUNNER_TEMP="+t.TempDir())
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("conflicting create unexpectedly succeeded: %s", output)
	}
	calls, readErr := os.ReadFile(logPath) //nolint:gosec // test-owned temporary log path
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(calls), "release upload") || strings.Contains(string(calls), "uploads.github.com") {
		t.Fatalf("failed create fell through to asset upload: %s", calls)
	}
	if got := strings.Count(string(calls), "api --method POST repos/Cd1s/ssm/releases --input"); got != 1 {
		t.Fatalf("create calls = %d, want 1; calls=%s", got, calls)
	}
}

func runCreateOnlyReleaseScript(
	t *testing.T,
	actualLatestTag string,
	actualLatestIDJSON string,
	actualLatestDraft bool,
	actualLatestPrerelease bool,
) (string, string, error) {
	t.Helper()
	root := filepath.Join("..", "..")
	bin := t.TempDir()
	fixture := filepath.Join(t.TempDir(), `windows\path`)
	if err := os.MkdirAll(fixture, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "gh.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "created.json")
	assetsPath := filepath.Join(t.TempDir(), "assets.json")
	fakeGH := filepath.Join(bin, "gh")
	fake := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$GH_FAKE_LOG"
if [ "${1:-}" = api ] && [ "${2:-}" = --paginate ]; then
  if [ -n "${GH_FAKE_STATE:-}" ] && [ -s "$GH_FAKE_STATE" ]; then
    printf '%s\n' '[{"id":4242,"tag_name":"v2.0.1"}]'
  else
    printf '%s\n' '[]'
  fi
  exit 0
fi
if [ "${1:-}" = api ] && [ "${2:-}" = --method ] && [ "${3:-}" = POST ] && [ "${4:-}" = repos/Cd1s/ssm/releases ]; then
  shift 3
  input=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --input ]; then
      input="$2"
      break
    fi
    shift
  done
  [ -n "$input" ]
  cp "$input" "$GH_FAKE_STATE"
  jq '. + {id: 4242, assets: []}' "$input"
  exit 0
fi
if [ "${1:-}" = api ] && [ "${2:-}" = --method ] && [ "${3:-}" = POST ]; then
  case "${4:-}" in
    https://uploads.github.com/repos/Cd1s/ssm/releases/4242/assets?name=*)
      name="${4##*name=}"
      shift 4
      input=""
      while [ "$#" -gt 0 ]; do
        if [ "$1" = --input ]; then
          input="$2"
          break
        fi
        shift
      done
      [ -n "$input" ]
      size="$(wc -c < "$input" | tr -d '[:space:]')"
      digest="sha256:$(sha256sum < "$input" | awk '{print $1}')"
      jq -n --arg name "$name" --argjson size "$size" --arg digest "$digest" \
        '{id:9001,name:$name,state:"uploaded",content_type:"application/octet-stream",size:$size,digest:$digest}'
      exit 0
      ;;
  esac
  exit 96
fi
case "${2:-}" in
  repos/Cd1s/ssm/releases/tags/v2.0.1)
    jq '. + {id: 4242, assets: []}' "$GH_FAKE_STATE"
    ;;
  repos/Cd1s/ssm/releases/4242)
    jq --slurpfile assets "$GH_FAKE_ASSETS" '. + {id: 4242, assets: $assets[0]}' "$GH_FAKE_STATE"
    ;;
  repos/Cd1s/ssm/releases/latest)
    jq -n --argjson id "$GH_FAKE_LATEST_ID_JSON" --arg tag "$GH_FAKE_LATEST_TAG" \
      --argjson draft "$GH_FAKE_LATEST_DRAFT" --argjson prerelease "$GH_FAKE_LATEST_PRERELEASE" \
      '{id:$id,tag_name:$tag,draft:$draft,prerelease:$prerelease}'
    ;;
  *) exit 97 ;;
esac
`
	if err := os.WriteFile(fakeGH, []byte(fake), 0o755); err != nil { //nolint:gosec // test-owned fake CLI must be executable
		t.Fatal(err)
	}
	assets := v2ReleaseAssetNames()
	assetObjects := make([]map[string]any, 0, len(assets))
	for _, name := range assets {
		digest := sha256.Sum256([]byte(name))
		assetObjects = append(assetObjects, map[string]any{
			"name": name, "state": "uploaded", "content_type": "application/octet-stream",
			"size": len(name), "digest": fmt.Sprintf("sha256:%x", digest),
		})
	}
	assetJSON, err := json.Marshal(assetObjects)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assetsPath, assetJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"publish", "v2.0.1", strings.Repeat("a", 40)}
	body := filepath.Join(fixture, "release-body.md")
	if err := os.WriteFile(body, []byte("reviewed release notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args = append(args, body, "v2.0.0")
	for _, name := range assets {
		path := filepath.Join(fixture, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, path)
	}
	command := exec.Command("bash", append([]string{filepath.Join(root, "scripts", "release-create-only.sh")}, args...)...) //nolint:gosec // repository script and test-owned fixture paths
	command.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GH_FAKE_LOG="+logPath,
		"GH_FAKE_STATE="+statePath,
		"GH_FAKE_ASSETS="+assetsPath,
		"GH_FAKE_LATEST_TAG="+actualLatestTag,
		"GH_FAKE_LATEST_ID_JSON="+actualLatestIDJSON,
		fmt.Sprintf("GH_FAKE_LATEST_DRAFT=%t", actualLatestDraft),
		fmt.Sprintf("GH_FAKE_LATEST_PRERELEASE=%t", actualLatestPrerelease),
		"GITHUB_REPOSITORY=Cd1s/ssm",
		"GH_TOKEN=test-only",
		"RUNNER_TEMP="+t.TempDir(),
	)
	output, runErr := command.CombinedOutput()
	calls, err := os.ReadFile(logPath) //nolint:gosec // test-owned temporary log path
	if err != nil {
		t.Fatal(err)
	}
	return string(output), string(calls), runErr
}

func TestCreateOnlyReleaseScriptPublishesNewReleaseOnce(t *testing.T) {
	output, callText, err := runCreateOnlyReleaseScript(t, "v2.0.0", "364882535", false, false)
	if err != nil {
		t.Fatalf("create-only publication failed: %v\n%s", err, output)
	}
	if got := strings.Count(callText, "api --method POST repos/Cd1s/ssm/releases --input"); got != 1 {
		t.Fatalf("create calls = %d, want 1; calls=%s", got, callText)
	}
	if strings.Contains(callText, "release upload") {
		t.Fatalf("publication used mutable tag-resolved upload: %s", callText)
	}
	idBoundUpload := "api --method POST https://uploads.github.com/repos/Cd1s/ssm/releases/4242/assets?name="
	if got := strings.Count(callText, idBoundUpload); got != len(v2ReleaseAssetNames()) {
		t.Fatalf("ID-bound upload calls = %d, want %d; calls=%s", got, len(v2ReleaseAssetNames()), callText)
	}
	for _, forbidden := range []string{"--clobber", "--method PATCH", "--method DELETE", "release edit"} {
		if strings.Contains(callText, forbidden) {
			t.Fatalf("create-only publication used forbidden mutation %q: %s", forbidden, callText)
		}
	}
	if got := strings.Count(callText, "api repos/Cd1s/ssm/releases/latest"); got != 2 {
		t.Fatalf("latest GET calls = %d, want pre-create and post-upload checks; calls=%s", got, callText)
	}
}

func TestCreateOnlyReleaseScriptWaitsForExactCreatedReleaseVisibility(t *testing.T) {
	exact := `[{"id":4242,"tag_name":"v2.0.1"}]`
	output, calls, err := runCreateOnlyVisibilityScenario(t, []string{`[]`, `[]`, exact})
	if err != nil {
		t.Fatalf("delayed exact visibility failed: %v\n%s", err, output)
	}
	if got := strings.Count(calls, "api --method POST repos/Cd1s/ssm/releases --input"); got != 1 {
		t.Fatalf("create calls = %d, want exactly 1; calls=%s", got, calls)
	}
	firstUpload := strings.Index(calls, "api --method POST https://uploads.github.com/")
	if firstUpload < 0 {
		t.Fatalf("exact delayed visibility never reached asset upload: %s", calls)
	}
	if got := strings.Count(calls[:firstUpload], "api --paginate repos/Cd1s/ssm/releases?per_page=100"); got != 4 {
		t.Fatalf("Release inventory reads before first upload = %d, want initial absence plus 3 visibility reads; calls=%s", got, calls)
	}
}

func TestCreateOnlyReleaseScriptVisibilityTimeoutDoesNotUpload(t *testing.T) {
	output, calls, err := runCreateOnlyVisibilityScenario(t, []string{`[]`})
	if err == nil || !strings.Contains(output, "did not become uniquely visible after 10 attempts") {
		t.Fatalf("visibility timeout output = %q, err=%v", output, err)
	}
	if got := strings.Count(calls, "api --method POST repos/Cd1s/ssm/releases --input"); got != 1 {
		t.Fatalf("create calls = %d, want exactly 1; calls=%s", got, calls)
	}
	if got := strings.Count(calls, "api --paginate repos/Cd1s/ssm/releases?per_page=100"); got != 11 {
		t.Fatalf("Release inventory reads = %d, want initial absence plus 10 bounded visibility reads; calls=%s", got, calls)
	}
	assertNoAssetUploadCalls(t, calls)
}

func TestCreateOnlyReleaseScriptRejectsInexactCreatedReleaseVisibilityBeforeUpload(t *testing.T) {
	tests := map[string]string{
		"malformed":        `[{"id":4242}]`,
		"duplicate tag":    `[{"id":4242,"tag_name":"v2.0.1"},{"id":4243,"tag_name":"v2.0.1"}]`,
		"duplicate ID":     `[{"id":4242,"tag_name":"v2.0.1"},{"id":4242,"tag_name":"v9.9.9"}]`,
		"wrong ID for tag": `[{"id":4243,"tag_name":"v2.0.1"}]`,
		"wrong tag for ID": `[{"id":4242,"tag_name":"v9.9.9"}]`,
	}
	for name, inventory := range tests {
		t.Run(name, func(t *testing.T) {
			output, calls, err := runCreateOnlyVisibilityScenario(t, []string{inventory})
			if err == nil {
				t.Fatalf("inexact visibility unexpectedly succeeded: %s", output)
			}
			if got := strings.Count(calls, "api --method POST repos/Cd1s/ssm/releases --input"); got != 1 {
				t.Fatalf("create calls = %d, want exactly 1; calls=%s", got, calls)
			}
			assertNoAssetUploadCalls(t, calls)
		})
	}
}

func runCreateOnlyVisibilityScenario(t *testing.T, inventories []string) (string, string, error) {
	t.Helper()
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "gh.log")
	statePath := filepath.Join(t.TempDir(), "created.json")
	counterPath := filepath.Join(t.TempDir(), "inventory-count")
	assetsPath := filepath.Join(t.TempDir(), "assets.json")
	fakeGH := filepath.Join(bin, "gh")
	if runtime.GOOS == "windows" {
		fakeGH += ".exe"
	}

	assetObjects := make([]map[string]any, 0, len(v2ReleaseAssetNames()))
	for _, name := range v2ReleaseAssetNames() {
		digest := sha256.Sum256([]byte(name))
		assetObjects = append(assetObjects, map[string]any{
			"name": name, "state": "uploaded", "content_type": "application/octet-stream",
			"size": len(name), "digest": fmt.Sprintf("sha256:%x", digest),
		})
	}
	assetsJSON, err := json.Marshal(assetObjects)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assetsPath, assetsJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	quotedInventories := make([]string, 0, len(inventories))
	for _, inventory := range inventories {
		quotedInventories = append(quotedInventories, strconv.Quote(inventory))
	}
	inventoriesLiteral := "[]string{" + strings.Join(quotedInventories, ",") + "}"

	fakeSource := filepath.Join(bin, "fake-gh.go")
	fake := `package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var inventories = ` + inventoriesLiteral + `

func fatal(err error) {
	if err != nil { panic(err) }
}

func logCall(call string) {
	f, err := os.OpenFile(os.Getenv("GH_FAKE_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	fatal(err)
	_, err = fmt.Fprintln(f, call)
	fatal(err)
	fatal(f.Close())
}

func emitRelease(path string, assets json.RawMessage) {
	b, err := os.ReadFile(path)
	fatal(err)
	var release map[string]any
	fatal(json.Unmarshal(b, &release))
	release["id"] = float64(4242)
	var assetValue any
	fatal(json.Unmarshal(assets, &assetValue))
	release["assets"] = assetValue
	fatal(json.NewEncoder(os.Stdout).Encode(release))
}

func inputPath(args []string) string {
	for i := range args {
		if args[i] == "--input" && i+1 < len(args) { return args[i+1] }
	}
	return ""
}

func main() {
	args := os.Args[1:]
	call := strings.Join(args, " ")
	logCall(call)
	state := os.Getenv("GH_FAKE_STATE")
	switch {
	case len(args) >= 3 && args[0] == "api" && args[1] == "--paginate":
		if _, err := os.Stat(state); err != nil {
			fmt.Println("[]")
			return
		}
		counterPath := os.Getenv("GH_FAKE_COUNTER")
		count := 0
		if b, err := os.ReadFile(counterPath); err == nil { count, _ = strconv.Atoi(string(b)) }
		fatal(os.WriteFile(counterPath, []byte(strconv.Itoa(count+1)), 0o600))
		index := count
		if index >= len(inventories) { index = len(inventories)-1 }
		fmt.Println(inventories[index])
	case len(args) >= 4 && args[0] == "api" && args[1] == "--method" && args[2] == "POST" && args[3] == "repos/Cd1s/ssm/releases":
		input := inputPath(args)
		b, err := os.ReadFile(input)
		fatal(err)
		fatal(os.WriteFile(state, b, 0o600))
		emitRelease(state, json.RawMessage("[]"))
	case len(args) >= 4 && args[0] == "api" && args[1] == "--method" && args[2] == "POST" && strings.HasPrefix(args[3], "https://uploads.github.com/repos/Cd1s/ssm/releases/4242/assets?name="):
		input := inputPath(args)
		b, err := os.ReadFile(input)
		fatal(err)
		sum := sha256.Sum256(b)
		parsed, err := url.Parse(args[3])
		fatal(err)
		name := parsed.Query().Get("name")
		fmt.Printf("{\"id\":9001,\"name\":%q,\"state\":\"uploaded\",\"content_type\":\"application/octet-stream\",\"size\":%d,\"digest\":\"sha256:%s\"}\n", name, len(b), hex.EncodeToString(sum[:]))
	case len(args) >= 2 && args[0] == "api" && args[1] == "repos/Cd1s/ssm/releases/tags/v2.0.1":
		emitRelease(state, json.RawMessage("[]"))
	case len(args) >= 2 && args[0] == "api" && args[1] == "repos/Cd1s/ssm/releases/4242":
		assets, err := os.ReadFile(os.Getenv("GH_FAKE_ASSETS"))
		fatal(err)
		emitRelease(state, assets)
	case len(args) >= 2 && args[0] == "api" && args[1] == "repos/Cd1s/ssm/releases/latest":
		fmt.Println(` + strconv.Quote(`{"id":364882535,"tag_name":"v2.0.0","draft":false,"prerelease":false}`) + `)
	default:
		os.Exit(97)
	}
}
`
	if err := os.WriteFile(fakeSource, []byte(fake), 0o600); err != nil { //nolint:gosec // test-owned fake CLI source
		t.Fatal(err)
	}
	goExecutable, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command(goExecutable, "build", "-buildvcs=false", "-o", fakeGH, fakeSource) //nolint:gosec // fixed test-owned compiler and source
	build.Env = append(os.Environ(), "GO111MODULE=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake gh: %v: %s", err, output)
	}

	root := filepath.Join("..", "..")
	args := createOnlyPublishArguments(t, "v2.0.1", "v2.0.0")
	command := exec.Command("bash", append([]string{filepath.Join(root, "scripts", "release-create-only.sh")}, args...)...) //nolint:gosec // fixed repository helper and test-owned fixtures
	command.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GH_FAKE_LOG="+logPath,
		"GH_FAKE_STATE="+statePath,
		"GH_FAKE_COUNTER="+counterPath,
		"GH_FAKE_ASSETS="+assetsPath,
		"GITHUB_REPOSITORY=Cd1s/ssm",
		"GH_TOKEN=test-only",
		"RUNNER_TEMP="+t.TempDir(),
		"SSM_RELEASE_VISIBILITY_RETRY_DELAY_SECONDS=0",
	)
	output, runErr := command.CombinedOutput()
	calls, err := os.ReadFile(logPath) //nolint:gosec // test-owned log
	if err != nil {
		t.Fatal(err)
	}
	return string(output), string(calls), runErr
}

func assertNoAssetUploadCalls(t *testing.T, calls string) {
	t.Helper()
	if got := strings.Count(calls, "api --method POST https://uploads.github.com/repos/Cd1s/ssm/releases/"); got != 0 {
		t.Fatalf("asset upload calls = %d, want 0; calls=%s", got, calls)
	}
}

func TestCreateOnlyReleaseScriptRejectsActualLatestMismatch(t *testing.T) {
	output, calls, err := runCreateOnlyReleaseScript(t, "v1.4.4", "364597135", false, false)
	if err == nil {
		t.Fatalf("actual latest mismatch was accepted: %s", output)
	}
	if !strings.Contains(output, "GitHub latest does not match reviewed baseline v2.0.0 before create") {
		t.Fatalf("actual latest mismatch output = %q", output)
	}
	assertNoReleaseMutationCalls(t, calls)
}

func TestCreateOnlyReleaseScriptRejectsCreatedReleaseAsLatest(t *testing.T) {
	output, calls, err := runCreateOnlyReleaseScript(t, "v2.0.0", "4242", false, false)
	if err == nil {
		t.Fatalf("created Release was accepted as latest: %s", output)
	}
	if !strings.Contains(output, "created GitHub Release ID matches reviewed latest Release ID") {
		t.Fatalf("created Release latest output = %q", output)
	}
	if got := strings.Count(calls, "api --method POST repos/Cd1s/ssm/releases --input"); got != 1 {
		t.Fatalf("create calls = %d, want 1; calls=%s", got, calls)
	}
	if got := strings.Count(calls, "api --method POST https://uploads.github.com/repos/Cd1s/ssm/releases/4242/assets?name="); got != 0 {
		t.Fatalf("ID-bound upload calls = %d, want 0; calls=%s", got, calls)
	}
}

func TestCreateOnlyReleaseScriptRejectsInvalidLiveLatestBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name       string
		idJSON     string
		draft      bool
		prerelease bool
	}{
		{name: "zero ID", idJSON: "0"},
		{name: "string ID", idJSON: `"364882535"`},
		{name: "draft", idJSON: "364882535", draft: true},
		{name: "prerelease", idJSON: "364882535", prerelease: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, calls, err := runCreateOnlyReleaseScript(t, "v2.0.0", test.idJSON, test.draft, test.prerelease)
			if err == nil {
				t.Fatalf("invalid live latest was accepted: %s", output)
			}
			if !strings.Contains(output, "GitHub latest does not match reviewed baseline v2.0.0 before create") {
				t.Fatalf("invalid live latest output = %q", output)
			}
			assertNoReleaseMutationCalls(t, calls)
		})
	}
}

func assertNoReleaseMutationCalls(t *testing.T, calls string) {
	t.Helper()
	if got := strings.Count(calls, "api --method POST repos/Cd1s/ssm/releases --input"); got != 0 {
		t.Fatalf("create calls = %d, want 0; calls=%s", got, calls)
	}
	if got := strings.Count(calls, "api --method POST https://uploads.github.com/repos/Cd1s/ssm/releases/"); got != 0 {
		t.Fatalf("asset upload calls = %d, want 0; calls=%s", got, calls)
	}
}

func createOnlyPublishArguments(t *testing.T, targetTag, expectedLatestTag string) []string {
	t.Helper()
	fixture := t.TempDir()
	body := filepath.Join(fixture, "release-body.md")
	if err := os.WriteFile(body, []byte("reviewed release notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"publish", targetTag, strings.Repeat("a", 40), body, expectedLatestTag}
	for _, name := range v2ReleaseAssetNames() {
		path := filepath.Join(fixture, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, path)
	}
	return args
}

func v2ReleaseAssetNames() []string {
	return []string{
		"ssm-linux-amd64", "ssm-linux-arm64", "ssm-darwin-amd64", "ssm-darwin-arm64",
		"ssm-windows-amd64.exe", "ssm-windows-arm64.exe",
		"ssm-linux-amd64.sigstore.json", "ssm-linux-arm64.sigstore.json",
		"ssm-darwin-amd64.sigstore.json", "ssm-darwin-arm64.sigstore.json",
		"ssm-windows-amd64.exe.sigstore.json", "ssm-windows-arm64.exe.sigstore.json",
		"install.sh", "checksums.txt",
	}
}

func TestTrackedV2PublicationMetadataIsExactAndDurable(t *testing.T) {
	root := filepath.Join("..", "..")
	version, err := readSourceVersion(root)
	if err != nil {
		t.Fatal(err)
	}
	if version != "2.0.2" {
		t.Fatalf("source version = %q, want exact v2.0.2", version)
	}
	if err := validateReleaseNotes(root, version); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "RELEASE_NOTES.md")) //nolint:gosec // root and release-note path are repository-owned test inputs
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.ToLower(strings.Join(strings.Fields(string(data)), " "))
	for _, stale := range []string{
		"source and current release remain v1.4.3",
		"initial v2 release remains blocked",
		"a v2 binary is not available",
		"planned release build",
		"planned installer",
	} {
		if strings.Contains(notes, stale) {
			t.Errorf("v2 release notes retain stale pre-publication claim %q", stale)
		}
	}
	for _, durable := range []string{
		"backward-compatible patch release",
		"github cli 2.92.0",
		"private `mktemp` directory",
		"attestation.json",
		"no protocol or schema breaking change",
		"v2 compatibility behavior remains",
		"make_latest=false",
		"v2.0.2 is now github latest",
		"exact-tag release workflow",
	} {
		if !strings.Contains(notes, durable) {
			t.Errorf("v2 release notes omit durable publication contract %q", durable)
		}
	}
}

func TestInstallerSupportsExplicitExactTagWithoutChangingLatestDefault(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	installer := string(data)
	for description, required := range map[string]string{
		"opt-in exact tag":        `requested_tag="${SSM_RELEASE_TAG:-}"`,
		"default latest endpoint": `metadata_path="releases/latest"`,
		"exact-tag endpoint":      `metadata_path="releases/tags/$requested_tag"`,
		"stable tag grammar":      `^v[0-9]+\.[0-9]+\.[0-9]+$`,
		"selected-tag equality":   `"$release_tag" != "$requested_tag"`,
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("installer lacks %s contract %q", description, required)
		}
	}
}
