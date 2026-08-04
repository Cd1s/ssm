package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
  *"releases?per_page=100"*) printf '%s\n' 'v1.4.4' 'v2.0.0' ;;
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

func TestCreateOnlyReleaseScriptContract(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "release-create-only.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for description, required := range map[string]string{
		"draft-visible exhaustive lookup": `gh api --paginate`,
		"authenticated release listing":   `releases?per_page=100`,
		"one create-only REST call":       `gh api --method POST`,
		"stable creation":                 `draft: false`,
		"non-prerelease creation":         `prerelease: false`,
		"non-latest creation":             `make_latest: "false"`,
		"created release binding":         `created_release_id`,
		"post-create uniqueness binding":  `assert_only_created_release`,
		"exact latest preservation":       `required_latest_tag="v1.4.4"`,
	} {
		if !strings.Contains(text, required) {
			t.Errorf("create-only publisher lacks %s %q", description, required)
		}
	}
	for _, forbidden := range []string{
		"softprops/action-gh-release", "--clobber", "--method PATCH", "--method DELETE", "release edit", `make_latest: "true"`,
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("create-only publisher contains forbidden update/reuse behavior %q", forbidden)
		}
	}
}

func TestCreateOnlyReleaseScriptStopsWhenCreateConflicts(t *testing.T) {
	root := filepath.Join("..", "..")
	bin := t.TempDir()
	fixture := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "gh.log")
	fakeGH := filepath.Join(bin, "gh")
	fake := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$GH_FAKE_LOG"
case "$*" in
  api\ --paginate*) exit 0 ;;
  api\ --method\ POST*) exit 42 ;;
  *) exit 97 ;;
esac
`
	if err := os.WriteFile(fakeGH, []byte(fake), 0o755); err != nil { //nolint:gosec // test-owned fake CLI must be executable
		t.Fatal(err)
	}
	assets := v2ReleaseAssetNames()
	args := []string{"publish", "v2.0.0", strings.Repeat("a", 40)}
	body := filepath.Join(fixture, "release-body.md")
	if err := os.WriteFile(body, []byte("reviewed release notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args = append(args, body)
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
	if strings.Contains(string(calls), "release upload") {
		t.Fatalf("failed create fell through to asset upload: %s", calls)
	}
}

func TestCreateOnlyReleaseScriptPublishesNewReleaseOnce(t *testing.T) {
	root := filepath.Join("..", "..")
	bin := t.TempDir()
	fixture := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "gh.log")
	statePath := filepath.Join(t.TempDir(), "created.json")
	assetsPath := filepath.Join(t.TempDir(), "assets.json")
	fakeGH := filepath.Join(bin, "gh")
	fake := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$GH_FAKE_LOG"
if [ "${1:-}" = api ] && [ "${2:-}" = --paginate ]; then
  if [ -n "${GH_FAKE_STATE:-}" ] && [ -s "$GH_FAKE_STATE" ]; then
    case "$*" in
      *"[.id, .tag_name]"*) printf '4242\tv2.0.0\n' ;;
    esac
  fi
  exit 0
fi
if [ "${1:-}" = api ] && [ "${2:-}" = --method ] && [ "${3:-}" = POST ]; then
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
if [ "${1:-}" = release ] && [ "${2:-}" = upload ]; then
  exit 0
fi
case "${2:-}" in
  repos/Cd1s/ssm/releases/tags/v2.0.0)
    jq '. + {id: 4242, assets: []}' "$GH_FAKE_STATE"
    ;;
  repos/Cd1s/ssm/releases/4242)
    jq --slurpfile assets "$GH_FAKE_ASSETS" '. + {id: 4242, assets: $assets[0]}' "$GH_FAKE_STATE"
    ;;
  repos/Cd1s/ssm/releases/latest)
    printf '%s\n' '{"id":364597135,"tag_name":"v1.4.4","draft":false,"prerelease":false}'
    ;;
  *) exit 97 ;;
esac
`
	if err := os.WriteFile(fakeGH, []byte(fake), 0o755); err != nil { //nolint:gosec // test-owned fake CLI must be executable
		t.Fatal(err)
	}
	assets := v2ReleaseAssetNames()
	assetObjects := make([]map[string]string, 0, len(assets))
	for _, name := range assets {
		assetObjects = append(assetObjects, map[string]string{"name": name, "state": "uploaded"})
	}
	assetJSON, err := json.Marshal(assetObjects)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assetsPath, assetJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"publish", "v2.0.0", strings.Repeat("a", 40)}
	body := filepath.Join(fixture, "release-body.md")
	if err := os.WriteFile(body, []byte("reviewed release notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args = append(args, body)
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
		"GITHUB_REPOSITORY=Cd1s/ssm",
		"GH_TOKEN=test-only",
		"RUNNER_TEMP="+t.TempDir(),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("create-only publication failed: %v\n%s", err, output)
	}
	calls, err := os.ReadFile(logPath) //nolint:gosec // test-owned temporary log path
	if err != nil {
		t.Fatal(err)
	}
	callText := string(calls)
	if got := strings.Count(callText, "api --method POST"); got != 1 {
		t.Fatalf("create calls = %d, want 1; calls=%s", got, calls)
	}
	if got := strings.Count(callText, "release upload"); got != 1 {
		t.Fatalf("upload calls = %d, want 1; calls=%s", got, calls)
	}
	for _, forbidden := range []string{"--clobber", "--method PATCH", "--method DELETE", "release edit"} {
		if strings.Contains(callText, forbidden) {
			t.Fatalf("create-only publication used forbidden mutation %q: %s", forbidden, calls)
		}
	}
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
	if version != "2.0.0" {
		t.Fatalf("source version = %q, want exact v2.0.0", version)
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
		"stable v2.0.0",
		"make_latest=false",
		"v1.4.4 remains github latest",
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
