package main

import (
	"os"
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
		"stable release":             "          prerelease: false\n",
		"non-draft release":          "          draft: false\n",
		"non-latest release":         "          make_latest: false\n",
		"asset non-overwrite":        "          overwrite_files: false\n",
		"exact file match":           "          fail_on_unmatched_files: true\n",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("v2 release workflow lacks %s %q", description, required)
		}
	}
	if strings.Contains(workflow, "make_latest: true") {
		t.Fatal("v2 release workflow can still promote itself to GitHub latest")
	}
	if strings.Contains(workflow, "overwrite_files: true") {
		t.Fatal("v2 release workflow can still overwrite existing GitHub release assets")
	}
	for description, required := range map[string]string{
		"existing-release endpoint": "releases/tags/$tag",
		"existing-release refusal":  "GitHub Release $tag already exists; refusing to mutate or overwrite it",
		"ambiguous-state refusal":   "unable to prove GitHub Release $tag is absent\" >&2",
	} {
		if got := strings.Count(workflow, required); got != 2 {
			t.Errorf("v2 release workflow must enforce %s before preflight and publication: got %d occurrences of %q, want 2", description, got, required)
		}
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
