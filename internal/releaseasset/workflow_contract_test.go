package releaseasset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBridgeReleaseWorkflowProducesEvidenceForLegacyLatestRollout(t *testing.T) {
	workflow := readRepositoryFile(t, ".github/workflows/release.yml")
	for description, required := range map[string]string{
		"tag-only source":        "tags:\n      - 'v1.*'",
		"read-only default":      "permissions:\n  contents: read",
		"OIDC build permission":  "id-token: write",
		"attestation permission": "attestations: write",
		"attestation action":     "uses: actions/attest@v4",
		"adjacent bundle":        ".sigstore.json",
		"exact workflow ref":     "Cd1s/ssm/.github/workflows/release.yml@refs/tags/$tag",
		"bridge rollout latest":  "make_latest: true",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("release workflow lacks %s %q", description, required)
		}
	}
	if strings.Contains(workflow, "workflow_dispatch:") {
		t.Error("release workflow permits a branch/manual publishing identity")
	}
	for _, name := range ExpectedReleaseNames() {
		if !strings.Contains(workflow, name) && name != "checksums.txt" && name != "install.sh" {
			t.Errorf("release workflow lacks asset %q", name)
		}
	}
}

func TestMaintenanceCIRequiresNativeAndNonPublishingCandidateGates(t *testing.T) {
	ci := readRepositoryFile(t, ".github/workflows/ci.yml")
	for description, required := range map[string]string{
		"maintenance PR trigger": "release/v1.4.x",
		"Windows native job":     "runs-on: windows-latest",
		"Darwin native job":      "runs-on: macos-latest",
		"Windows security test":  "TestWindowsNativeReplacementSecurity",
		"Darwin security test":   "TestDarwinNativeReplacementSecurity",
		"candidate verifier":     "go run ./cmd/bridgeverify candidate",
		"read-only permissions":  "permissions:\n  contents: read",
	} {
		if !strings.Contains(ci, required) {
			t.Errorf("maintenance CI lacks %s %q", description, required)
		}
	}
	for _, forbidden := range []string{"action-gh-release", "gh release create", "git tag", "contents: write"} {
		if strings.Contains(ci, forbidden) {
			t.Errorf("maintenance CI contains publication authority %q", forbidden)
		}
	}
}

func readRepositoryFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", filepath.FromSlash(name))
	data, err := os.ReadFile(path) //nolint:gosec // callers provide fixed repository-relative contract paths
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
