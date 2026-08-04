package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2RecoveryWorkflowIsExactlyBound(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "recover-v2.0.0.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for description, required := range map[string]string{
		"manual trigger":  "  workflow_dispatch:\n",
		"repository":      "Cd1s/ssm",
		"source SHA":      "10417d0e235eff9b22081765b0ad17b75cf74990",
		"release ID":      "364882535",
		"source run":      "30911029600",
		"latest ID":       "364597135",
		"latest tag":      "v1.4.4",
		"one-time helper": "./scripts/recover-v2.0.0-release.sh",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("recovery workflow lacks %s %q", description, required)
		}
	}
	for _, forbidden := range []string{"schedule:", "push:\n", "pull_request:", "--method PATCH", "--method DELETE", "gh release upload", "--clobber"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("recovery workflow contains forbidden behavior %q", forbidden)
		}
	}
}

func TestV2RecoveryHelperHasExactClosedContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "recover-v2.0.0-release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for description, required := range map[string]string{
		"exact repository":         `expected_repository="Cd1s/ssm"`,
		"exact tag":                `expected_tag="v2.0.0"`,
		"exact SHA":                `expected_source_sha="10417d0e235eff9b22081765b0ad17b75cf74990"`,
		"fixed release ID":         `expected_release_id="364882535"`,
		"source run ID":            `expected_run_id="30911029600"`,
		"latest release ID":        `required_latest_id="364597135"`,
		"latest tag":               `required_latest_tag="v1.4.4"`,
		"exhaustive inventory":     `releases?per_page=100`,
		"fixed release reads":      `releases/$expected_release_id`,
		"fixed upload origin":      `https://uploads.github.com/repos/$expected_repository/releases/$expected_release_id/assets?name=`,
		"tagged install source":    `contents/install.sh?ref=$expected_source_sha`,
		"original artifacts":       `actions/runs/$expected_run_id/artifacts?per_page=100`,
		"crypto verifier":          `go run ./cmd/recoveryverify`,
		"transport reconciliation": `reconcile_ambiguous_upload`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("recovery helper lacks %s %q", description, required)
		}
	}
	for _, name := range v2ReleaseAssetNames() {
		if !strings.Contains(script, name) {
			t.Errorf("recovery helper lacks exact asset %q", name)
		}
	}
	for _, forbidden := range []string{"--method PATCH", "--method DELETE", "gh release upload", "--clobber", "releases/tags/", "make_latest"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("recovery helper contains forbidden mutation/resolution %q", forbidden)
		}
	}
}
