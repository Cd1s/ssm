package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func readWorkflowFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name)) //nolint:gosec // fixed reviewed workflow names
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMissingPinnedToolPrerequisitesShowCopyableAcquisitionCommands(t *testing.T) {
	manifest := verificationManifest()
	ci, ok := findProfile(manifest, "ci")
	if !ok {
		t.Fatal("ci profile not found")
	}
	want := map[string]string{
		"go":            "GOTOOLCHAIN=go1.26.8",
		"gofmt":         "GOTOOLCHAIN=go1.26.8",
		"golangci-lint": "GOBIN=<dir> go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4",
	}
	seen := map[string]bool{}
	for _, check := range ci.Checks {
		for _, prerequisite := range check.Prerequisites {
			hint, tracked := want[prerequisite.Name]
			if prerequisite.Kind != "tool" || !tracked {
				continue
			}
			seen[prerequisite.Name] = true
			missing := unavailablePrerequisites(
				[]Prerequisite{prerequisite},
				func(Prerequisite) prerequisiteState {
					return prerequisiteState{detail: "found 0.0.0, need " + prerequisite.Version}
				},
			)
			if len(missing) != 1 || !strings.Contains(missing[0], hint) {
				t.Errorf("%s prerequisite message %q does not contain %q", prerequisite.Name, missing, hint)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("ci manifest has no %s tool prerequisite to attach a hint to", name)
		}
	}

	if got := unavailablePrerequisites(
		[]Prerequisite{{Kind: "tool", Name: "jq", Version: "any"}},
		func(Prerequisite) prerequisiteState { return prerequisiteState{detail: "not found in PATH"} },
	); len(got) != 1 || strings.Contains(got[0], "GOTOOLCHAIN") || strings.Contains(got[0], "go install") {
		t.Errorf("unrelated tool message %q carries a Go acquisition hint", got)
	}
	if got := unavailablePrerequisites(
		[]Prerequisite{{Kind: "tool", Name: "go", Version: "1.26.8"}},
		func(Prerequisite) prerequisiteState { return prerequisiteState{available: true} },
	); len(got) != 0 {
		t.Errorf("available prerequisite reported as missing: %v", got)
	}
}

func TestRequirePinnedEnvironmentReachesVerificationChildren(t *testing.T) {
	values, err := isolatedEnvironmentForOS("/tmp/verify", "linux", func(name string) (string, bool) {
		switch name {
		case "PATH":
			return "/usr/bin", true
		case "SSM_VERIFY_REQUIRE_PINNED":
			return "1", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := environmentValue(values, "SSM_VERIFY_REQUIRE_PINNED"); got != "1" {
		t.Fatalf("SSM_VERIFY_REQUIRE_PINNED = %q, want 1 to reach go test children", got)
	}
	values, err = isolatedEnvironmentForOS("/tmp/verify", "linux", func(name string) (string, bool) {
		return "/usr/bin", name == "PATH"
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := environmentValue(values, "SSM_VERIFY_REQUIRE_PINNED"); present {
		t.Fatal("SSM_VERIFY_REQUIRE_PINNED is set in children although the parent did not set it")
	}
}

func TestCIWorkflowEnforcesPinnedHostAndOnlyTriggersOnDefaultBranch(t *testing.T) {
	text := readWorkflowFile(t, "ci.yml")
	for _, job := range []string{"check", "windows"} {
		block := workflowJobBlock(t, text, job)
		if !strings.Contains(block, "    env:\n      SSM_VERIFY_REQUIRE_PINNED: \"1\"\n") {
			t.Errorf("%s job does not set SSM_VERIFY_REQUIRE_PINNED=1", job)
		}
	}
	if got := strings.Count(text, "SSM_VERIFY_REQUIRE_PINNED"); got != 2 {
		t.Errorf("SSM_VERIFY_REQUIRE_PINNED appears %d times, want 2 (check and windows jobs)", got)
	}
	const triggers = "on:\n  workflow_dispatch:\n" +
		"  push:\n    branches: [agent-headless-sync]\n" +
		"  pull_request:\n    branches: [agent-headless-sync]\n"
	if !strings.Contains(text, triggers) {
		t.Errorf("ci.yml triggers are not exactly workflow_dispatch plus the default branch")
	}
	for _, stale := range []string{"dev", "main"} {
		if regexp.MustCompile(`(?m)^\s*branches:.*[\[\s,]` + stale + `[\],\s]`).MatchString(text) {
			t.Errorf("ci.yml still triggers on stale branch %q", stale)
		}
	}
}

func workflowJobBlock(t *testing.T, text, job string) string {
	t.Helper()
	start := strings.Index(text, "\n  "+job+":\n")
	if start < 0 {
		t.Fatalf("job %s not found", job)
	}
	rest := text[start+1:]
	end := len(rest)
	if next := regexp.MustCompile(`(?m)^  [a-z][a-z0-9_-]*:\n`).FindAllStringIndex(rest, -1); len(next) > 1 {
		end = next[1][0]
	}
	return rest[:end]
}

func TestVulnerabilityWorkflowMatchesReviewedGoldenAndManifest(t *testing.T) {
	text := readWorkflowFile(t, "vulncheck.yml")
	golden, err := os.ReadFile(filepath.Join("testdata", "vulncheck.yml"))
	if err != nil {
		t.Fatalf("read checked-in vulnerability workflow golden: %v", err)
	}
	if text != string(golden) {
		t.Fatal("vulnerability workflow differs from the reviewed complete golden")
	}

	for description, want := range map[string]string{
		"manual trigger":     "on:\n  workflow_dispatch:\n",
		"weekly schedule":    "  schedule:\n    - cron: \"17 3 * * 1\"\n",
		"top-level read":     "\npermissions:\n  contents: read\n",
		"job-level read":     "    permissions:\n      contents: read\n",
		"credential-free":    "          persist-credentials: false\n",
		"fixed go version":   "          go-version: \"" + pinnedGoVersion + "\"\n",
		"checkout version":   "      - uses: actions/checkout@v7\n",
		"setup-go version":   "      - uses: actions/setup-go@v6\n",
		"manifest command":   "        run: " + manifestVulnerabilityCommand(t) + "\n",
		"single job":         "jobs:\n  govulncheck:\n",
		"github runner host": "    runs-on: ubuntu-latest\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("vulnerability workflow lacks %s: %q", description, want)
		}
	}
	for _, forbidden := range []string{
		"issues: write", "contents: write", "pull-requests", "gh issue", "gh api",
		"push:", "pull_request", "secrets.", "id-token",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("vulnerability workflow contains forbidden %q (SECURITY.md forbids public issues; no write authority)", forbidden)
		}
	}

	ci := readWorkflowFile(t, "ci.yml")
	for _, use := range []string{"actions/checkout@v7", "actions/setup-go@v6"} {
		if !strings.Contains(ci, "uses: "+use) || !strings.Contains(text, "uses: "+use) {
			t.Errorf("ci.yml and vulncheck.yml do not both use %s", use)
		}
	}
	if !strings.Contains(ci, "go-version: \""+pinnedGoVersion+"\"") {
		t.Errorf("ci.yml does not use the manifest Go version %s", pinnedGoVersion)
	}
}

func manifestVulnerabilityCommand(t *testing.T) string {
	t.Helper()
	command := vulnerabilityCheck().Action.Command
	if command == nil {
		t.Fatal("vulnerability check has no command")
	}
	return strings.Join(append([]string{command.Executable}, command.Args...), " ")
}

func TestEveryRepositoryWorkflowIsReviewedWithAGolden(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", ".github", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	var workflows []string
	for _, entry := range entries {
		workflows = append(workflows, entry.Name())
	}
	sort.Strings(workflows)
	want := []string{"ci.yml", "release.yml", "vulncheck.yml"}
	if strings.Join(workflows, ",") != strings.Join(want, ",") {
		t.Fatalf("workflows = %v, want exactly the reviewed set %v; add a testdata golden and tests for any new workflow", workflows, want)
	}
	for _, name := range workflows {
		golden, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // name comes from the reviewed workflow directory listing under testdata
		if err != nil {
			t.Errorf("workflow %s has no reviewed golden: %v", name, err)
			continue
		}
		if readWorkflowFile(t, name) != string(golden) {
			t.Errorf("workflow %s differs from its reviewed golden", name)
		}
	}
}

func TestPinnedGoVersionMatchesGoModAndWorkflows(t *testing.T) {
	goMod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(goMod), "\ngo "+pinnedGoVersion+"\n") {
		t.Fatalf("go.mod does not declare the manifest Go version %s", pinnedGoVersion)
	}
	for _, name := range []string{"ci.yml", "release.yml", "vulncheck.yml"} {
		text := readWorkflowFile(t, name)
		if name != "vulncheck.yml" {
			want := "GOLANGCI_LINT_VERSION: \"" + pinnedGolangciLintVersion + "\"\n"
			if !strings.Contains(text, want) || strings.Count(text, "GOLANGCI_LINT_VERSION:") != 1 {
				t.Errorf("%s does not pin GOLANGCI_LINT_VERSION to the manifest value %s", name, pinnedGolangciLintVersion)
			}
		}
		if strings.Count(text, "go-version: \"") != strings.Count(text, "go-version: \""+pinnedGoVersion+"\"") {
			t.Errorf("%s has a setup-go version that is not the manifest pin %s", name, pinnedGoVersion)
		}
	}
}

func TestReleaseVerifierJobEnforcesPinnedHost(t *testing.T) {
	text := readWorkflowFile(t, "release.yml")
	if got := strings.Count(text, "SSM_VERIFY_REQUIRE_PINNED"); got != 1 {
		t.Fatalf("SSM_VERIFY_REQUIRE_PINNED appears %d times in release.yml, want 1", got)
	}
	block := workflowJobBlock(t, text, "preflight")
	if !strings.Contains(block, "    env:\n      SSM_VERIFY_REQUIRE_PINNED: \"1\"\n") ||
		!strings.Contains(block, "run: go run ./cmd/verify release\n") {
		t.Fatal("the release verifier job does not set SSM_VERIFY_REQUIRE_PINNED=1")
	}
}
