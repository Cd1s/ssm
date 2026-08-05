package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestCurrentV2BeginnerDocumentationContract(t *testing.T) {
	root := repositoryRoot(t)
	active := currentV2ActiveDocumentation(t, root)

	for _, name := range []string{"README.md", "README.en.md"} {
		document := active[name]
		for _, required := range []string{
			"https://github.com/Cd1s/ssm/releases/latest/download/install.sh",
			"v2.0.0",
			"latest",
		} {
			if !strings.Contains(strings.ToLower(document), strings.ToLower(required)) {
				t.Errorf("%s lacks fresh-install/latest fact %q", name, required)
			}
		}
		assertBeginnerFirstRunOrder(t, name, document)
	}

	for _, name := range []string{"skills/agent-ssm/SKILL.md", "skills/agent-ssm/README.md"} {
		document := active[name]
		for _, required := range []string{
			"v2.0.0 (current/latest)",
			"v1.4.3/v1.4.4",
			"v1 compatibility branch",
			"ssm update --major",
			"ssm update --major --yes",
			"releases/latest/download/install.sh",
		} {
			if !strings.Contains(strings.ToLower(document), strings.ToLower(required)) {
				t.Errorf("%s lacks current-version contract %q", name, required)
			}
		}
	}

	for name, document := range active {
		for _, claim := range staleCurrentV2DocumentationClaims(document) {
			t.Errorf("%s contains stale current-release claim %q", name, claim)
		}
	}
}

func currentV2ActiveDocumentation(t *testing.T, root string) map[string]string {
	t.Helper()
	paths := []string{
		"README.md",
		"README.en.md",
		"SECURITY.md",
		"docs/migration-v1-to-v2.md",
		"docs/migration-v1-to-v2.zh-CN.md",
		"docs/update-provenance-runbook.md",
		"docs/update-provenance-runbook.zh-CN.md",
		"skills/agent-ssm/SKILL.md",
		"skills/agent-ssm/README.md",
		"skills/agent-ssm/references/version-compatibility.md",
		"skills/agent-ssm/references/install-update.md",
	}
	documents := make(map[string]string, len(paths))
	for _, name := range paths {
		data, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // name is a fixed active-document contract path
		if err != nil {
			t.Fatalf("read active documentation %s: %v", name, err)
		}
		documents[name] = string(data)
	}
	return documents
}

func assertBeginnerFirstRunOrder(t *testing.T, name, document string) {
	t.Helper()
	anchors := []struct {
		label  string
		regexp *regexp.Regexp
	}{
		{"install", regexp.MustCompile(`https://github\.com/Cd1s/ssm/releases/latest/download/install\.sh`)},
		{"version", regexp.MustCompile(`sshctl --json --version`)},
		{"status", regexp.MustCompile(`sshctl --json status`)},
		{"host list", regexp.MustCompile(`sshctl --json host list`)},
		{"exact-alias hostname", regexp.MustCompile(`sshctl --json run [A-Za-z0-9._-]+ --argv hostname`)},
	}
	previous := -1
	for _, anchor := range anchors {
		match := anchor.regexp.FindStringIndex(document)
		if match == nil {
			t.Errorf("%s lacks beginner first-run step %q", name, anchor.label)
			continue
		}
		if match[0] <= previous {
			t.Errorf("%s first-run step %q is out of order", name, anchor.label)
		}
		previous = match[0]
	}
}

func staleCurrentV2DocumentationClaims(document string) []string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bv2\.0\.0\b.{0,120}\bnon[- ]latest\b`),
		regexp.MustCompile(`(?i)\bnon[- ]latest\b.{0,120}\bv2\.0\.0\b`),
		regexp.MustCompile(`(?i)\bstaged\s+v2(?:\.0\.0)?(?:\s+release)?\b`),
		regexp.MustCompile(`(?i)\bv2\.0\.0\b.{0,120}\bstaged\b`),
		regexp.MustCompile(`(?i)\bstaged\b.{0,120}\bv2\.0\.0\b`),
		regexp.MustCompile(`(?i)\bv1\.4\.4\b.{0,60}\b(?:remains|is|as|stays)\b.{0,40}\blatest\b`),
		regexp.MustCompile(`(?i)\b(?:default installer|default install)\b.{0,100}\bv1\.4\.4\b`),
		regexp.MustCompile(`(?i)默认安装.{0,100}v1\.4\.4`),
	}
	var claims []string
	for _, pattern := range patterns {
		claims = append(claims, pattern.FindAllString(document, -1)...)
	}
	return claims
}

func TestBundledAgentSkillProbesVersionBeforeChoosingMajorContract(t *testing.T) {
	root := repositoryRoot(t)
	skill := readAgentSkillContractFile(t, root, "SKILL.md")
	probe := "sshctl --json --version"
	if probeAt, firstOperationAt := strings.Index(skill, probe), strings.Index(skill, "sshctl --json status"); probeAt < 0 || firstOperationAt < 0 || probeAt > firstOperationAt {
		t.Fatalf("bundled skill must run %q before its first state-aware operation", probe)
	}
	for description, required := range map[string]string{
		"v1 bridge versions":        "v1.4.3 / v1.4.4",
		"v2 release version":        "v2.0.0",
		"unsupported-major stop":    "unsupported major",
		"fail-closed instruction":   "fail closed",
		"v1 compatibility branch":   "v1 compatibility branch",
		"v2 compatibility branch":   "v2 compatibility branch",
		"major migration review":    "ssm update --major",
		"major migration authority": "ssm update --major --yes",
		"schema stability":          "request schema version remains 1",
	} {
		if !strings.Contains(strings.ToLower(skill), strings.ToLower(required)) {
			t.Errorf("bundled skill lacks %s %q", description, required)
		}
	}

	compatibility := readAgentSkillContractFile(t, root, filepath.Join("references", "version-compatibility.md"))
	for _, required := range []string{
		"v1.4.3", "v1.4.4", "v2.0.0", "request-v1.schema.json", "op:get",
		"push --only", "push --all", "--refresh=0", "sync_config_error",
		"direction", "kind", "unsupported major",
	} {
		if !strings.Contains(strings.ToLower(compatibility), strings.ToLower(required)) {
			t.Errorf("version compatibility reference lacks %q", required)
		}
	}

	bridgeSchema := readAgentSkillContractFile(t, root, filepath.Join("references", "request-v1-bridge.schema.json"))
	v2Schema := readAgentSkillContractFile(t, root, filepath.Join("references", "request-v1.schema.json"))
	for name, schema := range map[string]string{"v1 bridge": bridgeSchema, "v2": v2Schema} {
		var parsed any
		if err := json.Unmarshal([]byte(schema), &parsed); err != nil {
			t.Errorf("%s request schema is not JSON: %v", name, err)
		}
	}
	if strings.Contains(bridgeSchema, `"get"`) {
		t.Error("v1 bridge schema incorrectly advertises v2 request op:get")
	}
	if !strings.Contains(v2Schema, `"get"`) {
		t.Error("v2 request schema omits request op:get")
	}

	bulkImport := readAgentSkillContractFile(t, root, filepath.Join("references", "import-json.md"))
	for _, required := range []string{
		"sshctl --json --version",
		"v1 compatibility branch",
		"v2 compatibility branch",
		"historical bare-push behavior",
		"invocation-start pending-ID set",
	} {
		if !strings.Contains(strings.ToLower(bulkImport), strings.ToLower(required)) {
			t.Errorf("bulk import reference lacks version-aware contract %q", required)
		}
	}
}

func TestLatestDocumentationContract(t *testing.T) {
	root := repositoryRoot(t)
	documents := []struct {
		name string
		path string
	}{
		{name: "README.md", path: "README.md"},
		{name: "README.en.md", path: "README.en.md"},
		{name: "agent skill", path: filepath.Join("skills", "agent-ssm", "SKILL.md")},
		{name: "agent skill README", path: filepath.Join("skills", "agent-ssm", "README.md")},
		{name: "version compatibility", path: filepath.Join("skills", "agent-ssm", "references", "version-compatibility.md")},
		{name: "install and update", path: filepath.Join("skills", "agent-ssm", "references", "install-update.md")},
		{name: "security", path: "SECURITY.md"},
		{name: "migration", path: filepath.Join("docs", "migration-v1-to-v2.md")},
		{name: "migration Chinese", path: filepath.Join("docs", "migration-v1-to-v2.zh-CN.md")},
		{name: "update provenance", path: filepath.Join("docs", "update-provenance-runbook.md")},
		{name: "update provenance Chinese", path: filepath.Join("docs", "update-provenance-runbook.zh-CN.md")},
	}
	contents := make(map[string]string, len(documents))
	for _, document := range documents {
		contents[document.name] = readLatestContractFile(t, root, document.path)
	}

	readmes := map[string][]string{
		"README.md": {
			"### 1. 安装",
			"### 2. 验证版本",
			"### 3. 查看状态",
			"### 4. 列出主机",
			"### 5. 对一个精确 alias 运行 hostname",
		},
		"README.en.md": {
			"### 1. Install",
			"### 2. Verify the version",
			"### 3. Check status",
			"### 4. List hosts",
			"### 5. Run hostname on one exact alias",
		},
	}
	for name, anchors := range readmes {
		assertLatestContractAnchorsInOrder(t, name, contents[name], anchors)
		body := strings.ToLower(contents[name])
		freshInstallAnchor := "fresh install"
		if name == "README.md" {
			freshInstallAnchor = "全新安装"
		}
		for _, required := range []string{
			"v2.0.0",
			"github",
			"latest",
			freshInstallAnchor,
			"releases/latest/download/install.sh",
		} {
			if !strings.Contains(body, required) {
				t.Errorf("%s lacks fresh-install/latest contract %q", name, required)
			}
		}
	}

	skill := strings.ToLower(contents["agent skill"])
	for _, required := range []string{
		"v2.0.0 (current/latest)",
		"v1.4.3/v1.4.4",
		"sshctl --json --version",
		"ordinary update remains in major 1",
		"ssm update --major --yes",
	} {
		if !strings.Contains(skill, strings.ToLower(required)) {
			t.Errorf("agent skill lacks latest compatibility contract %q", required)
		}
	}

	compatibility := strings.ToLower(contents["version compatibility"])
	for _, required := range []string{
		"v2.0.0 (current/latest)",
		"v1.4.3 / v1.4.4",
		"ordinary or automatic v1 update stays in major 1",
		"ssm update --major --yes",
	} {
		if !strings.Contains(compatibility, strings.ToLower(required)) {
			t.Errorf("version compatibility reference lacks %q", required)
		}
	}

	for _, document := range documents {
		body := strings.ToLower(contents[document.name])
		if !strings.Contains(body, "v2.0.0") {
			t.Errorf("%s does not identify v2.0.0 as the active contract", document.name)
		}
		for _, stale := range []string{
			"non-latest",
			"staged v2 release",
			"staged v2.0.0",
			"v2.0.0 is staged",
			"v2 release is staged",
			"v1.4.4 remains github latest",
			"v1.4.4 都保持为 github latest",
			"default installer follows github latest and therefore installs v1.4.4",
			"默认安装跟随 github latest，因此安装 v1.4.4",
		} {
			if strings.Contains(body, strings.ToLower(stale)) {
				t.Errorf("%s retains stale latest-state claim %q", document.name, stale)
			}
		}
	}
}

func readLatestContractFile(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // root and name are repository-owned test inputs
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertLatestContractAnchorsInOrder(t *testing.T, name, document string, anchors []string) {
	t.Helper()
	lower := strings.ToLower(document)
	offset := 0
	for _, anchor := range anchors {
		anchor = strings.ToLower(anchor)
		at := strings.Index(lower[offset:], anchor)
		if at < 0 {
			t.Errorf("%s lacks beginner-path anchor %q after byte %d", name, anchor, offset)
			return
		}
		offset += at + len(anchor)
	}
}

func TestBundledAgentSkillPromptsAlwaysProbeVersionFirst(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "skills", "agent-ssm", "test-prompts.json")) //nolint:gosec // repositoryRoot and the relative contract path are test-owned
	if err != nil {
		t.Fatal(err)
	}
	var prompts []struct {
		Name             string   `json:"name"`
		ExpectedBehavior []string `json:"expected_behavior"`
	}
	if err := json.Unmarshal(data, &prompts); err != nil {
		t.Fatal(err)
	}
	if len(prompts) < 10 {
		t.Fatalf("agent skill prompts = %d, want compatibility and deployment coverage", len(prompts))
	}
	seen := map[string]bool{}
	for _, prompt := range prompts {
		seen[prompt.Name] = true
		joined := strings.ToLower(strings.Join(prompt.ExpectedBehavior, "\n"))
		if !strings.Contains(joined, "sshctl --json --version") || !strings.Contains(joined, "first") {
			t.Errorf("prompt %q does not require the version probe first", prompt.Name)
		}
	}
	for _, name := range []string{"v1-compatibility-branch", "v2-compatibility-branch", "unsupported-major-fails-closed"} {
		if !seen[name] {
			t.Errorf("agent skill prompts omit %q", name)
		}
	}
}

func TestAgentSkillInstallInstructionsCoverExactTagCodexAndHermes(t *testing.T) {
	root := repositoryRoot(t)
	document := readAgentSkillContractFile(t, root, filepath.Join("references", "install-update.md"))
	for _, required := range []string{
		"v2.0.0", "exact tag", "CODEX_HOME", "HERMES_HOME", "Codex", "Hermes",
		"install-agent-ssm-skill.sh", "sshctl --json --version", "--replace",
	} {
		if !strings.Contains(strings.ToLower(document), strings.ToLower(required)) {
			t.Errorf("agent skill installation instructions lack %q", required)
		}
	}
}

func TestAgentSkillDeploymentUsesTemporaryCodexAndHermesRoots(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the reviewed deployment helper is a POSIX sh installer for Codex/Hermes hosts")
	}
	root := repositoryRoot(t)
	script := filepath.Join(root, "scripts", "install-agent-ssm-skill.sh")
	source := filepath.Join(root, "skills", "agent-ssm")
	tests := []struct {
		platform string
		version  string
	}{
		{platform: "codex", version: "1.4.4"},
		{platform: "hermes", version: "2.0.0"},
	}
	for _, test := range tests {
		t.Run(test.platform+"-"+test.version, func(t *testing.T) {
			installRoot := t.TempDir()
			binary := writeVersionProbeFixture(t, test.version)
			if test.platform == "codex" {
				link := filepath.Join(t.TempDir(), "sshctl")
				if err := os.Symlink(binary, link); err != nil {
					t.Fatal(err)
				}
				binary = link
			}
			command := exec.Command("sh", script, //nolint:gosec // all executable and argument paths are test-owned fixtures
				"--platform", test.platform,
				"--source", source,
				"--root", installRoot,
				"--sshctl", binary,
			)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("deploy bundled skill: %v\n%s", err, output)
			}
			destination := filepath.Join(installRoot, "skills", "agent-ssm")
			assertAgentSkillTreesEqual(t, source, destination)
		})
	}

	t.Run("unsupported-major", func(t *testing.T) {
		installRoot := t.TempDir()
		command := exec.Command("sh", script, //nolint:gosec // all executable and argument paths are test-owned fixtures
			"--platform", "codex",
			"--source", source,
			"--root", installRoot,
			"--sshctl", writeVersionProbeFixture(t, "3.0.0"),
		)
		if output, err := command.CombinedOutput(); err == nil {
			t.Fatalf("unsupported major deployed a skill:\n%s", output)
		}
		if _, err := os.Stat(filepath.Join(installRoot, "skills", "agent-ssm")); !os.IsNotExist(err) {
			t.Fatalf("unsupported major created destination: %v", err)
		}
	})

	t.Run("reviewed-update-preserves-prior-copy", func(t *testing.T) {
		installRoot := t.TempDir()
		destination := filepath.Join(installRoot, "skills", "agent-ssm")
		if err := os.MkdirAll(destination, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, "SKILL.md"), []byte("prior reviewed skill\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("sh", script, //nolint:gosec // all executable and argument paths are test-owned fixtures
			"--platform", "codex",
			"--source", source,
			"--root", installRoot,
			"--sshctl", writeVersionProbeFixture(t, "2.0.0"),
			"--replace",
		)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("update bundled skill: %v\n%s", err, output)
		}
		assertAgentSkillTreesEqual(t, source, destination)
		backups, err := filepath.Glob(filepath.Join(installRoot, "skills", ".agent-ssm.backup.*", "agent-ssm", "SKILL.md"))
		if err != nil {
			t.Fatal(err)
		}
		if len(backups) != 1 {
			t.Fatalf("preserved skill backups = %v, want exactly one", backups)
		}
		data, err := os.ReadFile(backups[0])
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "prior reviewed skill\n" {
			t.Fatalf("preserved prior skill = %q", data)
		}
	})
}

func readAgentSkillContractFile(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "skills", "agent-ssm", name)) //nolint:gosec // root and name are repository-owned test inputs
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeVersionProbeFixture(t *testing.T, version string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshctl")
	body := "#!/bin/sh\n" +
		"test \"$1\" = --json\n" +
		"test \"$2\" = --version\n" +
		"test \"$#\" = 2\n" +
		"printf '%s\\n' '{\"ok\":true,\"version\":\"" + version + "\"}'\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil { //nolint:gosec // the fixture must be executable
		t.Fatal(err)
	}
	return path
}

func assertAgentSkillTreesEqual(t *testing.T, source, destination string) {
	t.Helper()
	readTree := func(root string) map[string]string {
		files := map[string]string{}
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path) //nolint:gosec // WalkDir yields a path beneath the test-owned source or destination
			if err != nil {
				return err
			}
			files[filepath.ToSlash(relative)] = string(data)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	want, got := readTree(source), readTree(destination)
	wantNames, gotNames := make([]string, 0, len(want)), make([]string, 0, len(got))
	for name := range want {
		wantNames = append(wantNames, name)
	}
	for name := range got {
		gotNames = append(gotNames, name)
	}
	sort.Strings(wantNames)
	sort.Strings(gotNames)
	if strings.Join(gotNames, "\n") != strings.Join(wantNames, "\n") {
		t.Fatalf("deployed skill files = %v, want %v", gotNames, wantNames)
	}
	for name, wantBody := range want {
		if got[name] != wantBody {
			t.Errorf("deployed skill file %s differs from bundle", name)
		}
	}
}
