package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var (
	executablePushPattern = regexp.MustCompile(`(?i)\b(?:sshctl|ssm)\b(?:[ \t]+(?:--[a-z0-9-]+(?:=[^ \t]+)?|\[--[a-z0-9-]+\]))*[ \t]+push\b`)
	explicitPushScope     = regexp.MustCompile(`^--(?:all\b|only(?:\b|=))`)
	stalePushClaims       = []*regexp.Regexp{
		regexp.MustCompile("(?i)legacy[ \t]+bare[ \t`]*push"),
		regexp.MustCompile("(?i)bare[ \t`]*push[^\\n]{0,40}(?:compatib|alias|synonym|equivalent|same as|means)"),
		regexp.MustCompile("(?i)(?:compatib|alias|synonym|equivalent)[^\\n]{0,40}bare[ \t`]*push"),
		regexp.MustCompile("裸[ \t`]*push[^\\n]{0,40}(?:兼容|表示全部|等同|别名)"),
		regexp.MustCompile("(?:兼容|别名)[^\\n]{0,40}裸[ \t`]*push"),
	}
)

func TestActivePushGuidanceRequiresExplicitPublicationScope(t *testing.T) {
	t.Parallel()

	paths := []string{
		"README.en.md",
		"README.md",
		"skills/agent-ssm/SKILL.md",
		"skills/agent-ssm/README.md",
		"skills/agent-ssm/references/import-json.md",
		"skills/agent-ssm/test-prompts.json",
		"cmd/ssm/main.go",
		"cmd/ssm/help.go",
		"cmd/ssm/hosts.go",
		"internal/cloud/cloud.go",
		"internal/machinecontract/contract.go",
	}
	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			assertExplicitPushGuidance(t, path, readRepositoryFile(t, path))
		})
	}

	t.Run("RELEASE_NOTES.md current contract", func(t *testing.T) {
		t.Parallel()
		current, _, ok := strings.Cut(readRepositoryFile(t, "RELEASE_NOTES.md"), "\n## Historical v1 release notes")
		if !ok {
			t.Fatal("RELEASE_NOTES.md does not delimit historical v1 behavior")
		}
		assertExplicitPushGuidance(t, "RELEASE_NOTES.md (current contract)", current)
	})
}

func assertExplicitPushGuidance(t *testing.T, path, document string) {
	t.Helper()

	for index, line := range strings.Split(document, "\n") {
		for _, pattern := range stalePushClaims {
			if pattern.MatchString(line) {
				t.Errorf("%s:%d presents bare push as an alias or compatibility scope: %s", path, index+1, strings.TrimSpace(line))
				break
			}
		}
		for _, match := range executablePushPattern.FindAllStringIndex(line, -1) {
			tail := strings.TrimLeft(line[match[1]:], " \t`'\"()[]{}:;,.")
			if !explicitPushScope.MatchString(tail) {
				t.Errorf("%s:%d contains a push invocation without an explicit scope: %s", path, index+1, strings.TrimSpace(line))
			}
		}
	}
}

func readRepositoryFile(t *testing.T, path string) string {
	t.Helper()

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve documentation contract test source")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
