package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTimeoutDocumentationNamesEveryTimeout pins that the README (both
// languages) and the agent skill say what each timeout governs, the keepalive
// switch, and the exec_timeout exit code.
func TestTimeoutDocumentationNamesEveryTimeout(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, name := range []string{"README.md", "README.en.md", filepath.Join("skills", "agent-ssm", "SKILL.md")} {
		data, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // fixed repository documentation paths
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, want := range []string{
			"--connect-timeout", "--exec-timeout", "exec_timeout", "timed_out", "SSM_KEEPALIVE", "keepalive@openssh.com", "124",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not mention %q", name, want)
			}
		}
	}
	readme, _ := os.ReadFile(filepath.Join(root, "README.md")) //nolint:gosec // fixed repository documentation path
	if !strings.Contains(string(readme), "不是执行超时") {
		t.Error("README.md must say --timeout is a connect timeout, not an execution timeout")
	}
	if !strings.Contains(string(readme), "已弃用") {
		t.Error("README.md must mark the legacy --timeout alias deprecated")
	}
	english, _ := os.ReadFile(filepath.Join(root, "README.en.md"))                  //nolint:gosec // fixed repository documentation path
	skill, _ := os.ReadFile(filepath.Join(root, "skills", "agent-ssm", "SKILL.md")) //nolint:gosec // fixed repository documentation path
	for name, text := range map[string]string{"README.en.md": string(english), "SKILL.md": string(skill)} {
		if !strings.Contains(text, "not an execution timeout") {
			t.Errorf("%s must say --timeout is a connect timeout, not an execution timeout", name)
		}
	}
	if !strings.Contains(string(english), "deprecated") || !strings.Contains(string(skill), "Deprecated") {
		t.Error("README.en.md and SKILL.md must mark the legacy --timeout alias deprecated")
	}
}
