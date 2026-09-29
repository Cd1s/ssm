package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStdinForwardingRulesAreDocumented(t *testing.T) {
	required := []string{"--stdin", "--no-stdin", "--stdin-file", "SSM_FORWARD_STDIN", "stdin_forwarded"}
	for _, name := range []string{"README.md", "README.en.md", filepath.Join("skills", "agent-ssm", "SKILL.md")} {
		data, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // repository-owned documentation
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, fragment := range required {
			if !strings.Contains(text, fragment) {
				t.Errorf("%s does not document %s", name, fragment)
			}
		}
		if !strings.Contains(text, "while read") {
			t.Errorf("%s does not warn about stdin in while-read loops", name)
		}
	}
	for _, command := range []string{"run", "exec", "plan"} {
		out := captureHelpOutput(t, func() { runSSHCTL([]string{command, "--help"}) })
		for _, fragment := range append(required, "while read") {
			if !strings.Contains(out, fragment) {
				t.Errorf("%s help does not mention %s", command, fragment)
			}
		}
	}
}
