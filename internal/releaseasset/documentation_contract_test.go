package releaseasset

import (
	"strings"
	"testing"
)

func TestBridgeDocumentationStatesMajorSafetyAndPublicationBoundary(t *testing.T) {
	for _, name := range []string{"README.md", "README.en.md"} {
		document := readRepositoryFile(t, name)
		for description, required := range map[string]string{
			"ordinary same-major boundary": "same-major",
			"explicit major review":        "ssm update --major",
			"explicit major authorization": "ssm update --major --yes",
		} {
			if !strings.Contains(document, required) {
				t.Errorf("%s lacks %s %q", name, description, required)
			}
		}
	}

	notes := readRepositoryFile(t, "RELEASE_NOTES.md")
	for description, required := range map[string]string{
		"candidate heading":      "## v1.4.4",
		"not published":          "not published",
		"bridge-first staging":   "bridge-first",
		"separate v2 decision":   "v2 cannot become GitHub latest",
		"legacy compatibility":   "legacy asset names",
		"provenance requirement": "pinned keyless provenance",
	} {
		if !strings.Contains(notes, required) {
			t.Errorf("release notes lack %s %q", description, required)
		}
	}

	migration := readRepositoryFile(t, "docs/v1-to-v2-bridge.md")
	for _, required := range []string{
		"BC-1", "BC-2", "BC-3", "BC-4", "BC-5", "BC-6", "BC-7", "BC-8", "BC-9", "BC-10",
		"Cd1s/ssm/.github/workflows/release.yml@refs/tags/",
		"https://token.actions.githubusercontent.com",
		"ssm update --major --yes",
	} {
		if !strings.Contains(migration, required) {
			t.Errorf("migration guide lacks %q", required)
		}
	}
}
