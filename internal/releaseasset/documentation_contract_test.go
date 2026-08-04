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
		"candidate heading":             "## v1.4.4",
		"verbatim publication boundary": "exact-tag release workflow",
		"non-publishing candidate":      "non-publishing candidate gate",
		"bridge-first staging":          "bridge-first",
		"separate v2 decision":          "v2 cannot become GitHub latest",
		"legacy compatibility":          "legacy asset names",
		"provenance requirement":        "pinned keyless provenance",
	} {
		if !strings.Contains(notes, required) {
			t.Errorf("release notes lack %s %q", description, required)
		}
	}

	migration := readRepositoryFile(t, "docs/v1-to-v2-bridge.md")
	for description, required := range map[string]string{
		"BC-1 meaning":                 "BC-1 — invalid cloud configuration",
		"BC-2 meaning":                 "BC-2 — cross-alias saved-key dependencies",
		"BC-3 meaning":                 "BC-3 — stream startup NDJSON",
		"BC-4 meaning":                 "BC-4 — legacy mutations become pending",
		"BC-5 meaning":                 "BC-5 — bare and empty-ledger push",
		"BC-6 meaning":                 "BC-6 — positive online stream refresh",
		"BC-7 meaning":                 "BC-7 — directory transfer fields",
		"BC-8 meaning":                 "BC-8 — same-major ordinary update",
		"BC-9 meaning":                 "BC-9 — digest plus pinned provenance",
		"BC-10 meaning":                "BC-10 — non-mutating CI-equivalent checks",
		"exact workflow tag identity":  "Cd1s/ssm/.github/workflows/release.yml@refs/tags/",
		"GitHub Actions issuer":        "https://token.actions.githubusercontent.com",
		"explicit major authorization": "ssm update --major --yes",
	} {
		if !strings.Contains(migration, required) {
			t.Errorf("migration guide lacks %s %q", description, required)
		}
	}

	runbook := readRepositoryFile(t, "docs/update-provenance-runbook.md")
	for description, required := range map[string]string{
		"current identity":       "release-tag-v1",
		"overlap window":         "seven full days",
		"expiry/removal gate":    "NotAfter",
		"rollback":               "rollback",
		"audit evidence":         "audit evidence",
		"emergency recovery":     "Emergency release recovery",
		"no checksum fallback":   "checksum-only",
		"no verification bypass": "no verification bypass",
	} {
		if !strings.Contains(runbook, required) {
			t.Errorf("provenance runbook lacks %s %q", description, required)
		}
	}
}
