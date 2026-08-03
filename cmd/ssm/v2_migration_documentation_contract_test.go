package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	v2GuideBegin = "<!-- ssm-v2-migration: guide-begin -->"
	v2GuideEnd   = "<!-- ssm-v2-migration: guide-end -->"
	v2BCTable    = "<!-- ssm-v2-migration: bc-table columns=bc|old|new|affected|action|machine|rollback -->"
	v2ProvBegin  = "<!-- ssm-v2-provenance: runbook-begin -->"
	v2ProvEnd    = "<!-- ssm-v2-provenance: runbook-end -->"
)

var v2GuideSections = []string{
	"prerequisites", "backup-recovery-metadata", "automated-preflight",
	"manual-external-consumer-review", "staged-canary-rollout", "success-evidence",
	"failure-handling", "rollback", "troubleshooting", "stream-cardinality-refresh",
	"mutation-publication-reconciliation", "update-authorization-trust",
	"verification-profiles", "all-decisions", "release-blockers", "reviewer-mapping",
}

var v2ProvenanceSections = []string{
	"repository-pin", "workflow-pin", "issuer-pin", "digest-binding",
	"identity-rotation", "emergency-recovery", "old-executable-recovery-state",
	"verification-no-bypass",
}

type v2BCSpec struct {
	id             string
	anchors        []string
	machineAnchors []string
}

var v2BCSpecs = []v2BCSpec{
	{"BC-1", []string{"cloud.json", "sync_config_error", "--offline", "stage=sync_config", "exit=1"}, []string{"process exit=1", "cardinality=one JSON value or one terminal NDJSON record"}},
	{"BC-2", []string{"saved_key_create", "push --only", "transaction", "network"}, []string{"process exit=1", "cardinality=one JSON value"}},
	{"BC-3", []string{"NDJSON", "compact", "startup", "terminal"}, []string{"process exit=1", "cardinality=one terminal NDJSON record"}},
	{"BC-4", []string{"remove", "keys remove", "import-json", "transaction_id", "publish"}, []string{"process exit=0 on success", "cardinality=one JSON value"}},
	{"BC-5", []string{"bare", "invalid_arguments", "invocation-start", "no PUT", "sync_conflict"}, []string{"process exit=2 for bare", "process exit=1 for divergence", "cardinality=one JSON value"}},
	{"BC-6", []string{"--refresh=0", "positive", "--offline", "exit=2"}, []string{"process exit=2", "cardinality=one terminal NDJSON record"}},
	{"BC-7", []string{"direct", "request-v1", "direction", "kind", "stage", "bytes_sent", "bytes_received", "bytes_reused", "local_sha256", "remote_sha256", "omitted", "not_checked", "not_available", "atomic=false", "resume=unsupported"}, []string{"process exit=0 on success", "cardinality=one JSON value"}},
	{"BC-8", []string{"same-major", "update --major --yes", "review", "installed=false"}, []string{"process exit=0 on successful review/install", "cardinality=one JSON value"}},
	{"BC-9", []string{"checksums.txt", "provenance", "Cd1s/ssm", "release.yml", "14"}, []string{"process exit=1 on trust failure", "cardinality=one JSON value for updater machine mode"}},
	{"BC-10", []string{"gofmt -w", "verify ci", "verify release", "non-mutating", "preflight_passed"}, []string{"process exit=0 only on completed profile", "cardinality=not a JSON/NDJSON contract"}},
}

type v2BCReviewSpec struct {
	id       string
	evidence string
	fixture  string
}

var v2BCReviewSpecs = []v2BCReviewSpec{
	{"BC-1", "plans/issue-20-sync-transaction-ownership.md", "../cmd/ssm/compiled_cli_contract_test.go"},
	{"BC-2", "plans/issue-22-inventory-transaction-ownership.md", "../cmd/ssm/inventory_transaction_compiled_test.go"},
	{"BC-3", "plans/issue-21-stream-contract-migration.md", "../cmd/ssm/compiled_stream_contract_test.go"},
	{"BC-4", "plans/issue-24-legacy-mutation-ownership.md", "../cmd/ssm/legacy_mutation_compiled_test.go"},
	{"BC-5", "plans/issue-25-exact-push-scopes.md", "../cmd/ssm/push_scope_compiled_test.go"},
	{"BC-6", "plans/issue-21-stream-contract-migration.md", "../cmd/ssm/compiled_stream_contract_test.go"},
	{"BC-7", "plans/bc-7-transfer-outcome-migration.md", "../cmd/ssm/transfer_outcome_test.go"},
	{"BC-8", "plans/issue-27-major-update-migration.md", "../internal/update/update_test.go"},
	{"BC-9", "plans/issue-28-pinned-provenance.md", "../internal/update/update_test.go"},
	{"BC-10", "plans/verification-manifest.md", "../cmd/verify/main_test.go"},
}

var v2AdditionalChildEvidence = []struct {
	evidence string
	fixture  string
}{
	{"plans/issue-23-publication-intent.md", "../cmd/ssm/publication_intent_compiled_test.go"},
	{"plans/issue-29-three-module-contraction.md", "../cmd/ssm/deep_policy_ownership_test.go"},
}

func TestV2MigrationDocumentationContract(t *testing.T) {
	t.Run("parser rejects structural ambiguity", testV2DocumentationParserAdversarial)
	t.Run("stale claim scanner distinguishes historical text", testV2StaleClaimScannerAdversarial)
	t.Run("reviewer mapping rejects missing acceptance evidence", testV2ReviewerMappingAdversarial)

	root := repositoryRoot(t)
	guides := []string{"docs/migration-v1-to-v2.md", "docs/migration-v1-to-v2.zh-CN.md"}
	runbooks := []string{"docs/update-provenance-runbook.md", "docs/update-provenance-runbook.zh-CN.md"}

	guideMarkers := make([][]string, 0, len(guides))
	for _, name := range guides {
		body := readV2ContractFile(t, root, name)
		assertUniqueV2Marker(t, name, body, v2GuideBegin)
		assertUniqueV2Marker(t, name, body, v2GuideEnd)
		for _, section := range v2GuideSections {
			assertUniqueV2Marker(t, name, body, v2GuideSection(section))
		}
		for n := 1; n <= 14; n++ {
			marker := v2DecisionMarker(n)
			assertUniqueV2Marker(t, name, body, marker)
			assertMarkerHasBody(t, name, body, marker)
		}
		rows, err := parseV2BCTable(body, v2BCSpecs)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		assertV2BCSemantics(t, name, rows)
		assertV2SectionAnchors(t, name, body)
		assertV2ReviewerMapping(t, name, body)
		for _, stale := range staleV2Claims(v2GuideCurrentClaims(body, rows)) {
			t.Errorf("%s: stale current migration claim: %s", name, stale)
		}
		guideMarkers = append(guideMarkers, collectV2Markers(body, "<!-- ssm-v2-migration:"))
	}
	if got, want := strings.Join(guideMarkers[1], "\n"), strings.Join(guideMarkers[0], "\n"); got != want {
		t.Fatalf("English/Chinese migration marker order differs\nEN:\n%s\nZH:\n%s", want, got)
	}

	runbookMarkers := make([][]string, 0, len(runbooks))
	for _, name := range runbooks {
		body := readV2ContractFile(t, root, name)
		assertUniqueV2Marker(t, name, body, v2ProvBegin)
		assertUniqueV2Marker(t, name, body, v2ProvEnd)
		for _, section := range v2ProvenanceSections {
			marker := v2ProvenanceMarker(section)
			assertUniqueV2Marker(t, name, body, marker)
			assertMarkerHasBody(t, name, body, marker)
		}
		for _, anchor := range []string{
			"Cd1s/ssm", ".github/workflows/release.yml", "token.actions.githubusercontent.com",
			"checksums.txt", "release-tag-v1", "seven", "update_recovery_required",
			"gh attestation verify", "no verification bypass",
		} {
			assertContainsV2(t, name, body, anchor)
		}
		runbookMarkers = append(runbookMarkers, collectV2Markers(body, "<!-- ssm-v2-provenance:"))
	}
	if got, want := strings.Join(runbookMarkers[1], "\n"), strings.Join(runbookMarkers[0], "\n"); got != want {
		t.Fatalf("English/Chinese provenance marker order differs\nEN:\n%s\nZH:\n%s", want, got)
	}

	assertV2PublicSurfaces(t, root)
}

func parseV2BCTable(body string, specs []v2BCSpec) (map[string][]string, error) {
	if strings.Count(body, v2BCTable) != 1 {
		return nil, fmt.Errorf("BC table marker count = %d, want 1", strings.Count(body, v2BCTable))
	}
	tail := body[strings.Index(body, v2BCTable)+len(v2BCTable):]
	lines := strings.Split(tail, "\n")
	var table []string
	started := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "|") {
			started = true
			table = append(table, line)
			continue
		}
		if started && line != "" {
			break
		}
	}
	if len(table) != len(specs)+2 {
		return nil, fmt.Errorf("BC table has %d lines, want header, separator, and %d rows", len(table), len(specs))
	}
	if got := strings.ToLower(strings.Join(splitV2MarkdownRow(table[0]), "|")); got != "bc|old|new|affected|action|machine|rollback" {
		return nil, fmt.Errorf("BC header = %q", got)
	}
	for _, cell := range splitV2MarkdownRow(table[1]) {
		if strings.Trim(cell, " :-") != "" {
			return nil, fmt.Errorf("malformed BC separator row %q", table[1])
		}
	}
	want := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		want[spec.id] = struct{}{}
	}
	rows := make(map[string][]string, len(specs))
	for _, line := range table[2:] {
		cells := splitV2MarkdownRow(line)
		if len(cells) != 7 {
			return nil, fmt.Errorf("BC row has %d cells, want 7: %q", len(cells), line)
		}
		for n, cell := range cells {
			if strings.TrimSpace(cell) == "" {
				return nil, fmt.Errorf("BC row %q has empty cell %d", cells[0], n+1)
			}
		}
		id := strings.Trim(cells[0], "` ")
		if _, ok := want[id]; !ok {
			return nil, fmt.Errorf("unexpected BC identifier %q", id)
		}
		if _, duplicate := rows[id]; duplicate {
			return nil, fmt.Errorf("duplicate BC identifier %q", id)
		}
		rows[id] = cells
	}
	if len(rows) != len(specs) {
		return nil, fmt.Errorf("BC identifiers = %d, want %d", len(rows), len(specs))
	}
	return rows, nil
}

func splitV2MarkdownRow(line string) []string {
	line = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), "|"), "|"))
	parts := strings.Split(line, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func assertV2BCSemantics(t *testing.T, name string, rows map[string][]string) {
	t.Helper()
	for _, spec := range v2BCSpecs {
		joined := strings.Join(rows[spec.id], " ")
		for _, anchor := range spec.anchors {
			if !strings.Contains(strings.ToLower(joined), strings.ToLower(anchor)) {
				t.Errorf("%s: %s row missing semantic anchor %q", name, spec.id, anchor)
			}
		}
		machine := rows[spec.id][5]
		for _, anchor := range spec.machineAnchors {
			if !strings.Contains(strings.ToLower(machine), strings.ToLower(anchor)) {
				t.Errorf("%s: %s machine cell missing explicit contract %q", name, spec.id, anchor)
			}
		}
	}
}

func assertV2ReviewerMapping(t *testing.T, name, body string) {
	t.Helper()
	segment, err := v2MarkerBody(body, v2GuideSection("reviewer-mapping"))
	if err != nil {
		t.Errorf("%s: %v", name, err)
		return
	}
	for _, violation := range v2ReviewerMappingViolations(segment) {
		t.Errorf("%s: reviewer mapping %s", name, violation)
	}
}

func v2ReviewerMappingViolations(segment string) []string {
	var violations []string
	for _, spec := range v2BCReviewSpecs {
		linePrefix := "- [ ] " + spec.id + " "
		line := v2ChecklistLine(segment, linePrefix)
		if line == "" {
			violations = append(violations, "missing checklist item "+spec.id)
			continue
		}
		if !strings.Contains(line, "(#bc-contract-matrix)") {
			violations = append(violations, "missing BC matrix mapping "+spec.id)
		}
		if !strings.Contains(line, "]("+spec.evidence+")") {
			violations = append(violations, "missing linked evidence "+spec.evidence)
		}
		if !strings.Contains(line, "]("+spec.fixture+")") {
			violations = append(violations, "missing linked fixture source "+spec.fixture)
		}
	}
	for _, child := range v2AdditionalChildEvidence {
		if !strings.Contains(segment, "]("+child.evidence+")") {
			violations = append(violations, "missing linked evidence "+child.evidence)
		}
		if !strings.Contains(segment, "]("+child.fixture+")") {
			violations = append(violations, "missing linked fixture source "+child.fixture)
		}
	}
	for n := 1; n <= 14; n++ {
		id := fmt.Sprintf("D%02d", n)
		line := v2ChecklistLine(segment, "- [ ] "+id+" ")
		if line == "" || !strings.Contains(strings.ToLower(line), "(#"+strings.ToLower(id)+"-") {
			violations = append(violations, "missing decision checklist mapping "+id)
		}
	}
	for _, item := range []struct {
		label  string
		anchor string
	}{
		{"Release blockers", "#release-blockers|#发布阻断项"},
		{"Rollback guarantees", "#rollback|#回滚"},
	} {
		line := v2ChecklistLine(segment, "- [ ] "+item.label+" ")
		if line == "" || !v2ContainsAnySectionLink(line, strings.Split(item.anchor, "|")...) {
			violations = append(violations, "missing checklist mapping "+item.label)
		}
	}
	return violations
}

func v2ContainsAnySectionLink(line string, anchors ...string) bool {
	for _, anchor := range anchors {
		if strings.Contains(line, "("+anchor+")") {
			return true
		}
	}
	return false
}

func v2ChecklistLine(segment, prefix string) string {
	for _, line := range strings.Split(segment, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

func assertV2SectionAnchors(t *testing.T, name, body string) {
	t.Helper()
	anchors := map[string][]string{
		"prerequisites":                       {"Go 1.25.12", "jq", "golangci-lint 2.11.4"},
		"backup-recovery-metadata":            {"encrypted vault", "publishing-intent.json", "sync-conflict.json"},
		"automated-preflight":                 {"go run ./cmd/verify release", "cloud_configuration", "rollback_readiness"},
		"manual-external-consumer-review":     {"legacy_bare_push_consumers", "zero_refresh_online_streams", "directory_transfer_consumers"},
		"staged-canary-rollout":               {"canary", "--major", "--yes"},
		"success-evidence":                    {"preflight_passed", "transaction", "provenance"},
		"failure-handling":                    {"stop", "preserve", "evidence"},
		"rollback":                            {"v1", "pending", "reconcile"},
		"troubleshooting":                     {"sync_config_error", "sync_conflict", "update_recovery_required"},
		"stream-cardinality-refresh":          {"NDJSON", "non-empty", "--refresh", "--offline"},
		"mutation-publication-reconciliation": {"push --only", "push --all", "invocation-start", "reconcile", "changed=false", "action=unchanged", "transaction_id omitted", "do not publish"},
		"update-authorization-trust":          {"same-major", "update --major --yes", "provenance"},
		"verification-profiles":               {"make check", "verify ci", "verify release", "non-publishing"},
		"all-decisions":                       {"D01", "D14"},
		"release-blockers":                    {"v2-readiness-report", "all child tickets", "#31", "final readiness", "compiled public contract matrix", "six supported target combinations", "every mutation and push entry point", "no secrets", "does not", "publish"},
		"reviewer-mapping":                    {"BC-1", "BC-10", "D01", "D14"},
	}
	for section, required := range anchors {
		segment, err := v2MarkerBody(body, v2GuideSection(section))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, anchor := range required {
			if !strings.Contains(strings.ToLower(segment), strings.ToLower(anchor)) {
				t.Errorf("%s: section %s missing %q", name, section, anchor)
			}
		}
	}
}

func assertV2PublicSurfaces(t *testing.T, root string) {
	t.Helper()
	surfaces := map[string][]string{
		"README.en.md":               {"docs/migration-v1-to-v2.md", "docs/update-provenance-runbook.md", "--refresh", "update --major --yes", "changed:false", "action:\"unchanged\"", "transaction_id", "do not publish"},
		"README.md":                  {"docs/migration-v1-to-v2.zh-CN.md", "docs/update-provenance-runbook.zh-CN.md", "--refresh", "update --major --yes", "changed:false", "action:\"unchanged\"", "transaction_id", "do not publish"},
		"RELEASE_NOTES.md":           {"## v2.0.0", "BC-1", "BC-10", "v2-readiness-report", "all child tickets", "#31", "final readiness", "complete field-level", "changed:false", "action:\"unchanged\"", "does not publish"},
		"SECURITY.md":                {"docs/update-provenance-runbook.md", "identity rotation", "no verification bypass"},
		"skills/agent-ssm/SKILL.md":  {"docs/migration-v1-to-v2.md", "positive --refresh", "update --major --yes", "changed:false", "action:\"unchanged\"", "transaction_id", "do not publish"},
		"skills/agent-ssm/README.md": {"docs/migration-v1-to-v2.md", "positive --refresh", "update --major --yes", "changed:false", "action:\"unchanged\"", "transaction_id", "do not publish"},
		"skills/agent-ssm/references/import-json.md": {"publishing-intent.json", "reconcile", "pending", "changed:false", "action:\"unchanged\"", "transaction_id", "do not publish"},
		"cmd/ssm/help.go":                     {"positive", "--offline", "pending", "push --only", "direction", "kind"},
		"cmd/ssm/main.go":                     {"update within", "update --major", "--yes", "digest", "provenance", "never bypassed"},
		"docs/plans/verification-manifest.md": {"v2-readiness-report", "non-publishing", "initial_v2_release_readiness"},
	}
	for name, anchors := range surfaces {
		body := readV2ContractFile(t, root, name)
		active := body
		if name == "RELEASE_NOTES.md" {
			var violations []pushGuidanceViolation
			active, violations = excludeHistoricalPushGuidance(body)
			if len(violations) != 0 {
				t.Fatalf("%s: malformed historical markers: %+v", name, violations)
			}
		}
		for _, anchor := range anchors {
			assertContainsV2(t, name, active, anchor)
		}
		for _, stale := range staleV2Claims(active) {
			t.Errorf("%s: stale v2 claim: %s", name, stale)
		}
	}
}

func staleV2Claims(body string) []string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)bare\s+push.{0,60}(?:is|remains|means).{0,30}(?:push.?all|compatible|allowed)`),
		regexp.MustCompile(`(?i)(?:online|联网).{0,50}--refresh=0.{0,40}(?:allowed|accepted|supported|可)`),
		regexp.MustCompile(`(?i)(?:checksum|SHA-256).{0,50}(?:alone|only).{0,40}(?:authoriz|sufficient|足够|授权)`),
		regexp.MustCompile(`(?i)verify (?:ci|release)(?: profile)?\s+(?:creates? a tag|uploads?|publishes?|merges?)`),
	}
	var found []string
	for _, pattern := range patterns {
		for _, location := range pattern.FindAllStringIndex(body, -1) {
			end := min(len(body), location[1]+100)
			window := body[location[0]:end]
			if v2ClaimIsExplicitlySafe(window) {
				continue
			}
			found = append(found, compactExcerpt(body[location[0]:location[1]]))
		}
	}
	return found
}

func v2ClaimIsExplicitlySafe(window string) bool {
	safe := []*regexp.Regexp{
		regexp.MustCompile(`(?i)--refresh=0.{0,80}(?:only|仅).{0,40}--offline`),
		regexp.MustCompile(`(?i)(?:checksum|SHA-256).{0,60}(?:alone|only).{0,30}(?:never|does not|cannot)\s+authoriz`),
		regexp.MustCompile(`(?i)verify (?:ci|release).{0,40}(?:does not|never)\s+(?:create|upload|publish|merge)`),
	}
	for _, pattern := range safe {
		if pattern.MatchString(window) {
			return true
		}
	}
	return false
}

func v2GuideCurrentClaims(body string, rows map[string][]string) string {
	prefix := body
	if marker := strings.Index(prefix, v2BCTable); marker >= 0 {
		prefix = prefix[:marker]
	}
	var current strings.Builder
	current.WriteString(prefix)
	for _, spec := range v2BCSpecs {
		current.WriteString("\n")
		current.WriteString(strings.Join(rows[spec.id][2:], " "))
	}
	return current.String()
}

func testV2DocumentationParserAdversarial(t *testing.T) {
	marker := v2BCTable
	valid := marker + "\n| bc | old | new | affected | action | machine | rollback |\n| --- | --- | --- | --- | --- | --- | --- |\n| BC-X | old | new | users | act | fields | undo |\n"
	spec := []v2BCSpec{{id: "BC-X"}}
	if _, err := parseV2BCTable(valid, spec); err != nil {
		t.Fatalf("valid fixture: %v", err)
	}
	fixtures := map[string]string{
		"missing marker":   strings.Replace(valid, marker, "", 1),
		"duplicate marker": valid + marker,
		"duplicate row":    valid + "| BC-X | old | new | users | act | fields | undo |\n",
		"empty cell":       strings.Replace(valid, "| fields |", "| |", 1),
		"extra column":     strings.Replace(valid, "| rollback |", "| rollback | extra |", 1),
	}
	for name, body := range fixtures {
		if _, err := parseV2BCTable(body, spec); err == nil {
			t.Errorf("%s fixture was accepted", name)
		}
	}
}

func testV2StaleClaimScannerAdversarial(t *testing.T) {
	bad := []string{
		"Bare push remains a compatible push-all alias.",
		"Online --refresh=0 is supported.",
		"A checksum alone is sufficient to authorize replacement.",
		"verify release publishes artifacts.",
		"A checksum alone never fails to authorize replacement.",
	}
	for _, body := range bad {
		if got := staleV2Claims(body); len(got) == 0 {
			t.Errorf("stale scanner accepted %q", body)
		}
	}
	good := "Bare push is invalid. Online refresh must be positive. A checksum alone never authorizes replacement. verify release does not publish artifacts."
	if got := staleV2Claims(good); len(got) != 0 {
		t.Fatalf("stale scanner rejected current guidance: %v", got)
	}
	historical := "current guidance\n" + historicalBegin + "\nBare push remains a compatible push-all alias.\n" + historicalEnd
	active, violations := excludeHistoricalPushGuidance(historical)
	if len(violations) != 0 || len(staleV2Claims(active)) != 0 {
		t.Fatalf("historical exclusion failed: violations=%v stale=%v", violations, staleV2Claims(active))
	}
}

func testV2ReviewerMappingAdversarial(t *testing.T) {
	var valid strings.Builder
	for _, spec := range v2BCReviewSpecs {
		fmt.Fprintf(&valid, "- [ ] %s — [matrix](#bc-contract-matrix), [evidence](%s), [fixture](%s)\n", spec.id, spec.evidence, spec.fixture)
	}
	for _, child := range v2AdditionalChildEvidence {
		fmt.Fprintf(&valid, "[additional evidence](%s), [additional fixture](%s)\n", child.evidence, child.fixture)
	}
	for n := 1; n <= 14; n++ {
		fmt.Fprintf(&valid, "- [ ] D%02d — [decision](#d%02d-contract)\n", n, n)
	}
	valid.WriteString("- [ ] Release blockers — [section](#release-blockers)\n")
	valid.WriteString("- [ ] Rollback guarantees — [section](#rollback)\n")
	if got := v2ReviewerMappingViolations(valid.String()); len(got) != 0 {
		t.Fatalf("valid reviewer mapping rejected: %v", got)
	}
	fixtures := map[string]string{
		"unlinked child evidence":  strings.Replace(valid.String(), "](plans/issue-23-publication-intent.md)", "](`plans/issue-23-publication-intent.md`)", 1),
		"unlinked fixture source":  strings.Replace(valid.String(), "](../cmd/ssm/legacy_mutation_compiled_test.go)", "](`../cmd/ssm/legacy_mutation_compiled_test.go`)", 1),
		"missing BC checklist":     strings.Replace(valid.String(), "- [ ] BC-7 ", "BC-7 ", 1),
		"detached BC evidence":     strings.Replace(valid.String(), "[evidence](plans/issue-25-exact-push-scopes.md)", "evidence\n[detached](plans/issue-25-exact-push-scopes.md)", 1),
		"missing D checklist":      strings.Replace(valid.String(), "- [ ] D14 ", "D14 ", 1),
		"missing release mapping":  strings.Replace(valid.String(), "(#release-blockers)", "release-blockers", 1),
		"missing rollback mapping": strings.Replace(valid.String(), "- [ ] Rollback guarantees ", "Rollback guarantees ", 1),
	}
	for name, body := range fixtures {
		if got := v2ReviewerMappingViolations(body); len(got) == 0 {
			t.Errorf("%s fixture was accepted", name)
		}
	}
}

func v2GuideSection(id string) string { return "<!-- ssm-v2-migration: section=" + id + " -->" }

func v2DecisionMarker(n int) string {
	return fmt.Sprintf("<!-- ssm-v2-migration: decision=D%02d -->", n)
}

func v2ProvenanceMarker(id string) string { return "<!-- ssm-v2-provenance: " + id + " -->" }

func readV2ContractFile(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name))) //nolint:gosec // test-only path from fixed repository contract allowlists
	if err != nil {
		t.Fatalf("read required v2 contract surface %s: %v", name, err)
	}
	return string(data)
}

func assertUniqueV2Marker(t *testing.T, name, body, marker string) {
	t.Helper()
	if count := strings.Count(body, marker); count != 1 {
		t.Errorf("%s: marker %q count = %d, want 1", name, marker, count)
	}
}

func assertMarkerHasBody(t *testing.T, name, body, marker string) {
	t.Helper()
	segment, err := v2MarkerBody(body, marker)
	if err != nil {
		t.Errorf("%s: %v", name, err)
		return
	}
	if len(strings.Fields(segment)) < 8 {
		t.Errorf("%s: marker %q has no substantive body", name, marker)
	}
}

func v2MarkerBody(body, marker string) (string, error) {
	start := strings.Index(body, marker)
	if start < 0 {
		return "", fmt.Errorf("missing marker %q", marker)
	}
	start += len(marker)
	tail := body[start:]
	end := strings.Index(tail, "<!-- ssm-v2-")
	if end >= 0 {
		tail = tail[:end]
	}
	return strings.TrimSpace(tail), nil
}

func collectV2Markers(body, prefix string) []string {
	var markers []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, "-->") {
			markers = append(markers, line)
		}
	}
	return markers
}

func assertContainsV2(t *testing.T, name, body, anchor string) {
	t.Helper()
	if !strings.Contains(strings.ToLower(body), strings.ToLower(anchor)) {
		t.Errorf("%s: missing required v2 contract anchor %q", name, anchor)
	}
}
