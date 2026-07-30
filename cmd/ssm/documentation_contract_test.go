package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const (
	historicalBegin = "<!-- documentation-contract: historical-begin -->"
	historicalEnd   = "<!-- documentation-contract: historical-end -->"
)

var (
	executableNamePattern = regexp.MustCompile(`(?i)\b(?:sshctl|ssm)(?:\.exe)?\b`)
	lineContinuation      = regexp.MustCompile(`\\\r?\n[ \t]*`)
	stalePushClaims       = []*regexp.Regexp{
		regexp.MustCompile("(?is)\\bbare[ \t\\r\\n`]+push\\b.{0,80}\\b(?:remain(?:s|ed)?|is|was|are|were|mean(?:s|t)?|act(?:s|ed)?|serve(?:s|d)?)\\b.{0,50}\\b(?:compatib[[:alnum:]_-]*|alias|synonym[[:alnum:]_-]*|equivalent)\\b"),
		regexp.MustCompile("(?is)\\b(?:retain(?:s|ed)?|preserve(?:s|d)?)\\b.{0,50}\\bbare[ \t\\r\\n`]+push\\b.{0,50}\\b(?:compatib[[:alnum:]_-]*|alias|synonym[[:alnum:]_-]*|equivalent)\\b"),
		regexp.MustCompile("(?s)裸[ \t\\r\\n`]*push.{0,80}(?:仍|是|作为|等同|表示).{0,40}(?:兼容|别名|同义|等价|全部)"),
		regexp.MustCompile("(?s)(?:保留|维持).{0,50}裸[ \t\\r\\n`]*push.{0,50}(?:兼容|别名|同义|等价)"),
	}
	pushCommands = map[string]struct{}{
		"alias-link": {}, "check": {}, "doctor": {}, "exec": {}, "get": {},
		"help": {}, "host": {}, "host-key": {}, "hosts": {}, "import-json": {},
		"keys": {}, "list": {}, "login": {}, "logout": {}, "ls": {}, "map": {},
		"plan": {}, "pull": {}, "pull-if-changed": {}, "push": {}, "redirect": {},
		"register": {}, "remote-hash": {}, "remove": {}, "request": {}, "run": {},
		"server": {}, "status": {}, "sync": {}, "update": {},
	}
	globalFlagsWithoutValues = map[string]struct{}{
		"--help": {}, "--json": {}, "--offline": {}, "--version": {},
		"-h": {}, "-v": {},
	}
	globalFlagsWithValues = map[string]struct{}{
		"--master-pass-file": {},
	}
)

func TestActivePushGuidanceRequiresExplicitPublicationScope(t *testing.T) {
	t.Parallel()

	sources, err := discoverPushContractSources(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(sources))
	for path := range sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			for _, violation := range scanPushGuidance(sources[path]) {
				t.Errorf("%s:%d %s: %s", path, violation.line, violation.reason, violation.excerpt)
			}
		})
	}
}

type pushGuidanceViolation struct {
	line    int
	reason  string
	excerpt string
}

func scanPushGuidance(document string) []pushGuidanceViolation {
	active, violations := excludeHistoricalPushGuidance(document)
	for _, pattern := range stalePushClaims {
		for _, match := range pattern.FindAllStringIndex(active, -1) {
			violations = append(violations, pushGuidanceViolation{
				line:    lineAt(active, match[0]),
				reason:  "presents bare push as an alias or compatibility scope",
				excerpt: compactExcerpt(active[match[0]:match[1]]),
			})
		}
	}

	normalized := lineContinuation.ReplaceAllString(active, " ")
	for index, line := range strings.Split(normalized, "\n") {
		for _, match := range executableNamePattern.FindAllStringIndex(line, -1) {
			if describesBareExecutableProse(line[:match[0]]) {
				continue
			}
			if pushInvocationLacksScope(line[match[0]:]) {
				violations = append(violations, pushGuidanceViolation{
					line:    index + 1,
					reason:  "contains a push invocation without an explicit scope",
					excerpt: compactExcerpt(line),
				})
			}
		}
	}
	return violations
}

func describesBareExecutableProse(prefix string) bool {
	fields := strings.Fields(strings.TrimRight(prefix, " \t`'\"()[]{}:,."))
	return len(fields) > 0 && strings.EqualFold(fields[len(fields)-1], "bare")
}

func excludeHistoricalPushGuidance(document string) (string, []pushGuidanceViolation) {
	var active strings.Builder
	historical := false
	beginLine := 0
	var violations []pushGuidanceViolation
	for index, line := range strings.SplitAfter(document, "\n") {
		lineNumber := index + 1
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\n"))
		switch trimmed {
		case historicalBegin:
			if historical {
				violations = append(violations, pushGuidanceViolation{
					line: lineNumber, reason: "contains a nested historical section", excerpt: historicalBegin,
				})
			}
			historical = true
			beginLine = lineNumber
			active.WriteString("\n")
		case historicalEnd:
			if !historical {
				violations = append(violations, pushGuidanceViolation{
					line: lineNumber, reason: "closes a historical section that was not open", excerpt: historicalEnd,
				})
			}
			historical = false
			active.WriteString("\n")
		default:
			if historical {
				if strings.HasSuffix(line, "\n") {
					active.WriteString("\n")
				}
				continue
			}
			active.WriteString(line)
		}
	}
	if historical {
		violations = append(violations, pushGuidanceViolation{
			line: beginLine, reason: "does not close its historical section", excerpt: historicalBegin,
		})
	}
	return active.String(), violations
}

func pushInvocationLacksScope(commandText string) bool {
	tokens := shellLikeTokens(commandText)
	if len(tokens) < 2 || !isExecutableToken(tokens[0]) {
		return false
	}
	for index := 1; index < len(tokens); index++ {
		token := normalizeCommandToken(tokens[index])
		if token == "" {
			continue
		}
		if _, ok := pushCommands[token]; ok {
			if token != "push" {
				return false
			}
			return !tokensContainExplicitPushScope(tokens[index+1:])
		}
		if _, ok := globalFlagsWithoutValues[token]; ok {
			continue
		}
		if _, ok := globalFlagsWithValues[token]; ok {
			if index+1 < len(tokens) {
				index++
			}
			continue
		}
		if strings.HasPrefix(token, "-") {
			if strings.Contains(token, "=") {
				continue
			}
			if index+1 < len(tokens) {
				next := normalizeCommandToken(tokens[index+1])
				if _, command := pushCommands[next]; !command && !strings.HasPrefix(next, "-") {
					index++
				}
			}
			continue
		}
		return false
	}
	return false
}

func tokensContainExplicitPushScope(tokens []string) bool {
	for _, raw := range tokens {
		token := normalizeCommandToken(raw)
		if token == "--all" || token == "--only" || strings.HasPrefix(token, "--only=") {
			return true
		}
	}
	return false
}

func shellLikeTokens(commandText string) []string {
	var tokens []string
	var token strings.Builder
	flush := func() {
		if token.Len() == 0 {
			return
		}
		tokens = append(tokens, token.String())
		token.Reset()
	}
	for index := 0; index < len(commandText); {
		char := commandText[index]
		switch {
		case char == ' ' || char == '\t' || char == '\r' || char == '\n':
			flush()
			index++
		case char == ';' || char == '|' || char == '&':
			flush()
			return tokens
		case char == '#' && token.Len() == 0:
			return tokens
		case (char == '\'' || char == '"' || char == '`') && token.Len() == 0:
			quote := char
			index++
			for index < len(commandText) && commandText[index] != quote {
				token.WriteByte(commandText[index])
				index++
			}
			if index < len(commandText) {
				index++
			}
			flush()
		case char == '\'' || char == '"' || char == '`':
			index++
		default:
			token.WriteByte(char)
			index++
		}
	}
	flush()
	return tokens
}

func isExecutableToken(token string) bool {
	token = strings.ToLower(normalizeCommandToken(token))
	token = strings.TrimSuffix(token, ".exe")
	return token == "ssm" || token == "sshctl"
}

func normalizeCommandToken(token string) string {
	return strings.ToLower(strings.Trim(token, " \t\r\n`'\"()[]{}:,.;"))
}

func compactExcerpt(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func lineAt(document string, offset int) int {
	return strings.Count(document[:offset], "\n") + 1
}

func discoverPushContractSources(root string) (map[string]string, error) {
	sources := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !isPushContractSource(relative) {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // test-only path returned by WalkDir under the repository root
		if err != nil {
			return fmt.Errorf("read active push contract source %s: %w", relative, err)
		}
		sources[relative] = string(data)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover active push contract sources: %w", err)
	}
	return sources, nil
}

func isPushContractSource(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	directory := filepath.ToSlash(filepath.Dir(path))
	// Contract coverage is category-based rather than a file allowlist:
	// all root/domain documentation, all documentation plans and ADRs, all
	// active skill artifacts, and every production Go string under cmd or
	// internal are scanned. Tests are fixtures, not public guidance.
	switch {
	case directory == "." && extension == ".md":
		return true
	case strings.HasPrefix(path, "docs/") && extension == ".md":
		return true
	case strings.HasPrefix(path, "skills/") && (extension == ".md" || extension == ".json"):
		return true
	case (strings.HasPrefix(path, "cmd/") || strings.HasPrefix(path, "internal/")) &&
		extension == ".go" && !strings.HasSuffix(path, "_test.go"):
		return true
	default:
		return false
	}
}

func TestPushGuidanceScannerAdversarialFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		document  string
		wantError bool
	}{
		{
			name: "multiline shell continuation",
			document: "```sh\n" +
				"sshctl --master-pass-file ./pass \\\n" +
				"  --json \\\n" +
				"  push\n" +
				"```\n",
			wantError: true,
		},
		{
			name:      "global flag separate value before push",
			document:  "Run `sshctl --master-pass-file ./pass push` after review.",
			wantError: true,
		},
		{
			name:      "global flag equals value before push",
			document:  "Run `ssm --master-pass-file=./pass push` after review.",
			wantError: true,
		},
		{
			name:      "quoted command",
			document:  `The executable recovery is "sshctl --offline --json push".`,
			wantError: true,
		},
		{
			name:      "machine executable hint",
			document:  `Hint: retry with ssm --offline --json push`,
			wantError: true,
		},
		{
			name:      "bare push alias claim",
			document:  "Bare `push` remains synonymous with `push --all`.",
			wantError: true,
		},
		{
			name: "explicit scopes with global flag forms",
			document: "sshctl --master-pass-file ./pass --json push --only tx_reviewed\n" +
				"ssm --master-pass-file=./pass --offline push --all\n",
		},
		{
			name: "multiline explicit scope",
			document: "```sh\n" +
				"sshctl --master-pass-file ./pass \\\n" +
				"  push \\\n" +
				"  --only tx_reviewed\n" +
				"```\n",
		},
		{
			name:     "push is a remote argv value",
			document: "sshctl run app --argv printf push\n",
		},
		{
			name:     "bare executable consumer is prose",
			document: "Review legacy callers that use bare ssm push; migrate each caller to an explicit scope.\n",
		},
		{
			name: "explicit historical section is excluded",
			document: "<!-- documentation-contract: historical-begin -->\n" +
				"Bare `push` remains an alias for `push --all`.\n" +
				"sshctl --json push\n" +
				"<!-- documentation-contract: historical-end -->\n" +
				"sshctl --json push --only tx_reviewed\n",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := len(scanPushGuidance(test.document)) > 0
			if got != test.wantError {
				t.Fatalf("scanPushGuidance() violation = %t, want %t", got, test.wantError)
			}
		})
	}
}

func TestPushContractSourceDiscoveryIncludesRequiredSurfaces(t *testing.T) {
	t.Parallel()

	sources, err := discoverPushContractSources(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"README.en.md",
		"README.md",
		"CONTEXT.md",
		"AGENTS.md",
		"RELEASE_NOTES.md",
		"docs/adr/0002-require-reviewed-inventory-publication.md",
		"cmd/ssm/main.go",
		"cmd/ssm/help.go",
		"cmd/ssm/sshctl.go",
		"cmd/ssm/hosts.go",
		"internal/cloud/cloud.go",
		"internal/machinecontract/contract.go",
		"internal/update/migration.go",
		"skills/agent-ssm/SKILL.md",
		"skills/agent-ssm/test-prompts.json",
		"skills/agent-ssm/references/import-json.md",
	} {
		if _, ok := sources[path]; !ok {
			t.Errorf("active push contract discovery omitted %s", path)
		}
	}
}

func TestReviewedRecoveryGuidanceUsesExactSafeHint(t *testing.T) {
	t.Parallel()

	sources, err := discoverPushContractSources(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	for path, document := range sources {
		active, markerViolations := excludeHistoricalPushGuidance(document)
		if len(markerViolations) != 0 {
			continue
		}
		if !strings.Contains(active, "sync_conflict") ||
			!strings.Contains(active, "import-json <reviewed-file>") {
			continue
		}
		matched++
		if !strings.Contains(active, emptyLedgerRecoveryHint) {
			t.Errorf("%s documents reviewed sync_conflict import recovery without the exact merge-only production hint", path)
		}
	}
	if matched < 5 {
		t.Fatalf("reviewed recovery discovery matched %d sources, want at least 5", matched)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve documentation contract test source")
	}
	return filepath.Join(filepath.Dir(source), "..", "..")
}
