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
	executableNamePattern  = regexp.MustCompile(`(?i)\b(?:sshctl|ssm)(?:\.exe)?\b`)
	lineContinuation       = regexp.MustCompile(`\\\r?\n[ \t]*`)
	pushWordPattern        = regexp.MustCompile(`(?i)\bpush\b`)
	pushOnlyFlagPattern    = regexp.MustCompile("(?i)\\bpush\\b[ \t`'\"]+--only(?:\\b|=)")
	instructionalPushOnly  = regexp.MustCompile(`(?i)(?:\b(?:use|uses|using|run|runs|running|invoke|invokes|invoking|retry|retries|retrying|re-?run|publish|publishes|publishing|then)\b|用|使用|执行|运行|重试|发布).{0,160}$`)
	explicitScopeAfterPush = regexp.MustCompile(
		"(?i)^[ \t\r\n`'\"]*--(?:all\\b|only(?:\\b|=))",
	)
	negatedAdvicePrefix = regexp.MustCompile(
		`(?i)\b(?:do\s+not|don't|never|must\s+not|should\s+not|cannot|can't)\s*$`,
	)
	vaguePushAdvice = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:retry(?:ing)?|re-?run(?:ning)?|repeat(?:ing)?|try(?:ing)?)\b[^.;]{0,80}\bpush\b`),
		regexp.MustCompile(`(?i)\brun\b[^.;]{0,40}\bpush\b[^.;]{0,40}\bagain\b`),
		regexp.MustCompile(`(?i)\bpush\b[^.;]{0,30}\bagain\b`),
		regexp.MustCompile(`(?i)\bpull\b[^.;]{0,30}\bor\b[^.;]{0,30}\bpush\b`),
	}
	stalePushClaims = []*regexp.Regexp{
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
			for _, violation := range scanPushGuidanceSource(path, sources[path]) {
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
	return scanPushGuidanceSource("", document)
}

func scanPushGuidanceSource(path, document string) []pushGuidanceViolation {
	active, violations := activePushGuidance(path, document)
	violations = append(violations, scanVaguePushAdvice(active)...)
	violations = append(violations, scanPushOnlyValueSemantics(active)...)
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
			if pushInvocationHasInvalidScope(line[match[0]:]) {
				violations = append(violations, pushGuidanceViolation{
					line:    index + 1,
					reason:  "contains a push invocation without exactly one valid explicit scope",
					excerpt: compactExcerpt(line),
				})
			}
		}
	}
	return violations
}

func activePushGuidance(path, document string) (string, []pushGuidanceViolation) {
	if !isProductionGoSource(path) {
		return excludeHistoricalPushGuidance(document)
	}

	var violations []pushGuidanceViolation
	for _, marker := range []string{historicalBegin, historicalEnd} {
		offset := 0
		for {
			index := strings.Index(document[offset:], marker)
			if index < 0 {
				break
			}
			index += offset
			violations = append(violations, pushGuidanceViolation{
				line:    lineAt(document, index),
				reason:  "uses a historical exclusion marker in production Go",
				excerpt: marker,
			})
			offset = index + len(marker)
		}
	}
	return document, violations
}

func scanPushOnlyValueSemantics(document string) []pushGuidanceViolation {
	normalized := lineContinuation.ReplaceAllString(document, " ")
	var violations []pushGuidanceViolation
	for index, line := range strings.Split(normalized, "\n") {
		for _, match := range pushOnlyFlagPattern.FindAllStringIndex(line, -1) {
			executable := lineContainsExecutablePushInvocation(line, match[0])
			if !executable && !instructionalPushOnly.MatchString(line[:match[0]]) {
				continue
			}
			equalsForm := strings.HasSuffix(line[match[0]:match[1]], "=")
			value, valid := explicitPushOnlyValue(equalsForm, line[match[1]:])
			if !valid {
				violations = append(violations, pushGuidanceViolation{
					line:    index + 1,
					reason:  "uses --only without a non-empty transaction ID",
					excerpt: compactExcerpt(line[match[0]:]),
				})
				continue
			}
			if value != "<transaction-id>" &&
				(!executable || strings.HasPrefix(value, "<") || value == "transaction_id") {
				violations = append(violations, pushGuidanceViolation{
					line:    index + 1,
					reason:  "uses a non-canonical instructional transaction ID placeholder",
					excerpt: compactExcerpt(line[match[0]:]),
				})
			}
		}
	}
	return violations
}

func explicitPushOnlyValue(equalsForm bool, remainder string) (string, bool) {
	if equalsForm &&
		(remainder == "" || strings.ContainsRune(" \t\r\n", rune(remainder[0]))) {
		return "", false
	}
	remainder = strings.TrimLeft(remainder, " \t\r\n")
	if remainder == "" {
		return "", false
	}

	var value string
	if strings.ContainsRune("`'\"", rune(remainder[0])) {
		quote := remainder[0]
		end := strings.IndexByte(remainder[1:], quote)
		if end < 0 {
			return "", false
		}
		value = strings.TrimSpace(remainder[1 : end+1])
	} else {
		end := strings.IndexAny(remainder, " \t\r\n`'\",.;|&")
		if end < 0 {
			end = len(remainder)
		}
		value = normalizeCommandToken(remainder[:end])
	}
	if equalsForm {
		return value, value != ""
	}
	return value, value != "" && !strings.HasPrefix(value, "-")
}

func lineContainsExecutablePushInvocation(line string, pushStart int) bool {
	for _, match := range executableNamePattern.FindAllStringIndex(line[:pushStart], -1) {
		if commandNameAfterExecutable(line[match[0]:]) == "push" {
			return true
		}
	}
	return false
}

func scanVaguePushAdvice(document string) []pushGuidanceViolation {
	seenPushes := make(map[int]struct{})
	var violations []pushGuidanceViolation
	for _, pattern := range vaguePushAdvice {
		for _, match := range pattern.FindAllStringIndex(document, -1) {
			pushes := pushWordPattern.FindAllStringIndex(document[match[0]:match[1]], -1)
			if len(pushes) == 0 {
				continue
			}
			push := pushes[len(pushes)-1]
			pushStart := match[0] + push[0]
			pushEnd := match[0] + push[1]
			if _, seen := seenPushes[pushStart]; seen {
				continue
			}
			seenPushes[pushStart] = struct{}{}
			if negatesPushAdvice(document, match[0]) ||
				explicitScopeAfterPush.MatchString(document[pushEnd:]) {
				continue
			}
			violations = append(violations, pushGuidanceViolation{
				line:    lineAt(document, match[0]),
				reason:  "contains natural-language push guidance without an explicit scope",
				excerpt: compactExcerpt(document[match[0]:match[1]]),
			})
		}
	}
	return violations
}

func negatesPushAdvice(document string, adviceStart int) bool {
	const prefixLimit = 40
	prefixStart := adviceStart - prefixLimit
	if prefixStart < 0 {
		prefixStart = 0
	}
	return negatedAdvicePrefix.MatchString(document[prefixStart:adviceStart])
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

func pushInvocationHasInvalidScope(commandText string) bool {
	tokens := shellLikeTokens(commandText)
	commandIndex := commandIndexAfterExecutable(tokens)
	if commandIndex < 0 || normalizeCommandToken(tokens[commandIndex]) != "push" {
		return false
	}
	args := documentedPushArguments(tokens[commandIndex+1:])
	_, failure := parsePushScopeArguments(args)
	return failure != nil
}

func documentedPushArguments(tokens []string) []string {
	args := make([]string, 0, len(tokens))
	scopeComplete := false
	expectOnlyValue := false
	for _, raw := range tokens {
		token := normalizeCommandToken(raw)
		if token == "" {
			continue
		}
		if scopeComplete && !expectOnlyValue && !strings.HasPrefix(token, "-") {
			break
		}
		args = append(args, token)
		if expectOnlyValue {
			expectOnlyValue = false
			scopeComplete = true
			continue
		}
		switch {
		case token == "--only":
			expectOnlyValue = true
		case token == "--all", strings.HasPrefix(token, "--only="):
			scopeComplete = true
		case !strings.HasPrefix(token, "-"):
			return args
		}
	}
	return args
}

func commandIndexAfterExecutable(tokens []string) int {
	if len(tokens) < 2 || !isExecutableToken(tokens[0]) {
		return -1
	}
	for index := 1; index < len(tokens); index++ {
		token := normalizeCommandToken(tokens[index])
		if token == "" {
			continue
		}
		if _, ok := pushCommands[token]; ok {
			return index
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
		return -1
	}
	return -1
}

func commandNameAfterExecutable(commandText string) string {
	tokens := shellLikeTokens(commandText)
	commandIndex := commandIndexAfterExecutable(tokens)
	if commandIndex < 0 {
		return ""
	}
	return normalizeCommandToken(tokens[commandIndex])
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
			if !strings.HasSuffix(token.String(), "=") {
				flush()
				return tokens
			}
			quote := char
			index++
			for index < len(commandText) && commandText[index] != quote {
				token.WriteByte(commandText[index])
				index++
			}
			if index < len(commandText) {
				index++
			}
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
	return strings.ToLower(strings.Trim(token, " \t\r\n`'\"()[]{}:,.;：，。；"))
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

func isProductionGoSource(path string) bool {
	path = filepath.ToSlash(path)
	return (strings.HasPrefix(path, "cmd/") || strings.HasPrefix(path, "internal/")) &&
		strings.EqualFold(filepath.Ext(path), ".go") &&
		!strings.HasSuffix(path, "_test.go")
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
			name:      "vague retry push advice",
			document:  "Local changes remain pending; fix sync and retry push.",
			wantError: true,
		},
		{
			name:      "vague pull or push choice",
			document:  "Inspect the conflict, then explicitly pull or push after review.",
			wantError: true,
		},
		{
			name:      "vague run push again advice",
			document:  "After fixing connectivity, run `push` again.",
			wantError: true,
		},
		{
			name:      "bare push retry advice",
			document:  "Retry the bare push after fixing connectivity.",
			wantError: true,
		},
		{
			name: "explicit scopes with global flag forms",
			document: "sshctl --master-pass-file ./pass --json push --only tx_reviewed\n" +
				"ssm --master-pass-file=./pass --offline push --all\n",
		},
		{
			name:      "only requires a value",
			document:  "sshctl --json push --only\n",
			wantError: true,
		},
		{
			name:      "only equals requires a value",
			document:  "sshctl --json push --only=\n",
			wantError: true,
		},
		{
			name:      "only equals rejects a separate value",
			document:  "sshctl --json push --only= <transaction-id>\n",
			wantError: true,
		},
		{
			name:      "only rejects an empty quoted value",
			document:  "sshctl --json push --only \"\"\n",
			wantError: true,
		},
		{
			name:      "only rejects a whitespace quoted value",
			document:  "sshctl --json push --only '   '\n",
			wantError: true,
		},
		{
			name:      "only equals rejects an empty quoted value",
			document:  "sshctl --json push --only=\"\"\n",
			wantError: true,
		},
		{
			name:      "only equals rejects a whitespace quoted value",
			document:  "sshctl --json push --only='   '\n",
			wantError: true,
		},
		{
			name:      "only rejects another flag as its value",
			document:  "sshctl --json push --only --all\n",
			wantError: true,
		},
		{
			name:      "all then only is conflicting",
			document:  "sshctl --json push --all --only tx_reviewed\n",
			wantError: true,
		},
		{
			name:      "repeated only is invalid",
			document:  "sshctl --json push --only tx_first --only=tx_second\n",
			wantError: true,
		},
		{
			name:      "repeated all is invalid",
			document:  "sshctl --json push --all --all\n",
			wantError: true,
		},
		{
			name:      "unknown push flag is invalid",
			document:  "sshctl --json push --unknown\n",
			wantError: true,
		},
		{
			name:      "only rejects unknown option token as value",
			document:  "sshctl --json push --only --unknown\n",
			wantError: true,
		},
		{
			name:      "only equals all is conflicting",
			document:  "sshctl --json push --only=--all\n",
			wantError: true,
		},
		{
			name:      "only equals rejects unknown option token",
			document:  "sshctl --json push --only=--unknown\n",
			wantError: true,
		},
		{
			name:      "only equals rejects short option token",
			document:  "sshctl --json push --only=-x\n",
			wantError: true,
		},
		{
			name:      "only equals rejects known long option token",
			document:  "sshctl --json push --only=--json\n",
			wantError: true,
		},
		{
			name:      "only equals rejects known short option token",
			document:  "sshctl --json push --only=-v\n",
			wantError: true,
		},
		{
			name:      "instructional prose requires a value",
			document:  "Publish the returned transaction_id with push --only after review.\n",
			wantError: true,
		},
		{
			name:      "instructional prose rejects underscore placeholder",
			document:  "Publish with push --only <transaction_id> after review.\n",
			wantError: true,
		},
		{
			name:      "instructional prose rejects field name as placeholder",
			document:  "Publish with push --only transaction_id after review.\n",
			wantError: true,
		},
		{
			name: "only accepts canonical placeholder",
			document: "sshctl --json push --only <transaction-id>\n" +
				"sshctl --json push --only=<transaction-id>\n" +
				"Publish with push --only <transaction-id> after review.\n",
		},
		{
			name: "only accepts real ids and quoted non-empty values",
			document: "sshctl --json push --only tx_reviewed\n" +
				"sshctl --json push --only \"tx_reviewed_quoted\"\n" +
				"sshctl --json push --only='tx_reviewed_equals'\n" +
				"sshctl --json push --only=opaque:id/with=punctuation\n",
		},
		{
			name:     "all is an explicit scope",
			document: "sshctl --json push --all\n",
		},
		{
			name: "explicitly scoped prose guidance",
			document: "Retry push --only <transaction-id> after reviewing the transaction.\n" +
				"Pull or publish with push --all after reviewing every pending transaction.\n",
		},
		{
			name:     "bare push rejection is not advice",
			document: "Do not retry bare push; bare push is rejected before vault unlock.\n",
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
				"Fix sync and retry push.\n" +
				"Explicitly pull or push after review.\n" +
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

func TestProductionGoPushGuidanceCannotUseHistoricalExclusions(t *testing.T) {
	t.Parallel()

	document := "package fixture\n\n" +
		"const hint = `\n" + historicalBegin + "\n" +
		"retry with sshctl --json push\n" +
		historicalEnd + "\n`\n"
	violations := scanPushGuidanceSource("cmd/ssm/fixture.go", document)
	for _, violation := range violations {
		if violation.reason == "uses a historical exclusion marker in production Go" {
			return
		}
	}
	if len(violations) == 0 {
		t.Fatal("scanPushGuidanceSource() accepted a marker-wrapped unsafe production Go hint")
	}
	t.Fatal("scanPushGuidanceSource() did not reject the production Go historical marker")
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
		active, markerViolations := activePushGuidance(path, document)
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
