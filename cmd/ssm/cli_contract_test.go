package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file is the public-contract check for issue #83: the flags the parsers
// accept and the SSM_* environment variables the code reads must be documented
// (help output, README zh and en, the agent skill), and everything the
// documents name must exist in the implementation.
//
// The rule is deliberately mechanical so it stays cheap to maintain:
//
//   - accepted flags are every "--long-flag" string literal in the non-test
//     source of cmd/ssm, every flag registered on a flag.FlagSet, and the
//     run/exec/plan/map option tables in runargs.go;
//   - environment variables are every exact "SSM_*" string literal in the
//     non-test source under cmd/ and internal/;
//   - each accepted flag and variable must be mentioned (word-bounded, anywhere
//     in the document; this is not a per-section check and short flags such as
//     -j are covered only through the run option tables' help check) in
//     README.md, README.en.md, and skills/agent-ssm/SKILL.md, and, unless it is a
//     flag.FlagSet flag whose help the flag package generates, in the help
//     output of some command (environment variables: in `sshctl --help`);
//   - every "--flag" and "SSM_*" token in those documents and in help output
//     must be accepted or read by the code (there is no allowlist for the
//     reverse direction: an external tool's flag belongs in prose, not as a
//     bare --flag token).
//
// Adding a flag or variable without documenting it fails this test. An entry
// in one of the allowlists below needs a reason; an entry that no longer
// matches anything fails too, so the lists cannot rot.

// flagsWithoutDocumentation are string literals that look like flags but need
// no user documentation. Each entry states why.
var flagsWithoutDocumentation = map[string]string{
	"--background":  "internal: re-execution marker of the detached background sync child, never typed by users",
	"--direct":      "recognized only to reject: cp --direct is deliberately not implemented (its rejection is documented under cp)",
	"--fetch":       "recognized only to suggest 'get' for a mistyped run option, never accepted",
	"--script-file": "recognized only to suggest '-f' for a mistyped run option, never accepted",
	"--help":        "universal; every command answers -h/--help and the docs do not repeat it per command",
}

// internalEnv are SSM_* literals that are not user-facing environment
// variables. Prefix entries end in "_" and match every name that starts with
// them.
var internalEnv = map[string]string{
	"SSM_SYNC_CLAIM":             "internal: claim handed to the detached background sync child (backgroundClaimEnv)",
	"SSM_RESUME":                 "remote-side marker printed by the resume shell script, not read from the environment",
	"SSM_TRANSFER":               "remote-side marker printed by the transfer shell script, not read from the environment",
	"SSM_INTEGRITY_MISMATCH":     "remote-side marker printed by the transfer shell script, not read from the environment",
	"SSM_INTEGRITY_TOOL_MISSING": "remote-side marker printed by the transfer shell script, not read from the environment",
	"SSM_TEST_":                  "test-only fault and helper hooks compiled into production files",
	"SSM_COMPILED_TEST_":         "test-only hooks used by the compiled-CLI harness",
}

// developerEnv are variables of the repository's own tooling (cmd/verify), not
// of the ssm/sshctl binaries. They are documented in the README development
// section only.
var developerEnv = map[string]string{
	"SSM_VERIFY_REQUIRE_PINNED": "cmd/verify readiness switch, documented in the README development section",
}

var (
	flagLiteralPattern    = regexp.MustCompile(`^--[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
	envLiteralPattern     = regexp.MustCompile(`^SSM_[A-Z0-9_]+$`)
	flagTokenPattern      = regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(--[a-z][a-z0-9]*(?:-[a-z0-9]+)*)`)
	sourceEnvTokenPattern = regexp.MustCompile(`SSM_[A-Z0-9_]*[A-Z0-9_]`)
	envTokenPattern       = regexp.MustCompile(`SSM_[A-Z][A-Z0-9_]*[A-Z0-9]`)
)

// flagPackageMethods are the flag.FlagSet registration methods whose name
// argument is the flag name. Var-style methods take the name second or third,
// so the scanner uses the first string literal argument.
var flagPackageMethods = map[string]bool{
	"String": true, "StringVar": true, "Bool": true, "BoolVar": true, "Int": true, "IntVar": true,
	"Int64": true, "Int64Var": true, "Uint": true, "UintVar": true, "Uint64": true, "Uint64Var": true,
	"Float64": true, "Float64Var": true, "Duration": true, "DurationVar": true,
	"Func": true, "BoolFunc": true, "Var": true, "TextVar": true,
}

var contractDocuments = []string{"README.md", "README.en.md", filepath.Join("skills", "agent-ssm", "SKILL.md")}

func mentionsToken(text, token string) bool {
	pattern := regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(token) + `(?:$|[^A-Za-z0-9_-])`)
	return pattern.MatchString(text)
}

func readContractDocument(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), name)) //nolint:gosec // fixed repository documentation paths
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// productionGoFiles lists the non-test Go sources under the given repository
// directories.
func productionGoFiles(t *testing.T, dirs ...string) []string {
	t.Helper()
	var files []string
	for _, dir := range dirs {
		root := filepath.Join(repositoryRoot(t), dir)
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(files)
	return files
}

func stringLiterals(t *testing.T, files []string, visit func(value string, call *ast.CallExpr)) {
	t.Helper()
	fileSet := token.NewFileSet()
	for _, path := range files {
		parsed, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.BasicLit:
				if typed.Kind == token.STRING {
					if value, err := strconv.Unquote(typed.Value); err == nil {
						visit(value, nil)
					}
				}
			case *ast.CallExpr:
				visit("", typed)
			}
			return true
		})
	}
}

// acceptedFlags returns every long flag the CLI accepts (or deliberately
// recognizes) and the subset registered on flag.FlagSet values, whose help the
// flag package generates.
func acceptedFlags(t *testing.T) (all, flagPackage map[string]bool) {
	t.Helper()
	all = map[string]bool{}
	flagPackage = map[string]bool{}
	stringLiterals(t, productionGoFiles(t, filepath.Join("cmd", "ssm")), func(value string, call *ast.CallExpr) {
		if call == nil {
			if name, ok := flagFromLiteral(value); ok {
				all[name] = true
			}
			return
		}
		if name, ok := flagPackageName(call); ok {
			all["--"+name] = true
			flagPackage["--"+name] = true
		}
	})
	for _, option := range append(append([]string{}, runValueOptions...), runFlagOptions...) {
		if strings.HasPrefix(option, "--") {
			all[option] = true
		}
	}
	return all, flagPackage
}

// flagFromLiteral accepts "--flag" and the "--flag=" prefix form used with
// strings.HasPrefix, returning the bare flag name.
func flagFromLiteral(value string) (string, bool) {
	value = strings.TrimSuffix(value, "=")
	if flagLiteralPattern.MatchString(value) {
		return value, true
	}
	return "", false
}

func TestContractFlagScannerHandlesEqualsFormsAndRegistrations(t *testing.T) {
	for literal, want := range map[string]string{"--x": "--x", "--x-y=": "--x-y", "--X": "", "-x": "", "--": "", "plain": ""} {
		if got, _ := flagFromLiteral(literal); got != want {
			t.Errorf("flagFromLiteral(%q) = %q, want %q", literal, got, want)
		}
	}
	file := filepath.Join(t.TempDir(), "sample.go")
	source := "package p\nimport \"flag\"\nfunc f(fs *flag.FlagSet) {\n" +
		"var b bool\nfs.Func(\"fn\", \"u\", nil)\nfs.BoolFunc(\"bf\", \"u\", nil)\nfs.Uint(\"u\", 0, \"u\")\nfs.Var(nil, \"v\", \"u\")\nfs.BoolVar(&b, \"bv\", false, \"u\")\n_ = \"--only=\"\n}\n"
	if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	stringLiterals(t, []string{file}, func(value string, call *ast.CallExpr) {
		if call == nil {
			if name, ok := flagFromLiteral(value); ok {
				found[name] = true
			}
			return
		}
		if name, ok := flagPackageName(call); ok {
			found["--"+name] = true
		}
	})
	for _, want := range []string{"--fn", "--bf", "--u", "--v", "--bv", "--only"} {
		if !found[want] {
			t.Errorf("scanner missed %s (found %v)", want, found)
		}
	}
}

// flagPackageName returns the flag name registered by a flag.FlagSet method
// call: the first string literal argument.
func flagPackageName(call *ast.CallExpr) (string, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !flagPackageMethods[selector.Sel.Name] {
		return "", false
	}
	for _, argument := range call.Args {
		literal, ok := argument.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			continue
		}
		name, err := strconv.Unquote(literal.Value)
		if err == nil && flagLiteralPattern.MatchString("--"+name) {
			return name, true
		}
		return "", false
	}
	return "", false
}

func isInternalEnv(name string) bool {
	if _, ok := internalEnv[name]; ok {
		return true
	}
	for prefix := range internalEnv {
		if strings.HasSuffix(prefix, "_") && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// readEnvNames returns every exact SSM_* literal in the non-test source.
func readEnvNames(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	stringLiterals(t, productionGoFiles(t, "cmd", "internal"), func(value string, call *ast.CallExpr) {
		if call == nil && envLiteralPattern.MatchString(value) {
			names[value] = true
		}
	})
	return names
}

// helpCorpus captures the help text of the sshctl and ssm entrypoints keyed by
// a readable name. login, register, and server print flag.FlagSet help and are
// covered through the flag package instead.
func helpCorpus(t *testing.T) map[string]string {
	t.Helper()
	corpus := map[string]string{"sshctl --help": captureHelpOutput(t, sshctlUsage)}
	for _, command := range sortedCommandNames(sshctlCommands) {
		if isHelpToken(command) {
			continue
		}
		corpus["sshctl help "+command] = captureHelpOutput(t, func() { sshctlCommandUsage(command, nil) })
	}
	for _, command := range sortedCommandNames(ssmCommands) {
		switch command {
		case "login", "register", "server":
			continue
		}
		if isHelpToken(command) {
			continue
		}
		corpus["ssm help "+command] = captureHelpOutput(t, func() { ssmCommandUsage(command, nil) })
	}
	return corpus
}

func isHelpToken(command string) bool {
	for _, token := range helpTokens {
		if command == token {
			return true
		}
	}
	return false
}

func joinedHelp(corpus map[string]string) string {
	keys := make([]string, 0, len(corpus))
	for key := range corpus {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(corpus[key])
		builder.WriteByte('\n')
	}
	return builder.String()
}

func TestContractHelpHasNoTabsOrDuplicateLines(t *testing.T) {
	for name, output := range helpCorpus(t) {
		if strings.TrimSpace(output) == "" {
			t.Errorf("%s printed nothing", name)
			continue
		}
		if strings.ContainsRune(output, '\t') {
			t.Errorf("%s contains a tab: %q", name, output)
		}
		seen := map[string]int{}
		for _, line := range strings.Split(output, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			seen[trimmed]++
		}
		for line, count := range seen {
			if count > 1 {
				t.Errorf("%s repeats a line %d times: %q", name, count, line)
			}
		}
	}
}

func TestContractRunHelpListsEveryRunOption(t *testing.T) {
	options := append(append([]string{}, runValueOptions...), runFlagOptions...)
	for _, command := range []string{"run", "exec", "plan"} {
		output := captureHelpOutput(t, func() { sshctlCommandUsage(command, nil) })
		for _, option := range options {
			if option == "-h" || option == "--help" {
				continue
			}
			if !mentionsToken(output, option) {
				t.Errorf("%s --help does not mention %s", command, option)
			}
		}
	}
}

func TestContractAcceptedFlagsAreDocumented(t *testing.T) {
	flags, flagPackage := acceptedFlags(t)
	help := joinedHelp(helpCorpus(t))
	documents := map[string]string{}
	for _, name := range contractDocuments {
		documents[name] = readContractDocument(t, name)
	}
	for flag := range flagsWithoutDocumentation {
		if !flags[flag] {
			t.Errorf("flagsWithoutDocumentation lists %s, which the code no longer contains", flag)
		}
	}
	for _, flag := range sortedNameSet(flags) {
		if _, exempt := flagsWithoutDocumentation[flag]; exempt {
			continue
		}
		if !flagPackage[flag] && !mentionsToken(help, flag) {
			t.Errorf("accepted flag %s is not mentioned in any help output", flag)
		}
		for _, name := range contractDocuments {
			if !mentionsToken(documents[name], flag) {
				t.Errorf("accepted flag %s is not documented in %s", flag, name)
			}
		}
	}
}

func TestContractDocumentedFlagsAreAccepted(t *testing.T) {
	flags, _ := acceptedFlags(t)
	sources := map[string]string{"help output": joinedHelp(helpCorpus(t))}
	for _, name := range contractDocuments {
		sources[name] = readContractDocument(t, name)
	}
	for name, text := range sources {
		for _, match := range flagTokenPattern.FindAllStringSubmatch(text, -1) {
			flag := match[1]
			if flags[flag] {
				continue
			}
			t.Errorf("%s names %s, which no command accepts", name, flag)
		}
	}
}

func TestContractEnvironmentVariablesAreDocumented(t *testing.T) {
	names := readEnvNames(t)
	help := captureHelpOutput(t, sshctlUsage)
	documents := map[string]string{}
	for _, name := range contractDocuments {
		documents[name] = readContractDocument(t, name)
	}
	tokens := sourceEnvTokens(t)
	for name := range internalEnv {
		// Marker names live inside larger literals, so staleness is checked
		// against whole SSM_* tokens in the source: SSM_RESUME is not kept
		// alive by SSM_RESUME_ERROR, and a prefix entry needs one match.
		if strings.HasSuffix(name, "_") {
			matched := false
			for token := range tokens {
				if strings.HasPrefix(token, name) {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("internalEnv prefix %s matches nothing in the code", name)
			}
		} else if !tokens[name] {
			t.Errorf("internalEnv lists %s, which the code no longer contains", name)
		}
	}
	for name := range developerEnv {
		if !names[name] {
			t.Errorf("developerEnv lists %s, which the code no longer contains", name)
		}
	}
	for _, name := range sortedNameSet(names) {
		if isInternalEnv(name) {
			continue
		}
		if _, developer := developerEnv[name]; developer {
			for _, doc := range []string{"README.md", "README.en.md"} {
				if !mentionsToken(documents[doc], name) {
					t.Errorf("developer variable %s is not documented in %s", name, doc)
				}
			}
			continue
		}
		if !mentionsToken(help, name) {
			t.Errorf("environment variable %s is read by the code but not listed in `sshctl --help`", name)
		}
		for _, doc := range contractDocuments {
			if !mentionsToken(documents[doc], name) {
				t.Errorf("environment variable %s is read by the code but not documented in %s", name, doc)
			}
		}
	}
}

func TestContractDocumentedEnvironmentVariablesAreRead(t *testing.T) {
	names := readEnvNames(t)
	sources := map[string]string{"help output": joinedHelp(helpCorpus(t))}
	for _, name := range contractDocuments {
		sources[name] = readContractDocument(t, name)
	}
	for source, text := range sources {
		for _, name := range envTokenPattern.FindAllString(text, -1) {
			if names[name] || isInternalEnv(name) {
				continue
			}
			t.Errorf("%s names %s, which the code never reads", source, name)
		}
	}
}

// sourceEnvTokens returns every whole SSM_* token that appears anywhere in the
// non-test source, including inside larger string literals.
func sourceEnvTokens(t *testing.T) map[string]bool {
	t.Helper()
	tokens := map[string]bool{}
	for _, path := range productionGoFiles(t, "cmd", "internal") {
		data, err := os.ReadFile(path) //nolint:gosec // repository source discovered by the walk above
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range sourceEnvTokenPattern.FindAllString(string(data), -1) {
			tokens[token] = true
		}
	}
	return tokens
}

func sortedNameSet(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// login, register, and server print flag.FlagSet help and exit, so they are
// captured from the compiled binary (their help goes to stderr).
func TestContractFlagSetHelpHasNoTabsOrDuplicateLines(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	for _, command := range []string{"login", "register", "server"} {
		result := cli.Run(t, "ssm", nil, command, "--help")
		output := result.Stdout + result.Stderr
		if !strings.Contains(output, "Usage") {
			t.Fatalf("ssm %s --help printed no usage: %s", command, compiledOutputIdentity(result))
		}
		if strings.ContainsRune(output, '\t') {
			// The flag package indents flag descriptions with a tab; that is
			// its generated format, so only leading-tab runs of code are
			// checked for duplicates, not banned.
			output = strings.ReplaceAll(output, "\t", "  ")
		}
		seen := map[string]bool{}
		for _, line := range strings.Split(output, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if seen[trimmed] {
				t.Errorf("ssm %s --help repeats a line: %q", command, trimmed)
			}
			seen[trimmed] = true
		}
	}
}
