package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestSuggestCommand(t *testing.T) {
	for _, tc := range []struct {
		sshctl     bool
		word, want string
	}{
		{true, "keys", "`keys` is an ssm command; run `ssm keys ...`"},
		{true, "vault", "host list"},
		{true, "alias", "redirect"},
		{true, "stauts", "`sshctl status`"},
		{true, "hostkey", "`sshctl host-key`"},
		{true, "hosts2", "`sshctl hosts`"},
		{false, "status", "`status` is an sshctl command; run `sshctl status ...`"},
		{false, "pul", "`ssm pull`"},
	} {
		got, ok := suggestCommand(tc.sshctl, tc.word)
		if !ok || !strings.Contains(got.Hint, tc.want) {
			t.Errorf("suggestCommand(%v, %q) = %+v, %v; want hint containing %q", tc.sshctl, tc.word, got, ok, tc.want)
		}
	}
	for _, word := range []string{"web-prd1", "a", "zzzzzzzz", "prod"} {
		if got, ok := suggestCommand(true, word); ok {
			t.Errorf("suggestCommand(true, %q) = %+v, want no suggestion", word, got)
		}
	}
}

func TestSuggestRunOptionUsesRealOptionTable(t *testing.T) {
	for option, want := range map[string]string{
		"--script-file": "-f",
		"--fetch":       "sshctl get",
		"--timout":      "--timeout",
		"--jsn":         "--json",
		"--timout=5s":   "--timeout",
	} {
		if got := runOptionSuggestion(option); !strings.Contains(got, want) {
			t.Errorf("runOptionSuggestion(%q) = %q, want it to contain %q", option, got, want)
		}
	}
	for _, option := range []string{"--qqqqqqqq", "-x"} {
		if got := runOptionSuggestion(option); got != "" {
			t.Errorf("runOptionSuggestion(%q) = %q, want none", option, got)
		}
	}
}

// Every option literal accepted by parseRemoteRunArgs must be in the shared
// option tables, so suggestions cannot drift from the parser.
func TestRunOptionTablesCoverParser(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "runargs.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, name := range runValueOptions {
		known[name] = true
	}
	for _, name := range runFlagOptions {
		known[name] = true
	}
	var missing []string
	for _, declaration := range parsed.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "parseRemoteRunArgs" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, _ := strconv.Unquote(literal.Value)
			if !strings.HasPrefix(value, "-") || value == "-" || value == "--" {
				return true
			}
			value = strings.TrimSuffix(value, "=")
			if !known[value] && !strings.Contains(value, " ") {
				missing = append(missing, value)
			}
			return true
		})
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("parseRemoteRunArgs options missing from runValueOptions/runFlagOptions: %v", missing)
	}
}
