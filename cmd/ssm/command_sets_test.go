package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strconv"
	"testing"
)

// dispatchCases returns the string cases of the top-level "switch args[0]" in
// the named function (the default branch is not a string case).
func dispatchCases(t *testing.T, file, function string) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var cases []string
	found := false
	for _, declaration := range parsed.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != function {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			sw, ok := node.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			index, ok := sw.Tag.(*ast.IndexExpr)
			if !ok {
				return true
			}
			base, ok := index.X.(*ast.Ident)
			literal, isLiteral := index.Index.(*ast.BasicLit)
			if !ok || base.Name != "args" || !isLiteral || literal.Value != "0" {
				return true
			}
			found = true
			for _, statement := range sw.Body.List {
				for _, expression := range statement.(*ast.CaseClause).List {
					value, err := strconv.Unquote(expression.(*ast.BasicLit).Value)
					if err != nil {
						t.Fatal(err)
					}
					cases = append(cases, value)
				}
			}
			return false
		})
	}
	if !found {
		t.Fatalf("no switch args[0] in %s %s", file, function)
	}
	sort.Strings(cases)
	return cases
}

func sortedCommandNames(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// A subcommand added to a dispatch switch but not to the command sets would be
// mistaken for a host alias by the remote-argv boundary scanning.
func TestCommandSetsMatchDispatchSwitches(t *testing.T) {
	if got, want := dispatchCases(t, "sshctl.go", "runSSHCTLParsed"), sortedCommandNames(sshctlCommands); !reflect.DeepEqual(got, want) {
		t.Fatalf("sshctlCommands out of sync with runSSHCTLParsed:\nswitch=%q\nset=%q", got, want)
	}
	if got, want := dispatchCases(t, "main.go", "main"), sortedCommandNames(ssmCommands); !reflect.DeepEqual(got, want) {
		t.Fatalf("ssmCommands out of sync with main:\nswitch=%q\nset=%q", got, want)
	}
	for name := range sshctlCommands {
		if !knownCLICommands[name] {
			t.Errorf("%q missing from knownCLICommands", name)
		}
	}
	for name := range ssmCommands {
		if !knownCLICommands[name] {
			t.Errorf("%q missing from knownCLICommands", name)
		}
	}
}
