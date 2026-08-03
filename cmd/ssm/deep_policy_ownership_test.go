package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestDeepPolicyOwnershipContraction is the checked contraction gate for the
// three v2 policy owners. It deliberately inspects Go syntax and call/import
// relationships rather than source snippets: formatting and comments cannot
// make a policy owner appear (or disappear).
func TestDeepPolicyOwnershipContraction(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	packages := map[string]astPackage{
		"cmd/ssm":                       loadASTPackage(t, root, "cmd/ssm"),
		"internal/machinecontract":      loadASTPackage(t, root, "internal/machinecontract"),
		"internal/synctransaction":      loadASTPackage(t, root, "internal/synctransaction"),
		"internal/inventorytransaction": loadASTPackage(t, root, "internal/inventorytransaction"),
	}

	assertAllowedImports(t, packages)
	assertNoCommandPolicyCalls(t, packages["cmd/ssm"])
	assertNoDuplicatePolicyDeclarations(t, packages["cmd/ssm"])
	assertMachineContractDepth(t, packages["internal/machinecontract"])
	assertSyncTransactionDepth(t, packages["internal/synctransaction"])
	assertInventoryTransactionDepth(t, packages["internal/inventorytransaction"])
}

// TestDeepPolicyOwnershipAnalyzerAdversarialFixtures freezes the negative
// cases that motivated the semantic analyzer. These fixtures intentionally
// exercise the pre-hardening checks first; a green result means each evasion
// is rejected rather than merely named differently.
func TestDeepPolicyOwnershipAnalyzerAdversarialFixtures(t *testing.T) {
	t.Run("aliased and dot imports are owned by import path", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import (
    cloudAlias "ssm/internal/cloud"
    . "ssm/internal/cloud"
    . "encoding/json"
    jsonAlias "encoding/json"
)
func runList() {
    _ = cloudAlias.RemoteETag
    _ = RemoteETag
    _ = NewEncoder
    _ = jsonAlias.NewEncoder
}`)
		got := commandPolicyReferenceViolations(fixture)
		if len(got) == 0 || !containsViolation(got, "ssm/internal/cloud.RemoteETag") || !containsViolation(got, "encoding/json.NewEncoder") {
			t.Fatalf("analyzer accepted aliased/dot prohibited references")
		}
	})

	t.Run("indirect selector references remain policy references", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import cloudAlias "ssm/internal/cloud"
func runList() {
    var refresh func() = cloudAlias.RemoteETag
    _ = refresh
}`)
		if got := commandPolicyReferenceViolations(fixture); len(got) == 0 {
			t.Fatalf("analyzer accepted prohibited selector used as a function value")
		}
	})

	t.Run("renamed chained wrappers and closures are not invocation boundaries", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import (
    "ssm/internal/machinecontract"
    "ssm/internal/synctransaction"
)
func runList() { _ = renamedRefresh; _ = renamedRedaction }
func renamedRefresh() { chainedRefresh() }
func chainedRefresh() { syncTransaction(false).Refresh() }
func renamedRedaction(value string) string {
    wrapped := func() string { return machinecontract.RedactString(value) }
    return wrapped()
}`)
		if got := duplicatePolicyDeclarationViolations(fixture); len(got) == 0 {
			t.Fatalf("analyzer accepted renamed/chained refresh-redaction wrappers")
		}
	})

	t.Run("receiver identifiers preserve transaction ownership", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import "ssm/internal/synctransaction"
func runList() {
    tx := syncTransaction(false)
    tx.Refresh()
}
func helper(tx *synctransaction.Transaction) {
    tx.Refresh()
}
func beginStream() {
    tx := synctransaction.New()
    stream := tx.BeginStream()
    stream.Initialize()
}
func streamHelper(stream *synctransaction.Stream) {
    stream.BeforeLine()
}`)
		if got := duplicatePolicyDeclarationViolations(fixture); len(got) == 0 {
			t.Fatalf("analyzer accepted policy method through an unproven receiver identifier")
		}
	})

	t.Run("dot-imported receiver types preserve transaction ownership", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import . "ssm/internal/synctransaction"
func helper(tx *Transaction, stream *Stream) {
    tx.Refresh()
    stream.BeforeLine()
}`)
		if got := duplicatePolicyDeclarationViolations(fixture); len(got) == 0 {
			t.Fatalf("analyzer accepted policy methods through dot-imported receiver types")
		}
	})

	t.Run("renamed transaction factory remains a policy seam", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import "ssm/internal/synctransaction"
func runList() { foo().Refresh() }
func foo() *synctransaction.Transaction { return synctransaction.New() }`)
		if got := duplicatePolicyDeclarationViolations(fixture); len(got) == 0 {
			t.Fatalf("analyzer accepted renamed synctransaction.New factory")
		}
	})

	t.Run("renamed local factory returning syncTransaction remains a seam", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import "ssm/internal/synctransaction"
func runList() { foo().Refresh() }
func foo() *synctransaction.Transaction { return syncTransaction(false) }`)
		if got := duplicatePolicyDeclarationViolations(fixture); len(got) == 0 {
			t.Fatalf("analyzer accepted renamed local syncTransaction factory")
		}
	})

	t.Run("stored transaction and stream fields retain ownership", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import "ssm/internal/synctransaction"
type holders struct {
    transaction *synctransaction.Transaction
    stream *synctransaction.Stream
}
func helper(value holders) {
    value.transaction.Refresh()
    value.stream.BeforeLine()
}`)
		if got := duplicatePolicyDeclarationViolations(fixture); len(got) == 0 {
			t.Fatalf("analyzer accepted stored transaction/stream field receivers")
		}
	})

	t.Run("transaction and stream aliases retain ownership", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import "ssm/internal/synctransaction"
type aliasTransaction = synctransaction.Transaction
type aliasStream = synctransaction.Stream
func helper(tx *aliasTransaction, stream *aliasStream) {
    tx.Refresh()
    stream.BeforeLine()
}`)
		if got := duplicatePolicyDeclarationViolations(fixture); len(got) == 0 {
			t.Fatalf("analyzer accepted transaction/stream type aliases")
		}
	})

	t.Run("transaction and stream method expressions remain policy references", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import "ssm/internal/synctransaction"
func helper() {
    refresh := (*synctransaction.Transaction).Refresh
    beforeLine := (*synctransaction.Stream).BeforeLine
    _ = refresh
    _ = beforeLine
}`)
		if got := duplicatePolicyDeclarationViolations(fixture); len(got) == 0 {
			t.Fatalf("analyzer accepted transaction/stream method expressions")
		}
	})

	t.Run("function-value syncTransaction factories remain policy references", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
func helper() {
    factory := syncTransaction
    transaction := factory(false)
    transaction.Refresh()
}`)
		if got := duplicatePolicyDeclarationViolations(fixture); len(got) == 0 {
			t.Fatalf("analyzer accepted function-value syncTransaction factory")
		}
	})

	t.Run("reviewed invocation and inventory wiring boundaries stay allowed", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import "ssm/internal/synctransaction"
func syncTransaction(bool) *synctransaction.Transaction { return nil }
func runList() { syncTransaction(false).Refresh() }
func pushTransactionScopeInSession() {
    options := struct{ Sync *synctransaction.Transaction }{Sync: syncTransaction(false)}
    _ = options
}`)
		if got := duplicatePolicyDeclarationViolations(fixture); len(got) != 0 {
			t.Fatalf("analyzer rejected reviewed invocation/wiring boundary: %v", got)
		}
	})

	t.Run("named constant false is dead", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
const disabled = false
func Classify() {
    if disabled { RedactString() }
}`)
		got := policyPathViolations(fixture, "machine contract", []policyPath{{function: "Classify", calls: []string{"RedactString"}, branch: true, decisions: []string{"RedactString"}}})
		if len(got) == 0 {
			t.Fatalf("analyzer accepted named-constant dead policy branch")
		}
		localFixture := parseOwnershipFixture(t, `package main
func Classify() {
    const disabled = false
    if disabled { RedactString() }
}`)
		localViolations := policyPathViolations(localFixture, "machine contract", []policyPath{{function: "Classify", calls: []string{"RedactString"}, branch: true, decisions: []string{"RedactString"}}})
		if len(localViolations) == 0 {
			t.Fatalf("analyzer accepted local named-constant dead policy branch")
		}
	})

	t.Run("for false is dead", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
func Classify() {
    for false { RedactString() }
}`)
		got := policyPathViolations(fixture, "machine contract", []policyPath{{function: "Classify", calls: []string{"RedactString"}, branch: true, decisions: []string{"RedactString"}}})
		if len(got) == 0 {
			t.Fatalf("analyzer accepted for-false dead policy branch")
		}
	})

	for _, terminator := range []struct {
		name       string
		importLine string
		body       string
	}{
		{name: "panic", body: `panic("stop"); if unrelated { RedactString() }`},
		{name: "os.Exit", importLine: `import "os"`, body: `os.Exit(1); if unrelated { RedactString() }`},
		{name: "runtime.Goexit", importLine: `import "runtime"`, body: `runtime.Goexit(); if unrelated { RedactString() }`},
	} {
		t.Run(terminator.name+" terminates policy path", func(t *testing.T) {
			fixture := parseOwnershipFixture(t, fmt.Sprintf("package main\n%s\nfunc Classify() { %s }", terminator.importLine, terminator.body))
			got := policyPathViolations(fixture, "machine contract", []policyPath{{function: "Classify", calls: []string{"RedactString"}, branch: true, decisions: []string{"render"}}})
			if len(got) == 0 {
				t.Fatalf("analyzer accepted policy path after %s terminator", terminator.name)
			}
		})
	}

	t.Run("fake Exit method is not a terminator", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
type fake struct{}
func (fake) Exit(int) {}
func Classify() {
    fakeObject := fake{}
    fakeObject.Exit(1)
    if unrelated { RedactString() }
}`)
		got := policyPathViolations(fixture, "machine contract", []policyPath{{function: "Classify", calls: []string{"RedactString"}, branch: true, decisions: []string{"RedactString"}}})
		if len(got) != 0 {
			t.Fatalf("analyzer treated fake Exit method as a terminator: %v", got)
		}
	})

	t.Run("terminator imports remain file-scoped", func(t *testing.T) {
		fixture := parseOwnershipFixtures(t, map[string]string{
			"imports_fixture.go": `package main
import hostos "os"`,
			"policy_fixture.go": `package main
type fake struct{}
func (fake) Exit(int) {}
func Classify() {
    hostos := fake{}
    hostos.Exit(1)
    if unrelated { RedactString() }
}`,
		})
		got := policyPathViolations(fixture, "machine contract", []policyPath{{function: "Classify", calls: []string{"RedactString"}, branch: true, decisions: []string{"RedactString"}}})
		if len(got) != 0 {
			t.Fatalf("analyzer let another file's os alias terminate this policy path: %v", got)
		}
	})

	t.Run("local terminator alias shadowing remains ordinary code", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
import hostos "os"
type fake struct{}
func (fake) Exit(int) {}
func Classify() {
    hostos := fake{}
    hostos.Exit(1)
    if unrelated { RedactString() }
}`)
		got := policyPathViolations(fixture, "machine contract", []policyPath{{function: "Classify", calls: []string{"RedactString"}, branch: true, decisions: []string{"RedactString"}}})
		if len(got) != 0 {
			t.Fatalf("analyzer let a local os alias shadow terminate this policy path: %v", got)
		}
	})

	t.Run("constant shadowing remains block scoped and sequential", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
const enabled = true
func Classify() {
    {
        const enabled = false
        if enabled { RedactString() }
        {
            if enabled { RedactString() }
        }
    }
    if enabled { RedactString() }
}`)
		function := packageFunctions(fixture)["Classify"]
		context := reachabilityContext{
			constants:   packageBooleanConstants(fixture),
			terminators: terminatorBindingsForFile(function.bindings),
		}
		analysis := reachableNodeAnalysis(function.declaration.Body, context)
		if !analysis.calls["RedactString"] {
			t.Fatalf("analyzer leaked local constant shadowing across blocks: %v", analysis.calls)
		}
	})

	t.Run("unrelated returns do not satisfy policy decisions", func(t *testing.T) {
		fixture := parseOwnershipFixture(t, `package main
func Classify() { if unrelated { return }; RedactString() }
func ProcessExit() { if unrelated { return } }`)
		paths := []policyPath{
			{function: "Classify", calls: []string{"RedactString"}, branch: true, decisions: []string{"RedactString"}},
			{function: "ProcessExit", branch: true, decisions: []string{"processExit"}},
		}
		got := policyPathViolations(fixture, "machine contract", paths)
		if len(got) == 0 {
			t.Fatalf("analyzer accepted unrelated return as policy decision")
		}
	})

	t.Run("shallow owner with dead policy paths is rejected", func(t *testing.T) {
		deadFixture := parseOwnershipFixture(t, `package main
func Classify() { if false { RedactString() } }
func ClassifySSH() { if false { Classify() } }
func Render() { if unrelated { render() } }
func WriteFailure() { if false { WriteFailureJSON(); WriteHuman(); ProcessExit() } }
func RedactString() { if false { redactAssignmentValues(); redactStructuredValues() } }
func ProcessExit() { if false {} }`)
		deadViolations := policyPathViolations(deadFixture, "machine contract", machineContractPolicyPaths())
		if !containsViolation(deadViolations, `function "Classify" does not own policy path through "RedactString"`) {
			t.Fatalf("analyzer accepted constant-dead required policy path: %v", deadViolations)
		}

		unrelatedFixture := parseOwnershipFixture(t, `package main
func Classify() { if unrelated { render() }; RedactString() }
func ClassifySSH() { if unrelated { render() }; Classify() }
func Render() { render() }
func WriteFailure() { if unrelated { render() }; WriteFailureJSON(); WriteHuman(); ProcessExit() }
func RedactString() { if unrelated { render() }; redactAssignmentValues(); redactStructuredValues() }
func ProcessExit() { if unrelated { render() } }`)
		unrelatedViolations := policyPathViolations(unrelatedFixture, "machine contract", machineContractPolicyPaths())
		if !containsViolation(unrelatedViolations, "does not govern a required policy path") {
			t.Fatalf("analyzer accepted unrelated branch as policy decision: %v", unrelatedViolations)
		}
	})
}

func containsViolation(violations []string, fragment string) bool {
	for _, violation := range violations {
		if strings.Contains(violation, fragment) {
			return true
		}
	}
	return false
}

func parseOwnershipFixture(t *testing.T, source string) astPackage {
	t.Helper()
	return parseOwnershipFixtures(t, map[string]string{"ownership_fixture.go": source})
}

func parseOwnershipFixtures(t *testing.T, sources map[string]string) astPackage {
	t.Helper()
	files := make(map[string]*ast.File, len(sources))
	for name, source := range sources {
		file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
		if err != nil {
			t.Fatalf("parse ownership fixture %s: %v", name, err)
		}
		files[name] = file
	}
	return astPackage{files: files}
}

type astPackage struct {
	files map[string]*ast.File
}

type namedASTFile struct {
	name string
	file *ast.File
}

func sortedASTFiles(packageAST astPackage) []namedASTFile {
	files := make([]namedASTFile, 0, len(packageAST.files))
	for name, file := range packageAST.files {
		files = append(files, namedASTFile{name: name, file: file})
	}
	sort.Slice(files, func(left, right int) bool { return files[left].name < files[right].name })
	return files
}

func loadASTPackage(t *testing.T, root, relative string) astPackage {
	t.Helper()
	directory := filepath.Join(root, filepath.FromSlash(relative))
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	files := make(map[string]*ast.File)
	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			continue
		}
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files[entry.Name()] = file
	}
	return astPackage{files: files}
}

func assertAllowedImports(t *testing.T, packages map[string]astPackage) {
	t.Helper()
	// These are the only internal edges needed by the three policy modules.
	// Mechanism packages remain below them; command code is the composition
	// root and is therefore not an allowed dependency of any owner.
	allowed := map[string]map[string]bool{
		"internal/machinecontract": {
			"ssm/internal/privatepath":     true,
			"ssm/internal/synctransaction": true,
		},
		"internal/synctransaction": {
			"ssm/internal/cloud":  true,
			"ssm/internal/config": true,
		},
		"internal/inventorytransaction": {
			"ssm/internal/config":          true,
			"ssm/internal/machinecontract": true,
			"ssm/internal/privatepath":     true,
			"ssm/internal/ssh":             true,
			"ssm/internal/synctransaction": true,
		},
	}
	for packagePath, packageAST := range packages {
		if packagePath == "cmd/ssm" {
			continue
		}
		for fileName, file := range packageAST.files {
			for _, spec := range file.Imports {
				importPath := strings.Trim(spec.Path.Value, `"`)
				if !strings.HasPrefix(importPath, "ssm/internal/") {
					continue
				}
				if !allowed[packagePath][importPath] {
					t.Errorf("%s/%s imports %s outside its allowed owner direction", packagePath, fileName, importPath)
				}
			}
		}
	}

	// No policy owner may depend on command orchestration. This catches an
	// attempted facade that reaches back into cmd/ssm to make its decisions.
	for packagePath, packageAST := range packages {
		if packagePath == "cmd/ssm" {
			continue
		}
		for fileName, file := range packageAST.files {
			for _, spec := range file.Imports {
				if strings.Trim(spec.Path.Value, `"`) == "ssm/cmd/ssm" {
					t.Errorf("%s/%s imports command orchestration", packagePath, fileName)
				}
			}
		}
	}
}

func assertNoCommandPolicyCalls(t *testing.T, packageAST astPackage) {
	t.Helper()
	for _, violation := range commandPolicyReferenceViolations(packageAST) {
		t.Error(violation)
	}
}

func commandPolicyReferenceViolations(packageAST astPackage) []string {
	// References in this table are transport/persistence policy decisions. The
	// command may invoke the owning module, but may not recreate these choices
	// against the mechanism directly. Resolve the package by import path rather
	// than its local spelling: aliases, dot imports, and function values must
	// all remain visible to the gate.
	forbidden := map[string]map[string]bool{
		"ssm/internal/cloud": {
			"RemoteETag":        true,
			"InspectRemoteBlob": true,
			"Pull":              true,
			"PullIfChanged":     true,
			"PushBlob":          true,
			"PushBlobObserved":  true,
		},
		"encoding/json": {
			"NewEncoder":    true,
			"MarshalIndent": true,
		},
	}
	violations := make([]string, 0)
	for _, namedFile := range sortedASTFiles(packageAST) {
		fileName, file := namedFile.name, namedFile.file
		bindings := importBindings(file)
		selectorNames := selectorIdentifierSet(file)
		ast.Inspect(file, func(node ast.Node) bool {
			switch reference := node.(type) {
			case *ast.SelectorExpr:
				binding, ok := selectorImportBinding(reference, bindings)
				if !ok || !forbidden[binding.path][reference.Sel.Name] {
					return true
				}
				violations = append(violations, fmt.Sprintf("cmd/ssm/%s makes %s.%s policy decision; invoke its owning module instead", fileName, binding.path, reference.Sel.Name))
			case *ast.Ident:
				if selectorNames[reference] {
					return true
				}
				for _, binding := range bindings.dots {
					if !forbidden[binding.path][reference.Name] {
						continue
					}
					violations = append(violations, fmt.Sprintf("cmd/ssm/%s makes %s.%s policy decision through a dot import; invoke its owning module instead", fileName, binding.path, reference.Name))
				}
			}
			return true
		})
	}
	sort.Strings(violations)
	return violations
}

type importBinding struct {
	path string
}

type fileImportBindings struct {
	named map[string]importBinding
	dots  []importBinding
}

func importBindings(file *ast.File) fileImportBindings {
	bindings := fileImportBindings{named: make(map[string]importBinding)}
	for _, spec := range file.Imports {
		importPath := strings.Trim(spec.Path.Value, `"`)
		localName := filepath.Base(importPath)
		dot := false
		if spec.Name != nil {
			localName = spec.Name.Name
			dot = localName == "."
		}
		binding := importBinding{path: importPath}
		if dot {
			bindings.dots = append(bindings.dots, binding)
		} else {
			bindings.named[localName] = binding
		}
	}
	return bindings
}

func selectorImportBinding(selector *ast.SelectorExpr, bindings fileImportBindings) (importBinding, bool) {
	identifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return importBinding{}, false
	}
	binding, ok := bindings.named[identifier.Name]
	if !ok {
		return importBinding{}, false
	}
	return binding, true
}

func selectorIdentifierSet(root ast.Node) map[*ast.Ident]bool {
	selectors := make(map[*ast.Ident]bool)
	ast.Inspect(root, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if ok {
			selectors[selector.Sel] = true
		}
		return true
	})
	return selectors
}

func assertNoDuplicatePolicyDeclarations(t *testing.T, packageAST astPackage) {
	t.Helper()
	for _, violation := range duplicatePolicyDeclarationViolations(packageAST) {
		t.Error(violation)
	}
}

func duplicatePolicyDeclarationViolations(packageAST astPackage) []string {
	// These helpers were the former command-owned policy seams. Parsing and
	// success shaping remain explicitly allowed; refresh/redaction policy does
	// not. Keep the historical names as a cheap diagnostic, then run the
	// structural graph so a renamed/chained helper cannot evade the gate.
	forbidden := map[string]bool{
		"pullIfChanged":               true,
		"refreshVaultIfChanged":       true,
		"refreshVaultIfChangedResult": true,
		"refreshHostVault":            true,
		"redactError":                 true,
		"redactString":                true,
	}
	violations := make([]string, 0)
	for _, namedFile := range sortedASTFiles(packageAST) {
		fileName, file := namedFile.name, namedFile.file
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || !forbidden[function.Name.Name] {
				continue
			}
			violations = append(violations, fmt.Sprintf("cmd/ssm/%s retains duplicate policy helper %q", fileName, function.Name.Name))
		}
	}
	violations = append(violations, commandPolicyGraphViolations(packageAST)...)
	sort.Strings(violations)
	return violations
}

var reviewedCommandPolicyBoundaries = map[string]bool{
	// These are the command's reviewed invocation roots. A root may invoke an
	// owner directly; policy-bearing helpers and closures below it are still
	// rejected by the graph.
	"runArgvStream":     true,
	"runAgentRequest":   true,
	"runCheck":          true,
	"runDoctor":         true,
	"runExecSpec":       true,
	"exitRunArgvStream": true,
	"runGet":            true,
	"runHostCommand":    true,
	"runHostKeyCommand": true,
	"runKeysList":       true,
	"runKeysRemove":     true,
	"runList":           true,
	"runMap":            true,
	"runPull":           true,
	"runPullIfChanged":  true,
	"runPush":           true,
	// This is the only push helper that constructs inventory publication
	// options with the retained sync factory; its callers only delegate here.
	"pushTransactionScopeInSession": true,
	"runRemoteHash":                 true,
	"runImportJSON":                 true,
	"runPutArgs":                    true,
	"runPutWithOptions":             true,
	"runRemove":                     true,
	"runSSHCTL":                     true,
	"runSSHCTLDoctor":               true,
	"runSSHCTLList":                 true,
	"runSSHCTLMap":                  true,
	"runSSHCTLParsed":               true,
	"runSSHCTLPlan":                 true,
	"runSSHCTLRun":                  true,
	"runSSHCTLRunInvocation":        true,
	"runSSHCTLStatus":               true,
	// The sole retained command-side construction boundary. Callers may wire
	// this factory into inventory/stream options without inheriting New's
	// transport policy; renamed constructors remain graph violations.
	"syncTransaction": true,
	"main":            true,
}

var commandSyncPolicyMethods = map[string]bool{
	"Refresh":                    true,
	"Pull":                       true,
	"Sync":                       true,
	"Facts":                      true,
	"BeginStream":                true,
	"Initialize":                 true,
	"BeforeLine":                 true,
	"PreparePublication":         true,
	"ObservePublicationIdentity": true,
	"SendPublication":            true,
	"VerifyEmptyPublication":     true,
	"ConfirmPublication":         true,
	"RemoteIdentity":             true,
}

var commandRedactionPolicyMethods = map[string]bool{
	"RedactString":       true,
	"RedactError":        true,
	"NewRedactingWriter": true,
}

type commandPolicyNode struct {
	name    string
	body    *ast.BlockStmt
	closure bool
	refs    []string
	edges   []string
}

func commandPolicyGraphViolations(packageAST astPackage) []string {
	nodes := make(map[string]*commandPolicyNode)
	closureNumber := 0
	for _, namedFile := range sortedASTFiles(packageAST) {
		file := namedFile.file
		bindings := importBindings(file)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			node := &commandPolicyNode{name: function.Name.Name, body: function.Body}
			node.edges = collectLocalFunctionCalls(function.Body)
			nodes[node.name] = node
			node.refs = collectCommandPolicyReferences(function.Body, bindings)
			collectCommandPolicyClosures(function.Body, function.Name.Name, bindings, nodes, &closureNumber)
		}
	}

	// A policy edge can be hidden behind a chain of ordinary local calls. Mark
	// every node that reaches a direct owner reference, then require all such
	// nodes to be one of the reviewed command invocation roots.
	reachesPolicy := make(map[string]bool)
	visiting := make(map[string]bool)
	var reaches func(string) bool
	reaches = func(name string) bool {
		if value, ok := reachesPolicy[name]; ok {
			return value
		}
		if visiting[name] {
			return false
		}
		node := nodes[name]
		if node == nil {
			return false
		}
		visiting[name] = true
		value := len(node.refs) > 0
		if !reviewedCommandPolicyBoundaries[name] {
			for _, edge := range node.edges {
				if reviewedCommandPolicyBoundaries[edge] {
					continue
				}
				if reaches(edge) {
					value = true
				}
			}
		}
		delete(visiting, name)
		reachesPolicy[name] = value
		return value
	}
	for name := range nodes {
		reaches(name)
	}

	violations := make([]string, 0)
	names := make([]string, 0, len(nodes))
	for name := range nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		node := nodes[name]
		if !reachesPolicy[name] || (!node.closure && reviewedCommandPolicyBoundaries[name]) {
			continue
		}
		if node.closure {
			violations = append(violations, fmt.Sprintf("cmd/ssm policy-bearing function literal %q is outside a reviewed invocation boundary", name))
			continue
		}
		violations = append(violations, fmt.Sprintf("cmd/ssm function %q reaches refresh/redaction policy outside a reviewed invocation boundary", name))
	}
	sort.Strings(violations)
	return violations
}

func collectCommandPolicyClosures(root *ast.BlockStmt, owner string, bindings fileImportBindings, nodes map[string]*commandPolicyNode, counter *int) {
	ast.Inspect(root, func(node ast.Node) bool {
		literal, ok := node.(*ast.FuncLit)
		if !ok {
			return true
		}
		name := fmt.Sprintf("%s$closure%d", owner, *counter)
		(*counter)++
		closure := &commandPolicyNode{name: name, body: literal.Body, closure: true}
		closure.refs = collectCommandPolicyReferences(literal.Body, bindings)
		closure.edges = collectLocalFunctionCalls(literal.Body)
		nodes[name] = closure
		collectCommandPolicyClosures(literal.Body, name, bindings, nodes, counter)
		return false
	})
}

func collectCommandPolicyReferences(root ast.Node, bindings fileImportBindings) []string {
	refs := make([]string, 0)
	selectorNames := selectorIdentifierSet(root)
	ast.Inspect(root, func(node ast.Node) bool {
		switch reference := node.(type) {
		case *ast.FuncLit:
			// Closures are separate graph nodes. Do not let a reviewed root hide
			// policy in an inline function literal.
			return false
		case *ast.SelectorExpr:
			if binding, ok := selectorImportBinding(reference, bindings); ok {
				switch binding.path {
				case "ssm/internal/machinecontract":
					if commandRedactionPolicyMethods[reference.Sel.Name] {
						refs = append(refs, binding.path+"."+reference.Sel.Name)
					}
				case "ssm/internal/synctransaction":
					if reference.Sel.Name == "New" || commandSyncPolicyMethods[reference.Sel.Name] {
						refs = append(refs, binding.path+"."+reference.Sel.Name)
					}
				}
				return true
			}
			if commandSyncPolicyMethods[reference.Sel.Name] {
				refs = append(refs, "ssm/internal/synctransaction."+reference.Sel.Name)
			}
		case *ast.Ident:
			if selectorNames[reference] {
				return true
			}
			for _, binding := range bindings.dots {
				if (binding.path == "ssm/internal/machinecontract" && commandRedactionPolicyMethods[reference.Name]) ||
					(binding.path == "ssm/internal/synctransaction" && (commandSyncPolicyMethods[reference.Name] || reference.Name == "New")) {
					refs = append(refs, binding.path+"."+reference.Name)
				}
			}
		}
		if reference, ok := node.(*ast.Ident); ok && reference.Name == "syncTransaction" && !selectorNames[reference] {
			refs = append(refs, "cmd/ssm.syncTransaction")
		}
		return true
	})
	return refs
}

func collectLocalFunctionCalls(root ast.Node) []string {
	calls := make([]string, 0)
	ast.Inspect(root, func(node ast.Node) bool {
		if _, ok := node.(*ast.FuncLit); ok {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if function, ok := call.Fun.(*ast.Ident); ok {
			calls = append(calls, function.Name)
		}
		return true
	})
	return calls
}

type policyPath struct {
	function  string
	calls     []string
	decisions []string
	branch    bool
}

func assertMachineContractDepth(t *testing.T, packageAST astPackage) {
	t.Helper()
	assertPolicyPaths(t, packageAST, "machine contract", machineContractPolicyPaths())
}

func machineContractPolicyPaths() []policyPath {
	return []policyPath{
		{function: "Classify", calls: []string{"RedactString"}, decisions: []string{"RedactString"}, branch: true},
		{function: "ClassifySSH", calls: []string{"Classify"}, decisions: []string{"errors.As", "strings.Contains", "isTimeoutErrorMessage"}, branch: true},
		{function: "Render", calls: []string{"render"}},
		{function: "WriteFailure", calls: []string{"WriteFailureJSON", "WriteHuman", "ProcessExit"}},
		{function: "RedactString", calls: []string{"redactAssignmentValues", "redactStructuredValues"}},
		{function: "ProcessExit", decisions: []string{"processExit"}, branch: true},
	}
}

func assertSyncTransactionDepth(t *testing.T, packageAST astPackage) {
	t.Helper()
	assertPolicyPaths(t, packageAST, "sync transaction", []policyPath{
		{function: "configuration", calls: []string{"ReadFile", "json.Unmarshal"}},
		{function: "refreshConfigured", calls: []string{"RemoteETag", "Pull", "commitSuccess"}},
		{function: "PreparePublication", calls: []string{"InspectRemoteBlob", "preserveConflict"}},
		{function: "SendPublication", calls: []string{"ObservePublicationIdentity", "PushBlobObserved"}},
		{function: "Facts", calls: []string{"configuration", "localFacts"}},
		{function: "Initialize", calls: []string{"refresh"}, decisions: []string{"transaction", "initialized", "offline"}, branch: true},
		{function: "BeforeLine", calls: []string{"refresh"}, decisions: []string{"transaction", "initialized", "offline", "now"}, branch: true},
	})
}

func assertInventoryTransactionDepth(t *testing.T, packageAST astPackage) {
	t.Helper()
	assertPolicyPaths(t, packageAST, "inventory transaction", []policyPath{
		{function: "ApplyHost", calls: []string{"buildHostCandidate", "config.Save"}},
		{function: "RemoveSavedKey", calls: []string{"removeKeyByName", "config.Save"}},
		{function: "ApplyImport", calls: []string{"validateImportInventory", "config.Save"}},
		{function: "Publish", calls: []string{"project", "SendPublication", "finalizePublishingIntent"}},
		{function: "ReconcilePublishingIntent", calls: []string{"reconcilePublishingIntent"}},
		{function: "Preflight", calls: []string{"dependencies"}},
	})
}

func assertPolicyPaths(t *testing.T, packageAST astPackage, owner string, paths []policyPath) {
	t.Helper()
	for _, violation := range policyPathViolations(packageAST, owner, paths) {
		t.Error(violation)
	}
}

func policyPathViolations(packageAST astPackage, owner string, paths []policyPath) []string {
	functions := packageFunctions(packageAST)
	packageConstants := packageBooleanConstants(packageAST)
	violations := make([]string, 0)
	for _, path := range paths {
		function, ok := functions[path.function]
		declaration := function.declaration
		if !ok || declaration == nil || declaration.Body == nil {
			violations = append(violations, fmt.Sprintf("%s is missing concrete policy function %q", owner, path.function))
			continue
		}
		context := reachabilityContext{
			constants:   packageConstants,
			terminators: terminatorBindingsForFile(function.bindings),
		}
		analysis := reachableNodeAnalysis(declaration.Body, context)
		for _, wanted := range path.calls {
			if !analysis.calls[wanted] && !analysis.calls[strings.TrimPrefix(wanted, "config.")] {
				violations = append(violations, fmt.Sprintf("%s function %q does not own policy path through %q", owner, path.function, wanted))
			}
		}
		if path.branch && analysis.branches == 0 {
			violations = append(violations, fmt.Sprintf("%s function %q has no policy decision branch", owner, path.function))
		} else if path.branch && !policyDecisionGovernsPath(analysis, path) {
			violations = append(violations, fmt.Sprintf("%s function %q has a branch that does not govern a required policy path", owner, path.function))
		}
	}
	return violations
}

func policyDecisionGovernsPath(analysis reachableAnalysis, path policyPath) bool {
	for _, decision := range analysis.decisions {
		for _, wanted := range path.calls {
			if decision.calls[wanted] || decision.calls[strings.TrimPrefix(wanted, "config.")] {
				return true
			}
		}
		for _, wanted := range path.decisions {
			if decision.calls[wanted] || decision.selectors[wanted] || decision.selectors[strings.TrimPrefix(wanted, "config.")] {
				return true
			}
		}
	}
	return false
}

type functionInfo struct {
	declaration *ast.FuncDecl
	bindings    fileImportBindings
}

func packageFunctions(packageAST astPackage) map[string]functionInfo {
	functions := make(map[string]functionInfo)
	for _, namedFile := range sortedASTFiles(packageAST) {
		for _, declaration := range namedFile.file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				functions[function.Name.Name] = functionInfo{declaration: function, bindings: importBindings(namedFile.file)}
			}
		}
	}
	return functions
}

type reachableAnalysis struct {
	calls     map[string]bool
	selectors map[string]bool
	branches  int
	decisions []reachableDecision
	returns   bool
	context   reachabilityContext
}

type reachabilityContext struct {
	constants   map[string]bool
	terminators reachabilityTerminators
}

type reachabilityTerminators struct {
	packages  map[string]string
	functions map[string]string
}

type reachableDecision struct {
	calls     map[string]bool
	selectors map[string]bool
	returns   bool
}

func reachableNodeAnalysis(root ast.Node, context reachabilityContext) reachableAnalysis {
	context.constants = cloneBooleanConstants(context.constants)
	analysis := reachableAnalysis{
		calls:     make(map[string]bool),
		selectors: make(map[string]bool),
		context:   context,
	}
	walkReachable(root, &analysis)
	return analysis
}

func cloneBooleanConstants(constants map[string]bool) map[string]bool {
	cloned := make(map[string]bool, len(constants))
	for name, value := range constants {
		cloned[name] = value
	}
	return cloned
}

func collectBooleanDecl(declaration ast.Decl, constants map[string]bool) {
	genDecl, ok := declaration.(*ast.GenDecl)
	if !ok || genDecl.Tok != token.CONST {
		return
	}
	for _, specification := range genDecl.Specs {
		valueSpec, ok := specification.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for index, name := range valueSpec.Names {
			if index >= len(valueSpec.Values) {
				continue
			}
			if value, known := constantBool(valueSpec.Values[index], constants); known {
				constants[name.Name] = value
			}
		}
	}
}

// walkReachable follows ordinary control flow while ignoring dead branches
// and nested function literals. Owner-depth assertions therefore measure a
// real decision path instead of matching names hidden in `if false` or a
// closure that is never part of the owner's execution.
func walkReachable(node ast.Node, analysis *reachableAnalysis) bool {
	if node == nil {
		return true
	}
	switch statement := node.(type) {
	case *ast.BlockStmt:
		outerConstants := analysis.context.constants
		analysis.context.constants = cloneBooleanConstants(outerConstants)
		defer func() { analysis.context.constants = outerConstants }()
		for _, child := range statement.List {
			if !walkReachable(child, analysis) {
				return false
			}
		}
		return true
	case *ast.DeclStmt:
		collectBooleanDecl(statement.Decl, analysis.context.constants)
		return true
	case *ast.IfStmt:
		visitSimpleNode(statement.Init, analysis)
		visitSimpleNode(statement.Cond, analysis)
		value, known := constantBool(statement.Cond, analysis.context.constants)
		if !known {
			analysis.branches++
			analysis.decisions = append(analysis.decisions, reachableDecisionForCondition(statement.Cond, statement.Body, analysis.context))
			if statement.Else != nil {
				analysis.decisions = append(analysis.decisions, reachableDecisionForCondition(statement.Cond, statement.Else, analysis.context))
			}
		}
		bodyContinues := true
		elseContinues := true
		if !known || value {
			bodyContinues = walkReachable(statement.Body, analysis)
		}
		if statement.Else != nil && (!known || !value) {
			elseContinues = walkReachable(statement.Else, analysis)
		}
		if known && value {
			return bodyContinues
		}
		if known && !value {
			return elseContinues
		}
		return bodyContinues || elseContinues
	case *ast.SwitchStmt:
		visitSimpleNode(statement.Init, analysis)
		visitSimpleNode(statement.Tag, analysis)
		analysis.branches++
		analysis.decisions = append(analysis.decisions, reachableDecisionForCondition(statement.Tag, statement.Body, analysis.context))
		walkReachable(statement.Body, analysis)
		return true
	case *ast.ForStmt:
		visitSimpleNode(statement.Init, analysis)
		visitSimpleNode(statement.Cond, analysis)
		visitSimpleNode(statement.Post, analysis)
		value, known := constantBool(statement.Cond, analysis.context.constants)
		if known && !value {
			return true
		}
		analysis.branches++
		analysis.decisions = append(analysis.decisions, reachableDecisionForCondition(statement.Cond, statement.Body, analysis.context))
		walkReachable(statement.Body, analysis)
		return true
	case *ast.RangeStmt:
		visitSimpleNode(statement.Key, analysis)
		visitSimpleNode(statement.Value, analysis)
		visitSimpleNode(statement.X, analysis)
		analysis.branches++
		analysis.decisions = append(analysis.decisions, reachableDecisionForCondition(statement.X, statement.Body, analysis.context))
		walkReachable(statement.Body, analysis)
		return true
	case *ast.CaseClause:
		for _, child := range statement.Body {
			if !walkReachable(child, analysis) {
				return false
			}
		}
		return true
	case *ast.ReturnStmt:
		analysis.returns = true
		for _, result := range statement.Results {
			visitSimpleNode(result, analysis)
		}
		return false
	case *ast.FuncLit:
		return true
	default:
		visitSimpleNode(node, analysis)
		if statementTerminates(node, analysis.context.terminators) {
			return false
		}
		return true
	}
}

func reachableDecisionForWithContext(root ast.Node, context reachabilityContext) reachableDecision {
	if root == nil {
		return reachableDecision{}
	}
	analysis := reachableNodeAnalysis(root, context)
	return reachableDecision{calls: analysis.calls, selectors: analysis.selectors, returns: analysis.returns}
}

func reachableDecisionForCondition(condition ast.Node, branch ast.Node, context reachabilityContext) reachableDecision {
	decision := reachableDecisionForWithContext(branch, context)
	conditionAnalysis := reachableNodeAnalysis(condition, context)
	for call := range conditionAnalysis.calls {
		decision.calls[call] = true
	}
	for selector := range conditionAnalysis.selectors {
		decision.selectors[selector] = true
	}
	return decision
}

func visitSimpleNode(root ast.Node, analysis *reachableAnalysis) {
	if root == nil {
		return
	}
	ast.Inspect(root, func(node ast.Node) bool {
		if node != root {
			if _, ok := node.(*ast.FuncLit); ok {
				return false
			}
			switch node.(type) {
			case *ast.IfStmt, *ast.SwitchStmt, *ast.ForStmt, *ast.RangeStmt, *ast.BlockStmt, *ast.ReturnStmt:
				// Control nodes are handled by walkReachable when they are reached
				// as statements, not while scanning a simple expression.
				return false
			}
		}
		switch node := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.SelectorExpr:
			recordSelector(node, analysis.selectors)
		case *ast.CallExpr:
			recordCall(node, analysis.calls)
		}
		return true
	})
}

func recordSelector(selector *ast.SelectorExpr, selectors map[string]bool) {
	selectors[selector.Sel.Name] = true
	if identifier, ok := selector.X.(*ast.Ident); ok {
		selectors[identifier.Name+"."+selector.Sel.Name] = true
	}
}

func recordCall(call *ast.CallExpr, calls map[string]bool) {
	switch function := call.Fun.(type) {
	case *ast.Ident:
		calls[function.Name] = true
	case *ast.SelectorExpr:
		calls[function.Sel.Name] = true
		if identifier, ok := function.X.(*ast.Ident); ok {
			calls[identifier.Name+"."+function.Sel.Name] = true
		}
	}
}

func constantBool(expression ast.Expr, constants map[string]bool) (bool, bool) {
	switch value := expression.(type) {
	case *ast.Ident:
		if constants != nil {
			if constant, ok := constants[value.Name]; ok {
				return constant, true
			}
		}
		switch value.Name {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	case *ast.ParenExpr:
		return constantBool(value.X, constants)
	case *ast.UnaryExpr:
		if value.Op == token.NOT {
			inner, known := constantBool(value.X, constants)
			return !inner, known
		}
	}
	return false, false
}

func statementTerminates(node ast.Node, bindings reachabilityTerminators) bool {
	expression, ok := node.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expression.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch function := call.Fun.(type) {
	case *ast.Ident:
		if function.Name == "panic" {
			return true
		}
		if function.Obj != nil {
			return false
		}
		path, ok := bindings.functions[function.Name]
		return ok && ((path == "os" && function.Name == "Exit") || (path == "runtime" && function.Name == "Goexit"))
	case *ast.SelectorExpr:
		identifier, ok := function.X.(*ast.Ident)
		if !ok || identifier.Obj != nil {
			return false
		}
		path, ok := bindings.packages[identifier.Name]
		return ok && ((path == "os" && function.Sel.Name == "Exit") || (path == "runtime" && function.Sel.Name == "Goexit"))
	default:
		return false
	}
}

func terminatorBindingsForFile(fileBindings fileImportBindings) reachabilityTerminators {
	bindings := reachabilityTerminators{packages: make(map[string]string), functions: make(map[string]string)}
	for localName, binding := range fileBindings.named {
		if binding.path == "os" || binding.path == "runtime" {
			bindings.packages[localName] = binding.path
		}
	}
	for _, binding := range fileBindings.dots {
		if binding.path == "os" {
			bindings.functions["Exit"] = binding.path
		}
		if binding.path == "runtime" {
			bindings.functions["Goexit"] = binding.path
		}
	}
	return bindings
}

func packageBooleanConstants(packageAST astPackage) map[string]bool {
	constants := make(map[string]bool)
	for _, file := range sortedASTFiles(packageAST) {
		for _, declaration := range file.file.Decls {
			genDecl, ok := declaration.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.CONST {
				continue
			}
			for _, specification := range genDecl.Specs {
				valueSpec, ok := specification.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, name := range valueSpec.Names {
					if index >= len(valueSpec.Values) {
						continue
					}
					if value, known := constantBool(valueSpec.Values[index], constants); known {
						constants[name.Name] = value
					}
				}
			}
		}
	}
	return constants
}
