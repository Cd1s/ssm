package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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

type astPackage struct {
	files map[string]*ast.File
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
	// Calls in this table are transport/persistence policy decisions. The
	// command may invoke the owning module, but may not recreate these choices
	// against the mechanism directly.
	forbidden := map[string]map[string]bool{
		"cloud": {
			"RemoteETag":        true,
			"InspectRemoteBlob": true,
			"Pull":              true,
			"PullIfChanged":     true,
			"PushBlob":          true,
			"PushBlobObserved":  true,
		},
		"json": {
			"NewEncoder":    true,
			"MarshalIndent": true,
		},
	}
	for fileName, file := range packageAST.files {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok || !forbidden[identifier.Name][selector.Sel.Name] {
				return true
			}
			t.Errorf("cmd/ssm/%s makes %s.%s policy decision; invoke its owning module instead", fileName, identifier.Name, selector.Sel.Name)
			return true
		})
	}
}

func assertNoDuplicatePolicyDeclarations(t *testing.T, packageAST astPackage) {
	t.Helper()
	// These helpers were the former command-owned policy seams. Parsing and
	// success shaping remain explicitly allowed; refresh/redaction policy does
	// not. The initial RED intentionally reports the residue still present on
	// the pre-contraction base.
	forbidden := map[string]bool{
		"pullIfChanged":               true,
		"refreshVaultIfChanged":       true,
		"refreshVaultIfChangedResult": true,
		"refreshHostVault":            true,
		"redactError":                 true,
		"redactString":                true,
	}
	for fileName, file := range packageAST.files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || !forbidden[function.Name.Name] {
				continue
			}
			t.Errorf("cmd/ssm/%s retains duplicate policy helper %q", fileName, function.Name.Name)
		}
	}
}

type policyPath struct {
	function string
	calls    []string
	branch   bool
}

func assertMachineContractDepth(t *testing.T, packageAST astPackage) {
	t.Helper()
	assertPolicyPaths(t, packageAST, "machine contract", []policyPath{
		{function: "Classify", calls: []string{"RedactString"}, branch: true},
		{function: "ClassifySSH", calls: []string{"Classify"}, branch: true},
		{function: "Render", calls: []string{"render"}},
		{function: "WriteFailure", calls: []string{"WriteFailureJSON", "WriteHuman", "ProcessExit"}},
		{function: "RedactString", calls: []string{"redactAssignmentValues", "redactStructuredValues"}},
		{function: "ProcessExit", branch: true},
	})
}

func assertSyncTransactionDepth(t *testing.T, packageAST astPackage) {
	t.Helper()
	assertPolicyPaths(t, packageAST, "sync transaction", []policyPath{
		{function: "configuration", calls: []string{"ReadFile", "json.Unmarshal"}},
		{function: "refreshConfigured", calls: []string{"RemoteETag", "Pull", "commitSuccess"}},
		{function: "PreparePublication", calls: []string{"InspectRemoteBlob", "preserveConflict"}},
		{function: "SendPublication", calls: []string{"ObservePublicationIdentity", "PushBlobObserved"}},
		{function: "Facts", calls: []string{"configuration", "localFacts"}},
		{function: "Initialize", calls: []string{"refresh"}, branch: true},
		{function: "BeforeLine", calls: []string{"refresh"}, branch: true},
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
	functions := packageFunctions(packageAST)
	for _, path := range paths {
		declaration := functions[path.function]
		if declaration == nil || declaration.Body == nil {
			t.Errorf("%s is missing concrete policy function %q", owner, path.function)
			continue
		}
		calls := callNames(declaration.Body)
		for _, wanted := range path.calls {
			if !calls[wanted] && !calls[strings.TrimPrefix(wanted, "config.")] {
				t.Errorf("%s function %q does not own policy path through %q", owner, path.function, wanted)
			}
		}
		branches := 0
		ast.Inspect(declaration.Body, func(node ast.Node) bool {
			switch node.(type) {
			case *ast.IfStmt, *ast.SwitchStmt, *ast.ForStmt, *ast.RangeStmt:
				branches++
			}
			return true
		})
		if path.branch && branches == 0 {
			t.Errorf("%s function %q has no policy decision branch", owner, path.function)
		}
	}
}

func packageFunctions(packageAST astPackage) map[string]*ast.FuncDecl {
	functions := make(map[string]*ast.FuncDecl)
	for _, file := range packageAST.files {
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				functions[function.Name.Name] = function
			}
		}
	}
	return functions
}

func callNames(root ast.Node) map[string]bool {
	calls := make(map[string]bool)
	ast.Inspect(root, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch function := call.Fun.(type) {
		case *ast.Ident:
			calls[function.Name] = true
		case *ast.SelectorExpr:
			calls[function.Sel.Name] = true
			if identifier, ok := function.X.(*ast.Ident); ok {
				calls[identifier.Name+"."+function.Sel.Name] = true
			}
		}
		return true
	})
	return calls
}
