package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeInterpreterTestScript(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseRemoteRunArgsInterpreterPython(t *testing.T) {
	path := writeInterpreterTestScript(t, "t.py", "import sys\nprint(sys.argv[1:])\n")
	for _, form := range [][]string{
		{"-f", path, "--interpreter", "python3", "--", "a", "b"},
		{"--interpreter=python3", "-f", path, "--", "a", "b"},
	} {
		spec, err := parseRemoteRunArgs(form)
		if err != nil {
			t.Fatal(err)
		}
		if len(spec.Scripts) != 1 || spec.Preflight {
			t.Fatalf("spec = %+v", spec)
		}
		script := spec.Scripts[0]
		if !script.NonShell || script.Interpreter != "python3" || strings.Join(script.Args, ",") != "a,b" {
			t.Fatalf("script = %+v", script)
		}
	}
}

func TestParseRemoteRunArgsInterpreterBashStillWorks(t *testing.T) {
	path := writeInterpreterTestScript(t, "t.sh", "echo hi\n")
	spec, err := parseRemoteRunArgs([]string{"--interpreter", "bash", "-f", path, "--preflight"})
	if err != nil {
		t.Fatal(err)
	}
	if script := spec.Scripts[0]; script.NonShell || script.Interpreter != "bash" || !spec.Preflight {
		t.Fatalf("spec = %+v", spec)
	}
}

func TestParseRemoteRunArgsInterpreterRejections(t *testing.T) {
	path := writeInterpreterTestScript(t, "t.py", "print(1)\n")
	for _, test := range []struct {
		name string
		args []string
	}{
		{"preflight with non-shell", []string{"-f", path, "--interpreter", "python3", "--preflight"}},
		{"flags in value", []string{"-f", path, "--interpreter", "python3 -u"}},
		{"metacharacters", []string{"-f", path, "--interpreter", "python3;id"}},
		{"shell and interpreter", []string{"-f", path, "--shell", "bash", "--interpreter", "python3"}},
		{"shell flag stays shell", []string{"-f", path, "--shell", "python3"}},
		{"missing value", []string{"-f", path, "--interpreter"}},
		{"interpreter without a script", []string{"--interpreter", "python3", "hostname"}},
	} {
		if _, err := parseRemoteRunArgs(test.args); err == nil {
			t.Errorf("%s: accepted %v", test.name, test.args)
		}
	}
}

func TestParseRemoteRunArgsNonShellShebangNeedsInterpreter(t *testing.T) {
	path := writeInterpreterTestScript(t, "t.py", "#!/usr/bin/env python3\nprint(1)\n")
	_, err := parseRemoteRunArgs([]string{"-f", path})
	if err == nil || !strings.Contains(err.Error(), "--interpreter python3") {
		t.Fatalf("err = %v", err)
	}
	spec, err := parseRemoteRunArgs([]string{"-f", path, "--interpreter", "python3"})
	if err != nil || !spec.Scripts[0].NonShell {
		t.Fatalf("spec = %+v err = %v", spec, err)
	}
}

func TestRequestInterpreter(t *testing.T) {
	path := writeInterpreterTestScript(t, "t.py", "print(1)\n")
	spec, err := requestRunSpec(agentRequest{Version: 1, Op: "run", Alias: "prod", ScriptFile: path, Interpreter: "python3", ScriptArgs: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Preflight || !spec.Scripts[0].NonShell || spec.Scripts[0].Interpreter != "python3" {
		t.Fatalf("spec = %+v", spec)
	}
	yes, no := true, false
	if _, err := requestRunSpec(agentRequest{Version: 1, Op: "run", Alias: "prod", ScriptFile: path, Interpreter: "python3", Preflight: &yes}); err == nil {
		t.Fatal("preflight:true with a non-shell interpreter must be rejected")
	}
	if _, err := requestRunSpec(agentRequest{Version: 1, Op: "run", Alias: "prod", ScriptFile: path, Interpreter: "python3", Preflight: &no}); err != nil {
		t.Fatal(err)
	}
	for _, req := range []agentRequest{
		{Version: 1, Op: "run", Alias: "prod", ScriptFile: path, Interpreter: "python3 -u"},
		{Version: 1, Op: "run", Alias: "prod", ScriptFile: path, Interpreter: "python3", Shell: "bash"},
		{Version: 1, Op: "run", Alias: "prod", Argv: []string{"true"}, Interpreter: "python3"},
	} {
		if _, err := requestRunSpec(req); err == nil {
			t.Fatalf("accepted %+v", req)
		}
	}
	bash, err := requestRunSpec(agentRequest{Version: 1, Op: "run", Alias: "prod", ScriptFile: path, Interpreter: "bash"})
	if err != nil || !bash.Preflight || bash.Scripts[0].NonShell {
		t.Fatalf("bash alias spec = %+v err = %v", bash, err)
	}
}
