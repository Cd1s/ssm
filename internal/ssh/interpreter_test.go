package ssh

import (
	"strings"
	"testing"
)

func TestParseInterpreterAcceptsOnlyPlainProgramForms(t *testing.T) {
	for _, test := range []struct {
		value    string
		program  string
		launcher string
		shell    bool
	}{
		{value: "python3", program: "python3"},
		{value: "/usr/bin/python3.12", program: "/usr/bin/python3.12"},
		{value: "env python3", program: "python3", launcher: "env"},
		{value: "/usr/bin/env perl", program: "perl", launcher: "/usr/bin/env"},
		{value: "bash", program: "bash", shell: true},
		{value: "/bin/zsh", program: "/bin/zsh", shell: true},
		{value: "env bash", program: "bash", shell: true},
		{value: "auto", program: "auto", shell: true},
	} {
		got, err := ParseInterpreter(test.value)
		if err != nil {
			t.Fatalf("%q: %v", test.value, err)
		}
		if got.Program != test.program || got.Launcher != test.launcher || got.Shell != test.shell {
			t.Errorf("%q = %+v", test.value, got)
		}
	}
	for _, value := range []string{
		"", "python3 -u", "python3; id", "$(id)", "`id`", "py thon", "python3\nid", "-python3",
		".hidden", "a/b", "/usr/../bin/python3", "/usr/bin/", "env python3 -u", "env -i python3",
		"python3|cat", "python3&", "python3>x", "'python3'", "\"python3\"", "py*", "env auto", "/usr/bin/env  /a/b c",
	} {
		if _, err := ParseInterpreter(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

func TestPrepareScriptWithInterpreterNonShell(t *testing.T) {
	script, err := PrepareScriptWithInterpreter("t.py", []byte("\xef\xbb\xbfimport sys\r\nprint(sys.argv[1:])\r\n"), "", "python3", []string{"a b", "it's"})
	if err != nil {
		t.Fatal(err)
	}
	if !script.NonShell || script.Interpreter != "python3" || script.Launcher != "" {
		t.Fatalf("script = %+v", script)
	}
	if strings.Contains(script.Body, "\r") || strings.HasPrefix(script.Body, "\xef\xbb\xbf") {
		t.Fatalf("body not normalized: %q", script.Body)
	}
	runner := BuildScriptRunner(script)
	want := "command -v 'python3' >/dev/null 2>&1 || "
	if !strings.HasPrefix(runner, want) || !strings.HasSuffix(runner, "exec 'python3' '-' 'a b' 'it'\"'\"'s'") {
		t.Fatalf("runner = %s", runner)
	}
	if strings.Contains(runner, "print(") {
		t.Fatalf("script body leaked into command: %s", runner)
	}
}

func TestPrepareScriptWithInterpreterEnvForm(t *testing.T) {
	script, err := PrepareScriptWithInterpreter("t.py", []byte("print(1)\n"), "", "/usr/bin/env python3", nil)
	if err != nil {
		t.Fatal(err)
	}
	runner := BuildScriptRunner(script)
	if !strings.Contains(runner, "command -v 'python3'") || !strings.HasSuffix(runner, "exec '/usr/bin/env' 'python3' '-'") {
		t.Fatalf("runner = %s", runner)
	}
}

func TestPrepareScriptWithInterpreterShellAliasKeepsShellSemantics(t *testing.T) {
	script, err := PrepareScriptWithInterpreter("t.sh", []byte("echo hi\n"), "", "bash", []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	if script.NonShell || script.Interpreter != "bash" || !strings.HasSuffix(BuildScriptRunner(script), "exec 'bash' '-s' '--' 'x'") {
		t.Fatalf("script = %+v runner = %s", script, BuildScriptRunner(script))
	}
	auto, err := PrepareScriptWithInterpreter("t.sh", []byte("#!/bin/bash\necho hi\n"), "", "auto", nil)
	if err != nil || auto.Interpreter != "bash" || auto.NonShell {
		t.Fatalf("auto = %+v err=%v", auto, err)
	}
	abs, err := PrepareScriptWithInterpreter("t.sh", []byte("echo hi\n"), "", "/bin/bash", nil)
	if err != nil || abs.Interpreter != "/bin/bash" || abs.NonShell || !strings.HasSuffix(BuildScriptRunner(abs), "exec '/bin/bash' '-s' '--'") {
		t.Fatalf("abs = %+v err=%v", abs, err)
	}
}

func TestPrepareScriptWithInterpreterExplicitBeatsShebangAndRejectsConflicts(t *testing.T) {
	script, err := PrepareScriptWithInterpreter("t", []byte("#!/bin/bash\nprint(1)\n"), "", "python3", nil)
	if err != nil || script.Interpreter != "python3" || !script.NonShell {
		t.Fatalf("script = %+v err=%v", script, err)
	}
	if _, err := PrepareScriptWithInterpreter("t", []byte("true\n"), "bash", "python3", nil); err == nil {
		t.Fatal("--shell and --interpreter together must conflict")
	}
	if _, err := PrepareScriptWithInterpreter("t", []byte("true\n"), "bash", "bash", nil); err != nil {
		t.Fatalf("identical --shell/--interpreter must be accepted: %v", err)
	}
	if _, err := PrepareScriptWithInterpreter("t", []byte("true\n"), "", "python3 -u", nil); err == nil {
		t.Fatal("interpreter arguments must be rejected")
	}
}

func TestShellFlagStaysShellOnly(t *testing.T) {
	if _, err := PrepareScript("t", []byte("print(1)\n"), "python3", nil); err == nil {
		t.Fatal("--shell python3 must stay rejected")
	}
}

func TestShebangHonoredAndNonShellShebangHintsInterpreter(t *testing.T) {
	for shebang, want := range map[string]string{
		"#!/bin/bash":          "bash",
		"#!/usr/bin/env bash":  "bash",
		"#!/usr/bin/env -S sh": "sh",
		"#!/bin/zsh -e":        "zsh",
	} {
		script, err := PrepareScript("t", []byte(shebang+"\r\ntrue\r\n"), "", nil)
		if err != nil || script.Interpreter != want || script.NonShell {
			t.Errorf("%s -> %+v err=%v", shebang, script, err)
		}
	}
	noShebang, err := PrepareScript("t", []byte("true\n"), "", nil)
	if err != nil || noShebang.Interpreter != "sh" {
		t.Fatalf("no shebang default = %+v err=%v", noShebang, err)
	}
	_, err = PrepareScript("t", []byte("\xef\xbb\xbf#!/usr/bin/env python3\r\nprint(1)\r\n"), "", nil)
	if err == nil || !strings.Contains(err.Error(), "--interpreter python3") {
		t.Fatalf("err = %v", err)
	}
	_, err = PrepareScript("t", []byte("#!/opt/x/we$ird\n"), "", nil)
	if err == nil || !strings.Contains(err.Error(), "--interpreter <program>") {
		t.Fatalf("err = %v", err)
	}
}
