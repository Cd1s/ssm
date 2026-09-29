package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRemoteArgvStart(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{"empty", nil, 0},
		{"options only", []string{"--json", "--no-reuse", "-v"}, 3},
		{"first positional", []string{"df", "-h"}, 0},
		{"after options", []string{"--json", "df", "-h"}, 1},
		{"--argv", []string{"--json", "--argv", "df", "-h"}, 1},
		{"dash dash", []string{"--timeout", "5s", "--", "free", "-h"}, 2},
		{"option values are skipped", []string{"--timeout", "5s", "-e", "A=@f", "--secret", "B=@g", "-j", "2", "--parallel", "3", "--shell", "bash", "-f", "s.sh", "--file", "t.sh", "--scripts", "a,b", "--refresh", "5s", "df"}, 20},
		{"values that look like commands", []string{"--timeout", "df", "df", "-h"}, 2},
		{"single dash is positional", []string{"-", "x"}, 0},
		{"missing value at end", []string{"--timeout"}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := remoteArgvStart(test.args); got != test.want {
				t.Fatalf("remoteArgvStart(%q) = %d, want %d", test.args, got, test.want)
			}
		})
	}
}

// The option table used for boundary scanning must agree with the parser about
// which options consume a value, or the two rule sets drift.
func TestRunOptionTableMatchesParseRemoteRunArgs(t *testing.T) {
	for _, option := range []string{"--jobs", "-j", "--parallel", "--timeout", "--secret", "-e", "--shell", "--interpreter", "-f", "--file", "--scripts"} {
		if !runOptionTakesValue(option) {
			t.Fatalf("%s consumes a value in parseRemoteRunArgs but not in runOptionTakesValue", option)
		}
	}
	for _, option := range []string{"--json", "--raw", "--argv", "--trace", "-v", "--plan", "--dry-run", "--no-reuse", "--preflight", "--no-preflight", "-s", "--script", "--stream", "--offline", "-h", "--help"} {
		if runOptionTakesValue(option) {
			t.Fatalf("%s is a flag but runOptionTakesValue says it consumes a value", option)
		}
	}
	if !runOptionTakesValue("--refresh") {
		t.Fatal("--refresh consumes a value in stream mode")
	}
}

func TestParseRemoteRunArgsArgvIsABoundary(t *testing.T) {
	old := machineJSON
	t.Cleanup(func() { machineJSON = old })
	machineJSON = false

	spec, err := parseRemoteRunArgs([]string{"--argv", "echo", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.JSON || spec.Command != "'echo' '--json'" {
		t.Fatalf("spec = %+v", spec)
	}
	spec, err = parseRemoteRunArgs([]string{"--json", "--argv", "--timeout", "5", "sleep"})
	if err != nil {
		t.Fatal(err)
	}
	if !spec.JSON || spec.Timeout != 0 || spec.Command != "'--timeout' '5' 'sleep'" {
		t.Fatalf("spec = %+v", spec)
	}
	spec, err = parseRemoteRunArgs([]string{"--argv", "--", "df", "-h"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Command != "'df' '-h'" {
		t.Fatalf("legacy --argv -- form = %q", spec.Command)
	}
	if _, err := parseRemoteRunArgs([]string{"--help"}); err == nil || err.Error() != "help" {
		t.Fatalf("--help before the argv must stay a help request, err=%v", err)
	}
}

func TestHelpRequestStopsAtRemoteArgv(t *testing.T) {
	for _, test := range []struct {
		args []string
		help bool
	}{
		{[]string{"run", "--help"}, true},
		{[]string{"run", "-h"}, true},
		{[]string{"help", "run"}, true},
		{[]string{"run", "host", "--help"}, true},
		{[]string{"run", "host", "--timeout", "5s", "-h"}, true},
		{[]string{"run", "--json", "host", "-h"}, true},
		{[]string{"run", "host", "--argv", "df", "-h"}, false},
		{[]string{"run", "host", "--", "free", "-h"}, false},
		{[]string{"run", "host", "df", "-h"}, false},
		{[]string{"run", "host", "python3", "x.py", "--help"}, false},
		{[]string{"exec", "host", "--argv", "ls", "-h"}, false},
		{[]string{"plan", "host", "--argv", "du", "-h"}, false},
		{[]string{"plan", "host", "-h"}, true},
		{[]string{"map", "--help"}, true},
		{[]string{"map", "a,b", "--help"}, true},
		{[]string{"map", "a,b", "--argv", "df", "-h"}, false},
		{[]string{"map", "a", "-j", "2", "--", "sort", "-h"}, false},
		{[]string{"map", "a", "--scripts", "x.sh", "--", "--help"}, false},
		{[]string{"run", "host", "-f", "x.sh", "--", "--help"}, false},
		{[]string{"run", "host", "-s", "--", "-h"}, false},
		{[]string{"host", "add", "--help"}, true},
		{[]string{"push", "help"}, true},
		{[]string{"prod-alias", "df", "-h"}, false},
		{[]string{"prod-alias", "--argv", "df", "-h"}, false},
		{[]string{"prod-alias", "--help"}, true},
		{[]string{"server", "df", "-h"}, false}, // "server" is an alias in sshctl
	} {
		if _, _, got := sshctlHelpRequest(test.args); got != test.help {
			t.Errorf("sshctlHelpRequest(%q) help=%t, want %t", test.args, got, test.help)
		}
	}
	// In ssm the same names are real commands, so their help still works.
	if _, _, got := helpRequest(false, []string{"server", "--help"}); !got {
		t.Error("ssm server --help must be a help request")
	}
	if _, _, got := helpRequest(false, []string{"exec", "host", "--argv", "df", "-h"}); got {
		t.Error("ssm exec must not capture remote -h")
	}
}

func TestCommandHasJSONFlagStopsAtRemoteArgv(t *testing.T) {
	for _, test := range []struct {
		command string
		rest    []string
		want    bool
	}{
		{"run", []string{"host", "--json", "--argv", "echo"}, true},
		{"run", []string{"--json", "host", "--argv", "echo"}, true},
		{"run", []string{"host", "--argv", "echo", "--json"}, false},
		{"run", []string{"host", "--", "echo", "--json"}, false},
		{"run", []string{"host", "echo", "--json"}, false},
		{"exec", []string{"host", "--timeout", "5s", "--json", "echo"}, true},
		{"plan", []string{"host", "--argv", "echo", "--json"}, false},
		{"map", []string{"a,b", "-j", "2", "--json", "--argv", "echo"}, true},
		{"map", []string{"a", "--argv", "echo", "--json"}, false},
		{"map", []string{"a", "--scripts", "x.sh", "--", "--json"}, false},
		{"host", []string{"list", "--json"}, true},
		{"put", []string{"a", "b", "c", "--", "--json"}, false},
		{"alias", []string{"echo", "--json"}, false},
		{"alias", []string{"--json", "echo"}, true},
	} {
		if got := commandHasJSONFlag(true, test.command, test.rest); got != test.want {
			t.Errorf("commandHasJSONFlag(%q, %q) = %t, want %t", test.command, test.rest, got, test.want)
		}
	}
}

func TestStartupOutputModeRemoteArgvJSON(t *testing.T) {
	for _, test := range []struct {
		name       string
		executable string
		args       []string
		wantJSON   bool
	}{
		{"remote --json after --argv", "sshctl", []string{"run", "prod", "--argv", "echo", "--json"}, false},
		{"global json plus remote json", "sshctl", []string{"--json", "run", "prod", "--argv", "echo", "--json"}, true},
		{"command json before argv", "sshctl", []string{"run", "prod", "--json", "--argv", "echo"}, true},
		{"map remote json", "sshctl", []string{"map", "prod", "--argv", "echo", "--json"}, false},
		{"ssm exec remote json", "ssm", []string{"exec", "prod", "echo", "--json"}, false},
		{"ssm list json", "ssm", []string{"list", "--json"}, true},
		{"alias shorthand remote json", "sshctl", []string{"prod", "echo", "--json"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if gotJSON, _ := startupOutputMode(test.executable, test.args); gotJSON != test.wantJSON {
				t.Fatalf("startupOutputMode(%q, %q) json=%t, want %t", test.executable, test.args, gotJSON, test.wantJSON)
			}
		})
	}
}

func TestInformationalInvocationStopsAtRemoteArgv(t *testing.T) {
	for _, args := range [][]string{
		{"run", "host", "--argv", "df", "-h"},
		{"run", "host", "df", "-h"},
		{"exec", "host", "python3", "x.py", "--help"},
		{"map", "a", "--argv", "sort", "-h"},
		{"plan", "host", "--", "--help"},
		{"--json", "run", "host", "--argv", "free", "-h"},
	} {
		if isInformationalInvocation(args) || isInformationalInvocationFor(true, args) {
			t.Errorf("remote flag in %q must not skip the update policy", args)
		}
	}
	for _, args := range [][]string{
		{"run", "--help"}, {"run", "host", "--help"}, {"help", "run"}, {"pull", "--help"},
		{"--offline", "push", "-h"}, {"--master-pass-file", "x", "--help"},
	} {
		if !isInformationalInvocation(args) {
			t.Errorf("isInformationalInvocation(%q) = false", args)
		}
	}
}

func TestSplitMapTargets(t *testing.T) {
	targets, rest := splitMapTargets([]string{"a,b", "web-*", "-j", "2", "--argv", "df"})
	if !reflect.DeepEqual(targets, []string{"a,b", "web-*"}) || !reflect.DeepEqual(rest, []string{"-j", "2", "--argv", "df"}) {
		t.Fatalf("targets=%q rest=%q", targets, rest)
	}
}

func TestDefaultMasterPassFileIfPresent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SSM_CONFIG_DIR", dir)
	if got := defaultMasterPassFileIfPresent(); got != "" {
		t.Fatalf("absent master.pass returned %q", got)
	}
	path := filepath.Join(dir, "master.pass")
	if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := defaultMasterPassFileIfPresent(); got != path {
		t.Fatalf("present master.pass returned %q, want %q", got, path)
	}
}
