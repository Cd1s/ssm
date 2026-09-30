package main

import (
	"strings"
	"testing"
)

// ssm update accepts exactly --major and --yes, and --yes authorizes nothing
// on its own. These checks run the compiled binary, but never reach the
// network: argument errors are reported before any release lookup.
func TestCompiledUpdateArgumentsRejectUnauthorizedForms(t *testing.T) {
	cli := newCompiledCLIHarness(t)
	for name, args := range map[string][]string{
		"--yes without --major": {"update", "--yes"},
		"unknown option":        {"update", "--majr"},
		"--json --yes":          {"--json", "update", "--yes"},
	} {
		t.Run(name, func(t *testing.T) {
			result := cli.Run(t, "ssm", nil, args...)
			if result.ProcessExit == 0 {
				t.Fatalf("ssm %s succeeded: %s", strings.Join(args, " "), compiledOutputIdentity(result))
			}
			output := result.Stdout + result.Stderr
			want := "--yes is valid only with update --major"
			if strings.Contains(strings.Join(args, " "), "--majr") {
				want = `unknown update option "--majr"`
			}
			if !strings.Contains(output, want) {
				t.Fatalf("ssm %s output lacks %q: %s", strings.Join(args, " "), want, compiledOutputIdentity(result))
			}
		})
	}
}

func TestSSMUpdateHelpDescribesMajorAndYes(t *testing.T) {
	out := captureHelpOutput(t, func() { ssmCommandUsage("update", nil) })
	for _, want := range []string{"--major", "--yes", "Digest and provenance verification are never bypassed"} {
		if !strings.Contains(out, want) {
			t.Errorf("ssm update --help lacks %q: %q", want, out)
		}
	}
}
