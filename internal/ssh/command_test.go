package ssh

import "testing"

func TestShellQuote(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "''"},
		{"simple", "'simple'"},
		{"hello world", "'hello world'"},
		{"it's", "'it'\"'\"'s'"},
		{`a"b`, `'a"b'`},
	}
	for _, tt := range tests {
		if got := ShellQuote(tt.in); got != tt.want {
			t.Fatalf("ShellQuote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestJoinRemoteCommand(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
		raw   bool
		want  string
	}{
		{"empty", nil, false, ""},
		{"single passthrough", []string{`cd /tmp && echo "hi"`}, false, `cd /tmp && echo "hi"`},
		{"single with spaces", []string{"printf %s 'hello'"}, false, "printf %s 'hello'"},
		{"multi argv safe", []string{"bash", "-c", "echo hi"}, false, "'bash' '-c' 'echo hi'"},
		{"multi spaces in arg", []string{"echo", "hello world"}, false, "'echo' 'hello world'"},
		{"multi raw join", []string{"bash", "-c", "echo hi"}, true, "bash -c echo hi"},
		{"single raw same", []string{"echo hi"}, true, "echo hi"},
		{"empty arg preserved", []string{"printf", "%s", ""}, false, "'printf' '%s' ''"},
		{"env assign prefix", []string{"FOO=bar", "printenv", "FOO"}, false, "FOO='bar' 'printenv' 'FOO'"},
		{"env assign value spaces", []string{"FOO=hello world", "printenv", "FOO"}, false, "FOO='hello world' 'printenv' 'FOO'"},
		{"multi env", []string{"A=1", "B=2", "true"}, false, "A='1' B='2' 'true'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := JoinRemoteCommand(tt.parts, tt.raw)
			if got != tt.want {
				t.Fatalf("JoinRemoteCommand(%#v, raw=%v) = %q, want %q", tt.parts, tt.raw, got, tt.want)
			}
		})
	}
}

func TestJoinRemoteArgvAlwaysQuotesSingleArgument(t *testing.T) {
	if got := JoinRemoteArgv([]string{"hello world"}); got != "'hello world'" {
		t.Fatalf("JoinRemoteArgv = %q", got)
	}
}
