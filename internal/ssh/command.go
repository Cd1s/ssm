package ssh

import (
	"os"
	"strings"
)

// TraceEnabled reports whether remote-command tracing is on via env.
// Agents can set SSM_TRACE=1 to see the exact remote shell line (quote debug).
func TraceEnabled() bool {
	return traceEnabled()
}

func traceEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SSM_TRACE")))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ShellQuote returns a single-quoted POSIX shell word that expands to s.
// Empty strings become '' so they remain a distinct argument.
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// isEnvAssign reports whether s looks like NAME=value for a POSIX shell
// environment assignment (leading unquoted form on a remote command line).
func isEnvAssign(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	name := s[:eq]
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// formatEnvAssign renders NAME=value so the remote shell applies it as an
// assignment. Values are shell-quoted so spaces/metacharacters are safe.
func formatEnvAssign(s string) string {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return ShellQuote(s)
	}
	return s[:eq] + "=" + ShellQuote(s[eq+1:])
}

// JoinRemoteCommand builds a remote shell command line from argv parts.
//
//   - 1 part: returned as-is so full shell scripts keep working
//     (e.g. "cd /tmp && echo hi" or "printf %s 'quoted'").
//   - 2+ parts: each part is shell-quoted then joined with spaces so spaces
//     and special characters in individual argv elements survive remote
//     re-parsing (agent-friendly: sshctl run host bash -c 'echo hi').
//   - Leading NAME=value tokens are kept as env assignments (value quoted)
//     so `sshctl run host FOO=bar printenv FOO` works without --raw.
//   - raw=true: always join with a single space and never quote (OpenSSH-style).
func JoinRemoteCommand(parts []string, raw bool) string {
	if len(parts) == 0 {
		return ""
	}
	if raw || len(parts) == 1 {
		return strings.Join(parts, " ")
	}

	// Collect leading env assignments (must leave at least one command word).
	envEnd := 0
	for envEnd < len(parts)-1 && isEnvAssign(parts[envEnd]) {
		envEnd++
	}

	out := make([]string, 0, len(parts))
	for i, p := range parts {
		if i < envEnd {
			out = append(out, formatEnvAssign(p))
			continue
		}
		out = append(out, ShellQuote(p))
	}
	return strings.Join(out, " ")
}

// RemoteParentDir returns the POSIX parent directory of remotePath for mkdir -p.
// Trailing slashes are trimmed. Root and empty parents yield "".
func RemoteParentDir(remotePath string) string {
	p := strings.TrimRight(remotePath, "/")
	if p == "" || p == "." {
		return ""
	}
	idx := strings.LastIndex(p, "/")
	if idx < 0 {
		return ""
	}
	if idx == 0 {
		return "/"
	}
	return p[:idx]
}
