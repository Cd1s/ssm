package ssh

import "strings"

// ShellQuote returns a single-quoted POSIX shell word that expands to s.
// Empty strings become '' so they remain a distinct argument.
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// JoinRemoteCommand builds a remote shell command line from argv parts.
//
//   - 1 part: returned as-is so full shell scripts keep working
//     (e.g. "cd /tmp && echo hi" or "printf %s 'quoted'").
//   - 2+ parts: each part is shell-quoted then joined with spaces so spaces
//     and special characters in individual argv elements survive remote
//     re-parsing (agent-friendly: sshctl run host bash -c 'echo hi').
//   - raw=true: always join with a single space and never quote (OpenSSH-style).
func JoinRemoteCommand(parts []string, raw bool) string {
	if len(parts) == 0 {
		return ""
	}
	if raw || len(parts) == 1 {
		return strings.Join(parts, " ")
	}
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = ShellQuote(p)
	}
	return strings.Join(quoted, " ")
}
