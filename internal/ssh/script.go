package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
)

// MaxScriptBytes is the largest stdin script accepted by the CLI.
const MaxScriptBytes = 16 << 20

// ScriptSpec is a validated script transported over SSH stdin.
type ScriptSpec struct {
	Label       string
	Body        string
	Interpreter string
	Args        []string
}

// PrepareScript normalizes text generated on any platform and selects a
// predictable remote shell. The script body is never embedded in a command.
func PrepareScript(label string, data []byte, requestedShell string, args []string) (ScriptSpec, error) {
	if len(data) > MaxScriptBytes {
		return ScriptSpec{}, fmt.Errorf("script exceeds %d bytes", MaxScriptBytes)
	}
	if len(data) >= 3 && string(data[:3]) == "\xef\xbb\xbf" {
		data = data[3:]
	}
	if strings.IndexByte(string(data), 0) >= 0 {
		return ScriptSpec{}, fmt.Errorf("script contains a NUL byte")
	}
	body := strings.ReplaceAll(string(data), "\r\n", "\n")
	body = strings.ReplaceAll(body, "\r", "\n")
	if strings.TrimSpace(body) == "" {
		return ScriptSpec{}, fmt.Errorf("script is empty")
	}
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	for _, arg := range args {
		if strings.IndexByte(arg, 0) >= 0 {
			return ScriptSpec{}, fmt.Errorf("script argument contains a NUL byte")
		}
	}

	interpreter, err := ResolveScriptShell(body, requestedShell)
	if err != nil {
		return ScriptSpec{}, err
	}
	if label == "" {
		label = "<stdin>"
	}
	return ScriptSpec{
		Label:       label,
		Body:        body,
		Interpreter: interpreter,
		Args:        append([]string(nil), args...),
	}, nil
}

// ResolveScriptShell accepts a small shell allowlist so the generated runner
// cannot become a second command-injection surface.
func ResolveScriptShell(body, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested != "" && requested != "auto" {
		if !isSupportedScriptShell(requested) {
			return "", fmt.Errorf("unsupported --shell %q (use auto, sh, bash, dash, ash, ksh, or zsh)", requested)
		}
		return requested, nil
	}

	firstLine := body
	if i := strings.IndexByte(firstLine, '\n'); i >= 0 {
		firstLine = firstLine[:i]
	}
	if !strings.HasPrefix(firstLine, "#!") {
		return "sh", nil
	}
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(firstLine, "#!")))
	if len(fields) == 0 {
		return "sh", nil
	}
	name := path.Base(fields[0])
	if name == "env" {
		fields = fields[1:]
		for len(fields) > 0 && strings.HasPrefix(fields[0], "-") {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			return "", fmt.Errorf("script shebang does not name an interpreter")
		}
		name = path.Base(fields[0])
	}
	if !isSupportedScriptShell(name) {
		return "", fmt.Errorf("unsupported script shebang interpreter %q; -s/-f accepts shell scripts only", name)
	}
	return name, nil
}

func isSupportedScriptShell(shell string) bool {
	switch shell {
	case "sh", "bash", "dash", "ash", "ksh", "zsh":
		return true
	default:
		return false
	}
}

// BuildScriptRunner returns the only command text sent in an SSH exec request.
// The generated script itself is supplied through stdin.
func BuildScriptRunner(spec ScriptSpec) string {
	words := []string{spec.Interpreter, "-s", "--"}
	words = append(words, spec.Args...)
	quoted := JoinRemoteArgv(words)
	name := ShellQuote(spec.Interpreter)
	marker := ShellQuote("ssm: error=interpreter_not_found interpreter=" + spec.Interpreter)
	return "command -v " + name + " >/dev/null 2>&1 || { printf '%s\\n' " + marker + " >&2; exit 127; }; exec " + quoted
}

// ScriptDigest identifies normalized script input without exposing its body.
func ScriptDigest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}
