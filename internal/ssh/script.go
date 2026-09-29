package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	"ssm/internal/machinecontract"
)

// MaxScriptBytes is the largest stdin script accepted by the CLI.
const MaxScriptBytes = 16 << 20

// ScriptSpec is a validated script transported over SSH stdin.
type ScriptSpec struct {
	Label       string
	Body        string
	Interpreter string
	Args        []string
	// NonShell marks an explicitly requested non-shell interpreter (for
	// example python3). It reads the script from stdin as "<interp> - args".
	NonShell bool
	// Launcher is "env" or "/usr/bin/env" when the interpreter was requested
	// as "env <name>"; empty otherwise.
	Launcher string
}

// PrepareScript normalizes text generated on any platform and selects a
// predictable remote shell. The script body is never embedded in a command.
func PrepareScript(label string, data []byte, requestedShell string, args []string) (ScriptSpec, error) {
	return PrepareScriptWithInterpreter(label, data, requestedShell, "", args)
}

// PrepareScriptWithInterpreter is PrepareScript with an optional explicit
// interpreter. A non-empty interpreter is treated as user-confirmed and is not
// limited to the shell allowlist; it must be one program name or absolute path
// (optionally as "env <name>"). A bare allowlisted shell name behaves exactly
// like requestedShell. Setting both requestedShell and interpreter is an error.
func PrepareScriptWithInterpreter(label string, data []byte, requestedShell, interpreter string, args []string) (ScriptSpec, error) {
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

	spec := ScriptSpec{Body: body, Args: append([]string(nil), args...)}
	requestedShell = strings.TrimSpace(requestedShell)
	interpreter = strings.TrimSpace(interpreter)
	switch {
	case interpreter != "" && requestedShell != "" && requestedShell != interpreter:
		return ScriptSpec{}, fmt.Errorf("use only one of --shell and --interpreter")
	case interpreter == "":
		shell, err := ResolveScriptShell(body, requestedShell)
		if err != nil {
			return ScriptSpec{}, err
		}
		spec.Interpreter = shell
	default:
		parsed, err := ParseInterpreter(interpreter)
		if err != nil {
			return ScriptSpec{}, err
		}
		if parsed.Shell {
			// Detection for "auto" and validation of shell names stay in one place.
			request := parsed.Program
			if parsed.Program != "auto" && !isSupportedScriptShell(parsed.Program) {
				request = path.Base(parsed.Program)
			}
			shell, err := ResolveScriptShell(body, request)
			if err != nil {
				return ScriptSpec{}, err
			}
			if request != parsed.Program {
				shell = parsed.Program
			}
			spec.Interpreter = shell
		} else {
			spec.Interpreter = parsed.Program
			spec.Launcher = parsed.Launcher
			spec.NonShell = true
		}
	}
	if label == "" {
		label = "<stdin>"
	}
	spec.Label = label
	return spec, nil
}

// ParsedInterpreter is a validated --interpreter value.
type ParsedInterpreter struct {
	Program  string // program name or absolute path ("auto" for shell auto-detection)
	Launcher string // "env" or "/usr/bin/env" for the "env <name>" form
	Shell    bool   // program is an allowlisted shell (or "auto")
}

// ParseInterpreter validates an --interpreter value without any shell
// interpretation. Accepted forms: "auto", one program name, one absolute path,
// or "env <name>" / "/usr/bin/env <name>". Anything else is rejected so the
// value can never carry arguments or shell metacharacters.
func ParseInterpreter(value string) (ParsedInterpreter, error) {
	fields := strings.Fields(value)
	launcher := ""
	if len(fields) == 2 && (fields[0] == "env" || fields[0] == "/usr/bin/env") {
		launcher = fields[0]
		fields = fields[1:]
	}
	if len(fields) != 1 || strings.ContainsAny(value, "\x00\r\n\t") {
		return ParsedInterpreter{}, fmt.Errorf("invalid --interpreter %q: give one program name or absolute path, or \"env <name>\"; interpreter arguments are not supported", value)
	}
	program := fields[0]
	if program == "auto" && launcher == "" {
		return ParsedInterpreter{Program: "auto", Shell: true}, nil
	}
	if program == "auto" || !validInterpreterProgram(program) {
		return ParsedInterpreter{}, fmt.Errorf("invalid --interpreter %q: use a plain program name (letters, digits, _ . + -) or an absolute path without shell metacharacters", value)
	}
	if isSupportedScriptShell(path.Base(program)) {
		// "env bash" is just bash: shells read the script with -s, not "-".
		return ParsedInterpreter{Program: program, Shell: true}, nil
	}
	return ParsedInterpreter{Program: program, Launcher: launcher}, nil
}

func validInterpreterProgram(program string) bool {
	if program == "" || len(program) > 255 {
		return false
	}
	for _, r := range program {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '+' || r == '-' || r == '/':
		default:
			return false
		}
	}
	if strings.HasPrefix(program, "/") {
		if strings.HasSuffix(program, "/") {
			return false
		}
		for _, seg := range strings.Split(program, "/") {
			if seg == ".." {
				return false
			}
		}
		return true
	}
	return !strings.Contains(program, "/") && program[0] != '-' && program[0] != '.'
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
		suggest := "<program>"
		if validInterpreterProgram(name) && !strings.Contains(name, "/") {
			suggest = name
		}
		return "", fmt.Errorf("script shebang interpreter %q is not a supported shell (sh, bash, dash, ash, ksh, zsh); add --interpreter %s to run it with that interpreter", name, suggest)
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
	if spec.NonShell {
		// Convention for non-shell interpreters: "<interp> - args..." reads the
		// script from stdin (python3, perl, ruby).
		words = []string{spec.Interpreter, "-"}
		if spec.Launcher != "" {
			words = append([]string{spec.Launcher}, words...)
		}
	}
	words = append(words, spec.Args...)
	quoted := JoinRemoteArgv(words)
	name := ShellQuote(spec.Interpreter)
	marker := ShellQuote(machinecontract.InterpreterNotFoundDiagnostic(spec.Interpreter))
	return "command -v " + name + " >/dev/null 2>&1 || { printf '%s\\n' " + marker + " >&2; exit 127; }; exec " + quoted
}

// BuildScriptSyntaxRunner parses the same normalized stdin body with the same
// remote interpreter without executing it. The body remains on stdin and is
// sent again only when the caller proceeds with the real runner.
func BuildScriptSyntaxRunner(spec ScriptSpec) string {
	words := []string{spec.Interpreter, "-n", "-s", "--"}
	quoted := JoinRemoteArgv(words)
	name := ShellQuote(spec.Interpreter)
	marker := ShellQuote(machinecontract.InterpreterNotFoundDiagnostic(spec.Interpreter))
	return "command -v " + name + " >/dev/null 2>&1 || { printf '%s\\n' " + marker + " >&2; exit 127; }; exec " + quoted
}

// ScriptDigest identifies normalized script input without exposing its body.
func ScriptDigest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}
