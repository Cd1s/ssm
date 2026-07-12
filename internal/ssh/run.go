package ssh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"ssm/internal/config"
)

var (
	syntaxLinePattern      = regexp.MustCompile(`(?i)\bline[ :]+([0-9]+)\b`)
	syntaxColonLinePattern = regexp.MustCompile(`(?m)^[^:\n]+:\s*([0-9]+):`)
)

// RunOptions controls a single remote command invocation.
type RunOptions struct {
	Command     string
	Input       string            // script body transported over SSH stdin
	RiskCommand string            // script body used only for local risk assessment
	Secrets     map[string]string // NAME -> value; injected as remote env assigns
	Capture     bool              // capture stdout/stderr into RunResult
	PlanOnly    bool              // do not dial/run
	NoReuse     bool
	Interpreter string
	ScriptLabel string
	Mode        string
	// RequestedAlias is the name the user typed (before redirects).
	RequestedAlias string
	ResolvedAlias  string
}

// RunResult is the structured result of a remote run (agent JSON schema).
type RunResult struct {
	OK            bool   `json:"ok"`
	Alias         string `json:"alias"`
	ResolvedAlias string `json:"resolved_alias,omitempty"`
	User          string `json:"user,omitempty"`
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port,omitempty"`
	Exit          int    `json:"exit"`
	Stdout        string `json:"stdout,omitempty"`
	Stderr        string `json:"stderr,omitempty"`
	LatencyMS     int64  `json:"latency_ms,omitempty"`
	RemoteCommand string `json:"remote_command,omitempty"` // secrets redacted
	Error         string `json:"error,omitempty"`
	Message       string `json:"message,omitempty"`
	Hint          string `json:"hint,omitempty"`
	Stage         string `json:"stage,omitempty"`
	Plan          bool   `json:"plan,omitempty"`
	Risk          string `json:"risk,omitempty"`
	ScriptLabel   string `json:"script,omitempty"` // multi-script map label
	Interpreter   string `json:"interpreter,omitempty"`
	InputBytes    int    `json:"stdin_bytes,omitempty"`
	ScriptSHA256  string `json:"script_sha256,omitempty"`
	Mode          string `json:"mode,omitempty"`
	Transport     string `json:"transport,omitempty"`
	Preflight     string `json:"preflight,omitempty"`
}

// BuildRemoteCommand injects secret env assigns before the user command.
func BuildRemoteCommand(cmd string, secrets map[string]string) string {
	if len(secrets) == 0 {
		return cmd
	}
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if !isEnvName(k) {
			continue
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(ShellQuote(secrets[k]))
		b.WriteByte(' ')
	}
	b.WriteString(cmd)
	return b.String()
}

// BuildScriptRemoteCommand exports secrets before the fixed stdin runner. A
// plain NAME=value prefix would apply only to the runner's first simple command
// and could be lost before exec starts the script interpreter.
func BuildScriptRemoteCommand(cmd string, secrets map[string]string) string {
	if len(secrets) == 0 {
		return cmd
	}
	keys := make([]string, 0, len(secrets))
	for key := range secrets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		if !isEnvName(key) {
			continue
		}
		b.WriteString("export ")
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(ShellQuote(secrets[key]))
		b.WriteString("; ")
	}
	b.WriteString(cmd)
	return b.String()
}

func isEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// ValidEnvName reports whether a name is safe as a POSIX environment variable.
func ValidEnvName(s string) bool { return isEnvName(s) }

// RedactSecrets replaces secret values in a display string with *** .
func RedactSecrets(s string, secrets map[string]string) string {
	if s == "" || len(secrets) == 0 {
		return s
	}
	out := s
	// Longer values first to avoid partial overlaps.
	type kv struct{ k, v string }
	var list []kv
	for k, v := range secrets {
		if v != "" {
			list = append(list, kv{k, v})
		}
	}
	sort.Slice(list, func(i, j int) bool { return len(list[i].v) > len(list[j].v) })
	for _, e := range list {
		out = strings.ReplaceAll(out, ShellQuote(e.v), "'***'")
		if len(e.v) >= 4 {
			out = strings.ReplaceAll(out, e.v, "***")
		}
	}
	return out
}

// AssessRisk returns a coarse risk tag for plan mode.
func AssessRisk(cmd string) string {
	low := strings.ToLower(cmd)
	dangerous := []string{
		"rm -rf /", "mkfs", "dd if=", "shutdown", "reboot", "poweroff",
		"userdel", "passwd ", "> /dev/sd", "curl | sh", "curl|sh", "wget | sh",
	}
	for _, d := range dangerous {
		if strings.Contains(low, d) {
			return "high"
		}
	}
	if strings.Contains(low, "rm ") || strings.Contains(low, "dd ") ||
		strings.Contains(low, "chmod 777") || strings.Contains(low, "iptables") {
		return "medium"
	}
	return "low"
}

// Run executes a remote command according to opts.
func Run(c config.Connection, v *config.Vault, opts RunOptions) RunResult {
	port := c.Port
	if port == 0 {
		port = 22
	}
	full := BuildRemoteCommand(opts.Command, opts.Secrets)
	if opts.Input != "" || opts.Mode == "shell_command" {
		full = BuildScriptRemoteCommand(opts.Command, opts.Secrets)
	}
	display := RedactSecrets(full, opts.Secrets)
	riskCommand := opts.Command
	if opts.RiskCommand != "" {
		riskCommand = opts.RiskCommand
	}
	res := RunResult{
		Alias:         opts.RequestedAlias,
		ResolvedAlias: opts.ResolvedAlias,
		User:          c.User,
		Host:          c.Host,
		Port:          port,
		RemoteCommand: display,
		Risk:          AssessRisk(riskCommand),
		ScriptLabel:   opts.ScriptLabel,
		Interpreter:   opts.Interpreter,
		Mode:          opts.Mode,
		Transport:     "ssh_exec",
	}
	if res.Mode == "" {
		res.Mode = "shell_command"
	}
	if opts.Input != "" {
		res.InputBytes = len(opts.Input)
		res.ScriptSHA256 = ScriptDigest(opts.Input)
		res.Mode = "script"
		res.Transport = "ssh_stdin"
	}
	if res.Alias == "" {
		res.Alias = c.Name
	}
	if res.ResolvedAlias == "" {
		res.ResolvedAlias = c.Name
	}

	if traceEnabled() {
		fmt.Fprintf(os.Stderr, "ssm: remote command: %s\n", display)
		if res.ScriptSHA256 != "" {
			fmt.Fprintf(os.Stderr, "ssm: script stdin: bytes=%d sha256=%s interpreter=%s\n", res.InputBytes, res.ScriptSHA256, res.Interpreter)
		}
	}

	if opts.PlanOnly {
		res.OK = true
		res.Plan = true
		res.Exit = 0
		return res
	}

	start := time.Now()
	client, err := dialSSHOpts(c, v, opts.NoReuse)
	if err != nil {
		ce := ClassifyError(err, c)
		res.OK = false
		res.Exit = ExitConnectionFailed
		res.Error = ce.Code
		res.Message = ce.Error()
		res.Hint = ce.Hint
		res.Stage = "dial"
		res.LatencyMS = time.Since(start).Milliseconds()
		if !opts.Capture {
			PrintAgentError(err, c)
		}
		return res
	}
	defer releaseClient(client, opts.NoReuse)

	session, err := client.NewSession()
	if err != nil {
		ce := ClassifyError(err, c)
		res.OK = false
		res.Exit = ExitConnectionFailed
		res.Error = ce.Code
		if res.Error == ErrCodeInternal {
			res.Error = ErrCodeSession
		}
		res.Hint = ce.Hint
		res.Message = ce.Error()
		res.Stage = "session"
		res.LatencyMS = time.Since(start).Milliseconds()
		if !opts.Capture {
			PrintAgentError(err, c)
		}
		return res
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	if opts.Capture {
		session.Stdout = &stdoutBuf
		session.Stderr = &stderrBuf
	} else {
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
	}
	if opts.Input != "" {
		session.Stdin = strings.NewReader(opts.Input)
	} else if !opts.Capture {
		stdinIsTTY := term.IsTerminal(int(os.Stdin.Fd()))
		if os.Getenv("SSM_FORWARD_STDIN") == "1" || (!stdinIsTTY && stdinHasReadableData()) {
			stdin, err := session.StdinPipe()
			if err != nil {
				res.OK = false
				res.Exit = 1
				res.Error = ErrCodeInternal
				res.Message = "failed to open SSH stdin"
				res.Hint = "retry the operation; report the failure if it persists"
				res.Stage = "session"
				res.LatencyMS = time.Since(start).Milliseconds()
				return res
			}
			go func() {
				_, _ = io.Copy(stdin, os.Stdin)
				_ = stdin.Close()
			}()
		} else if stdinIsTTY {
			session.Stdin = os.Stdin
		}
	}

	err = session.Run(full)
	res.LatencyMS = time.Since(start).Milliseconds()
	if opts.Capture {
		res.Stdout = stdoutBuf.String()
		res.Stderr = stderrBuf.String()
	}
	if err != nil {
		if exitErr, ok := err.(*gossh.ExitError); ok {
			res.Exit = exitErr.ExitStatus()
			res.OK = false
			if opts.Input != "" {
				if res.Exit == 127 && (!opts.Capture || strings.Contains(res.Stderr, "ssm: error=interpreter_not_found")) {
					res.Error = ErrCodeInterpreter
					res.Message = "remote script interpreter is unavailable"
					res.Hint = fmt.Sprintf("remote shell %q is unavailable; retry with --shell sh or install it", opts.Interpreter)
					res.Stage = "interpreter"
				} else {
					res.Error = ErrCodeRemoteScript
					res.Message = "remote script exited non-zero"
					res.Hint = "the script reached the remote interpreter but exited non-zero; inspect stderr"
					res.Stage = "remote_execution"
				}
				if !opts.Capture {
					fmt.Fprintf(os.Stderr, "ssm: error=%s script=%s exit=%d\n", res.Error, opts.ScriptLabel, res.Exit)
					fmt.Fprintf(os.Stderr, "ssm: hint=%s\n", res.Hint)
				}
			}
			if res.Error == "" {
				res.Error = ErrCodeRemote
				res.Message = "remote command exited non-zero"
				res.Hint = "inspect stdout/stderr; SSH transport succeeded"
				res.Stage = "remote_execution"
			}
			return res
		}
		ce := ClassifyError(err, c)
		res.OK = false
		res.Exit = ExitCodeFor(err)
		res.Error = ce.Code
		res.Message = ce.Error()
		res.Hint = ce.Hint
		res.Stage = "session"
		if !opts.Capture {
			PrintAgentError(err, c)
		}
		return res
	}
	res.OK = true
	res.Exit = 0
	return res
}

// RunScriptPreflight validates shell syntax remotely without executing the
// script. Interpreter lookup remains distinguishable from a syntax error.
func RunScriptPreflight(c config.Connection, v *config.Vault, spec ScriptSpec, noReuse bool, requestedAlias, resolvedAlias string) RunResult {
	res := Run(c, v, RunOptions{
		Command:        BuildScriptSyntaxRunner(spec),
		Input:          spec.Body,
		RiskCommand:    spec.Body,
		Capture:        true,
		NoReuse:        noReuse,
		Interpreter:    spec.Interpreter,
		ScriptLabel:    spec.Label,
		Mode:           "script",
		RequestedAlias: requestedAlias,
		ResolvedAlias:  resolvedAlias,
	})
	if res.OK {
		res.Preflight = "passed"
		res.Stdout = ""
		res.Stderr = ""
		return res
	}
	res.Preflight = "failed"
	if res.Error == ErrCodeRemoteScript {
		res.Error = ErrCodeScriptSyntax
		res.Message = "remote interpreter rejected script syntax"
		res.Stage = "syntax_preflight"
		line := syntaxErrorLine(res.Stderr)
		res.Stderr = ""
		res.Hint = "the remote interpreter rejected the script syntax; no script body was executed and raw parser output was suppressed"
		if line != "" {
			res.Hint += "; line=" + line
		}
	}
	return res
}

func syntaxErrorLine(stderr string) string {
	for _, pattern := range []*regexp.Regexp{syntaxLinePattern, syntaxColonLinePattern} {
		match := pattern.FindStringSubmatch(stderr)
		if len(match) == 2 {
			return match[1]
		}
	}
	return ""
}

// Exec is the classic streaming entry point (exit code only).
func Exec(c config.Connection, v *config.Vault, cmd string) int {
	res := Run(c, v, RunOptions{Command: cmd, Capture: false})
	return res.Exit
}

// WriteRunResult prints a RunResult as JSON or key=value.
func WriteRunResult(res RunResult, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return
	}
	if res.Plan {
		fmt.Printf("plan=1\n")
	}
	fmt.Printf("ok=%d\n", boolInt(res.OK))
	fmt.Printf("alias=%s\n", res.Alias)
	if res.ResolvedAlias != "" && res.ResolvedAlias != res.Alias {
		fmt.Printf("resolved_alias=%s\n", res.ResolvedAlias)
	}
	fmt.Printf("exit=%d\n", res.Exit)
	if res.RemoteCommand != "" {
		fmt.Printf("remote_command=%s\n", res.RemoteCommand)
	}
	if res.ScriptLabel != "" {
		fmt.Printf("script=%s\n", res.ScriptLabel)
	}
	if res.Interpreter != "" {
		fmt.Printf("interpreter=%s\n", res.Interpreter)
	}
	if res.InputBytes > 0 {
		fmt.Printf("stdin_bytes=%d\n", res.InputBytes)
	}
	if res.ScriptSHA256 != "" {
		fmt.Printf("script_sha256=%s\n", res.ScriptSHA256)
	}
	if res.Mode != "" {
		fmt.Printf("mode=%s\n", res.Mode)
	}
	if res.Transport != "" {
		fmt.Printf("transport=%s\n", res.Transport)
	}
	if res.Preflight != "" {
		fmt.Printf("preflight=%s\n", res.Preflight)
	}
	if res.Risk != "" {
		fmt.Printf("risk=%s\n", res.Risk)
	}
	if res.LatencyMS > 0 {
		fmt.Printf("latency_ms=%d\n", res.LatencyMS)
	}
	if res.Error != "" {
		fmt.Printf("error=%s\n", res.Error)
	}
	if res.Message != "" {
		fmt.Printf("message=%s\n", res.Message)
	}
	if res.Hint != "" {
		fmt.Printf("hint=%s\n", res.Hint)
	}
	if res.Stage != "" {
		fmt.Printf("stage=%s\n", res.Stage)
	}
	if res.Stdout != "" {
		fmt.Printf("stdout=%s\n", strings.ReplaceAll(res.Stdout, "\n", "\\n"))
	}
}
