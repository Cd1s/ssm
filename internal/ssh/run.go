package ssh

import (
	"bytes"
	"errors"
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
	"ssm/internal/machinecontract"
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
	machinecontract.ResultMetadata
	Plan         bool   `json:"plan,omitempty"`
	Risk         string `json:"risk,omitempty"`
	ScriptLabel  string `json:"script,omitempty"` // multi-script map label
	Interpreter  string `json:"interpreter,omitempty"`
	InputBytes   int    `json:"stdin_bytes,omitempty"`
	ScriptSHA256 string `json:"script_sha256,omitempty"`
	Mode         string `json:"mode,omitempty"`
	Transport    string `json:"transport,omitempty"`
	Preflight    string `json:"preflight,omitempty"`

	failure         machinecontract.Failure
	sensitiveValues []string
}

func applyRunFailure(result *RunResult, failure machinecontract.Failure) {
	result.OK = false
	result.Exit = failure.Exit
	result.ResultMetadata = failure.ResultMetadata()
	result.failure = failure
}

func redactRunFailure(result RunResult) RunResult {
	if result.OK {
		return result
	}
	return machinecontract.Redact(result, result.sensitiveValues...)
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

func runSensitiveValues(opts RunOptions) []string {
	values := make([]string, 0, len(opts.Secrets)+1)
	for _, value := range opts.Secrets {
		values = append(values, value)
	}
	if opts.Input == "" {
		return values
	}
	values = append(values, opts.Input)
	for _, line := range strings.Split(opts.Input, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line != "" {
			values = append(values, line)
		}
	}
	return values
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
		Alias:           opts.RequestedAlias,
		ResolvedAlias:   opts.ResolvedAlias,
		User:            c.User,
		Host:            c.Host,
		Port:            port,
		RemoteCommand:   display,
		Risk:            AssessRisk(riskCommand),
		ScriptLabel:     opts.ScriptLabel,
		Interpreter:     opts.Interpreter,
		Mode:            opts.Mode,
		Transport:       "ssh_exec",
		sensitiveValues: runSensitiveValues(opts),
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
		fmt.Fprintf(os.Stderr, "ssm: remote command: %s\n", machinecontract.RedactString(display))
		if res.ScriptSHA256 != "" {
			fmt.Fprintf(os.Stderr, "ssm: script stdin: bytes=%d sha256=%s interpreter=%s\n", res.InputBytes, res.ScriptSHA256, machinecontract.RedactString(res.Interpreter))
		}
	}

	if opts.PlanOnly {
		res.OK = true
		res.Plan = true
		res.Exit = 0
		return res
	}

	start := time.Now()
	client, session, acquireStage, err := acquireSSHSession(c, v, opts.NoReuse)
	if err != nil {
		failure := machinecontract.ClassifySSH(err, machinecontract.SSHContext{
			Alias: c.Name, Host: c.Host, Port: c.Port, Stage: acquireStage,
			SessionAcquisition: acquireStage == "session",
		})
		applyRunFailure(&res, failure)
		res.LatencyMS = time.Since(start).Milliseconds()
		if !opts.Capture {
			_ = machinecontract.WriteHuman(failure)
		}
		return res
	}
	defer releaseClient(client, opts.NoReuse)
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	var stdoutSpool, stderrSpool *machinecontract.DiagnosticSpool
	if opts.Capture {
		session.Stdout = &stdoutBuf
		session.Stderr = &stderrBuf
	} else {
		stdoutSpool, err = machinecontract.NewDiagnosticSpool(os.Stdout, res.sensitiveValues...)
		if err != nil {
			failure := machinecontract.Classify(machinecontract.InternalFailure, machinecontract.Details{
				Message: "failed to spool remote stdout",
				Cause:   err,
				Alias:   opts.RequestedAlias,
			})
			applyRunFailure(&res, failure)
			res.LatencyMS = time.Since(start).Milliseconds()
			_ = machinecontract.WriteHuman(failure)
			return res
		}
		defer func() { _ = stdoutSpool.Close() }()
		stderrSpool, err = machinecontract.NewDiagnosticSpool(os.Stderr, res.sensitiveValues...)
		if err != nil {
			_ = stdoutSpool.Close()
			failure := machinecontract.Classify(machinecontract.InternalFailure, machinecontract.Details{
				Message: "failed to spool remote stderr",
				Cause:   err,
				Alias:   opts.RequestedAlias,
			})
			applyRunFailure(&res, failure)
			res.LatencyMS = time.Since(start).Milliseconds()
			_ = machinecontract.WriteHuman(failure)
			return res
		}
		defer func() { _ = stderrSpool.Close() }()
		session.Stdout = stdoutSpool
		session.Stderr = stderrSpool
	}
	if opts.Input != "" {
		session.Stdin = strings.NewReader(opts.Input)
	} else if !opts.Capture {
		stdinIsTTY := term.IsTerminal(int(os.Stdin.Fd()))
		if os.Getenv("SSM_FORWARD_STDIN") == "1" || (!stdinIsTTY && stdinHasReadableData()) {
			stdin, err := session.StdinPipe()
			if err != nil {
				applyRunFailure(&res, machinecontract.Classify(machinecontract.SSHStdinFailed, machinecontract.Details{
					Message: "failed to open SSH stdin",
					Cause:   err,
					Alias:   opts.RequestedAlias,
				}))
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
		uncapturedInterpreterMarker := false
		if !opts.Capture && opts.Input != "" {
			var inspectErr error
			uncapturedInterpreterMarker, inspectErr = stderrSpool.Contains(machinecontract.InterpreterNotFoundDiagnostic(opts.Interpreter))
			if inspectErr != nil {
				failure := machinecontract.Classify(machinecontract.InternalFailure, machinecontract.Details{
					Message: "failed to inspect bounded remote diagnostics",
					Cause:   inspectErr,
					Alias:   opts.RequestedAlias,
				})
				applyRunFailure(&res, failure)
				_ = machinecontract.WriteHuman(failure)
				return res
			}
		}
		if !opts.Capture {
			if replayErr := replayRunDiagnosticSpools(false, stdoutSpool, stderrSpool); replayErr != nil {
				failure := machinecontract.Classify(machinecontract.InternalFailure, machinecontract.Details{
					Message: "failed to replay bounded remote diagnostics",
					Cause:   replayErr,
					Alias:   opts.RequestedAlias,
				})
				applyRunFailure(&res, failure)
				_ = machinecontract.WriteHuman(failure)
				return res
			}
		}
		if exitErr, ok := err.(*gossh.ExitError); ok {
			exit := exitErr.ExitStatus()
			classificationCaptured := opts.Capture
			classificationStderr := res.Stderr
			if !opts.Capture {
				classificationCaptured = true
				if uncapturedInterpreterMarker {
					classificationStderr = machinecontract.InterpreterNotFoundDiagnostic(opts.Interpreter)
				}
			}
			failure := machinecontract.ClassifyRunExecution(machinecontract.RunExecutionContext{
				Cause:       err,
				Exit:        exit,
				Alias:       opts.RequestedAlias,
				HasInput:    opts.Input != "",
				Capture:     classificationCaptured,
				Stderr:      classificationStderr,
				Script:      opts.ScriptLabel,
				Interpreter: opts.Interpreter,
			})
			if opts.Input != "" && !opts.Capture {
				_ = machinecontract.WriteHuman(failure)
			}
			applyRunFailure(&res, failure)
			return res
		}
		failure := machinecontract.ClassifySSH(err, machinecontract.SSHContext{
			Alias: c.Name, Host: c.Host, Port: c.Port, Stage: "session",
		})
		applyRunFailure(&res, failure)
		if !opts.Capture {
			_ = machinecontract.WriteHuman(failure)
		}
		return res
	}
	if !opts.Capture {
		if replayErr := replayRunDiagnosticSpools(true, stdoutSpool, stderrSpool); replayErr != nil {
			failure := machinecontract.Classify(machinecontract.InternalFailure, machinecontract.Details{
				Message: "failed to replay remote output",
				Cause:   replayErr,
				Alias:   opts.RequestedAlias,
			})
			applyRunFailure(&res, failure)
			_ = machinecontract.WriteHuman(failure)
			return res
		}
	}
	res.OK = true
	res.Exit = 0
	return res
}

func replayRunDiagnosticSpools(success bool, spools ...*machinecontract.DiagnosticSpool) error {
	var result error
	for _, spool := range spools {
		if spool != nil {
			result = errors.Join(result, spool.Replay(success))
		}
	}
	return result
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
	if res.Error == machinecontract.CodeRemoteScript {
		line := syntaxErrorLine(res.Stderr)
		failure := machinecontract.Classify(machinecontract.ScriptSyntaxFailed, machinecontract.Details{
			Message: "remote interpreter rejected script syntax",
			Alias:   requestedAlias,
			Exit:    res.Exit,
			Script:  spec.Label,
			Line:    line,
		})
		applyRunFailure(&res, failure)
		res.Preflight = "failed"
		res.Stderr = ""
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

// WriteRunResult prints a RunResult as JSON or key=value.
func WriteRunResult(res RunResult, asJSON bool) {
	if asJSON {
		res = redactRunFailure(res)
		if res.OK {
			_ = machinecontract.WriteJSON(res)
		} else {
			_ = machinecontract.WriteFailureJSON(res)
		}
		return
	}
	if !res.OK {
		_ = machinecontract.RenderRunFailure(
			machinecontract.Streams{Stdout: os.Stdout, Stderr: os.Stderr},
			machinecontract.RunFailureView{
				Plan:            res.Plan,
				Alias:           res.Alias,
				ResolvedAlias:   res.ResolvedAlias,
				Exit:            res.Exit,
				RemoteCommand:   res.RemoteCommand,
				Script:          res.ScriptLabel,
				Interpreter:     res.Interpreter,
				InputBytes:      res.InputBytes,
				ScriptSHA256:    res.ScriptSHA256,
				Mode:            res.Mode,
				Transport:       res.Transport,
				Preflight:       res.Preflight,
				Risk:            res.Risk,
				LatencyMS:       res.LatencyMS,
				Error:           res.Error,
				Message:         res.Message,
				Hint:            res.Hint,
				Stage:           res.Stage,
				Stdout:          res.Stdout,
				SensitiveValues: res.sensitiveValues,
			},
		)
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
	if res.Stdout != "" {
		fmt.Printf("stdout=%s\n", strings.ReplaceAll(res.Stdout, "\n", "\\n"))
	}
}

// WriteRunResultNDJSON preserves successful run payloads and sanitizes failed
// captures immediately before compact stream rendering.
func WriteRunResultNDJSON(output io.Writer, res RunResult) error {
	res = redactRunFailure(res)
	if res.OK {
		return machinecontract.WriteNDJSON(output, res)
	}
	return machinecontract.WriteFailureNDJSON(output, res)
}
