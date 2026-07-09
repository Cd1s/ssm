package ssh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"ssm/internal/config"
)

// RunOptions controls a single remote command invocation.
type RunOptions struct {
	Command  string
	Secrets  map[string]string // NAME -> value; injected as remote env assigns
	Capture  bool              // capture stdout/stderr into RunResult
	PlanOnly bool              // do not dial/run
	NoReuse  bool
	// RequestedAlias is the name the user typed (before redirects).
	RequestedAlias string
	ResolvedAlias  string
}

// RunResult is the structured result of a remote run (agent JSON schema).
type RunResult struct {
	OK             bool   `json:"ok"`
	Alias          string `json:"alias"`
	ResolvedAlias  string `json:"resolved_alias,omitempty"`
	User           string `json:"user,omitempty"`
	Host           string `json:"host,omitempty"`
	Port           int    `json:"port,omitempty"`
	Exit           int    `json:"exit"`
	Stdout         string `json:"stdout,omitempty"`
	Stderr         string `json:"stderr,omitempty"`
	LatencyMS      int64  `json:"latency_ms,omitempty"`
	RemoteCommand  string `json:"remote_command,omitempty"` // secrets redacted
	Error          string `json:"error,omitempty"`
	Hint           string `json:"hint,omitempty"`
	Plan           bool   `json:"plan,omitempty"`
	Risk           string `json:"risk,omitempty"`
	ScriptLabel    string `json:"script,omitempty"` // multi-script map label
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
		out = strings.ReplaceAll(out, e.v, "***")
		out = strings.ReplaceAll(out, ShellQuote(e.v), "'***'")
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
	display := RedactSecrets(full, opts.Secrets)
	res := RunResult{
		Alias:         opts.RequestedAlias,
		ResolvedAlias: opts.ResolvedAlias,
		User:          c.User,
		Host:          c.Host,
		Port:          port,
		RemoteCommand: display,
		Risk:          AssessRisk(opts.Command),
	}
	if res.Alias == "" {
		res.Alias = c.Name
	}
	if res.ResolvedAlias == "" {
		res.ResolvedAlias = c.Name
	}

	if traceEnabled() {
		fmt.Fprintf(os.Stderr, "ssm: remote command: %s\n", display)
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
		res.Hint = ce.Hint
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
		stdinIsTTY := term.IsTerminal(int(os.Stdin.Fd()))
		if os.Getenv("SSM_FORWARD_STDIN") == "1" || (!stdinIsTTY && stdinHasReadableData()) {
			stdin, err := session.StdinPipe()
			if err != nil {
				res.OK = false
				res.Exit = 1
				res.Error = ErrCodeInternal
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
			return res
		}
		ce := ClassifyError(err, c)
		res.OK = false
		res.Exit = ExitCodeFor(err)
		res.Error = ce.Code
		res.Hint = ce.Hint
		if !opts.Capture {
			PrintAgentError(err, c)
		}
		return res
	}
	res.OK = true
	res.Exit = 0
	return res
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
	if res.Risk != "" {
		fmt.Printf("risk=%s\n", res.Risk)
	}
	if res.LatencyMS > 0 {
		fmt.Printf("latency_ms=%d\n", res.LatencyMS)
	}
	if res.Error != "" {
		fmt.Printf("error=%s\n", res.Error)
	}
	if res.Hint != "" {
		fmt.Printf("hint=%s\n", res.Hint)
	}
	if res.Stdout != "" {
		fmt.Printf("stdout=%s\n", strings.ReplaceAll(res.Stdout, "\n", "\\n"))
	}
}
