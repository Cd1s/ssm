package ssh

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"ssm/internal/config"
)

// CheckResult is the structured output of sshctl check for agents.
type CheckResult struct {
	OK        bool   `json:"ok"`
	Alias     string `json:"alias"`
	User      string `json:"user"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	Uname     string `json:"uname,omitempty"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message,omitempty"`
	Hint      string `json:"hint,omitempty"`
	Exit      int    `json:"exit"`
	Stage     string `json:"stage,omitempty"`
	Address   string `json:"address,omitempty"`
}

// Check dials the host and runs a tiny probe (hostname; uname -sr).
// It is the recommended first step when an agent is unsure whether a failure
// is quote-related, network, host key, or remote-system health.
func Check(c config.Connection, v *config.Vault) CheckResult {
	port := c.Port
	if port == 0 {
		port = 22
	}
	res := CheckResult{
		Alias:   c.Name,
		User:    c.User,
		Host:    c.Host,
		Port:    port,
		Address: fmt.Sprintf("%s@%s:%d", c.User, c.Host, port),
	}

	start := time.Now()
	run := Run(c, v, RunOptions{Command: "hostname; uname -sr", Capture: true})
	res.LatencyMS = time.Since(start).Milliseconds()
	if !run.OK {
		res.OK = false
		res.Error = run.Error
		if res.Error == "" {
			res.Error = ErrCodeRemote
		}
		res.Hint = run.Hint
		res.Message = run.Message
		res.Exit = run.Exit
		res.Stage = run.Stage
		if run.Stderr != "" {
			res.Hint = strings.TrimSpace(run.Stderr) + "; " + res.Hint
		}
		return res
	}
	lines := strings.Split(strings.TrimSpace(run.Stdout), "\n")
	if len(lines) >= 1 {
		res.Hostname = strings.TrimSpace(lines[0])
	}
	if len(lines) >= 2 {
		res.Uname = strings.TrimSpace(lines[1])
	}
	res.OK = true
	res.Exit = 0
	return res
}

// WriteCheckResult prints check output as key=value lines or JSON.
func WriteCheckResult(res CheckResult, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return
	}
	fmt.Printf("ok=%d\n", boolInt(res.OK))
	fmt.Printf("alias=%s\n", res.Alias)
	fmt.Printf("user=%s\n", res.User)
	fmt.Printf("host=%s\n", res.Host)
	fmt.Printf("port=%d\n", res.Port)
	if res.Address != "" {
		fmt.Printf("address=%s\n", res.Address)
	}
	if res.LatencyMS > 0 {
		fmt.Printf("latency_ms=%d\n", res.LatencyMS)
	}
	if res.Hostname != "" {
		fmt.Printf("hostname=%s\n", res.Hostname)
	}
	if res.Uname != "" {
		fmt.Printf("uname=%s\n", res.Uname)
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
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
