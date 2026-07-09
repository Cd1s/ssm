package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"ssm/internal/ssh"
)

// remoteRunSpec is the resolved remote command for sshctl run / ssm exec / map / plan.
type remoteRunSpec struct {
	Command  string
	Trace    bool
	Timeout  time.Duration
	JSON     bool
	Plan     bool
	NoReuse  bool
	Secrets  map[string]string
	Workers  int
	Scripts  []ssh.ScriptSpec // multi-script parallel (-f repeated or --scripts)
	FromArgs bool             // command came from argv (not only scripts)
}

// parseRemoteRunArgs parses options and command parts after the host alias
// (or after map target list).
func parseRemoteRunArgs(args []string) (remoteRunSpec, error) {
	var (
		raw       bool
		fromStdin bool
		filePaths []string
		trace     bool
		timeout   time.Duration
		jsonOut   bool
		plan      bool
		noReuse   bool
		workers   int
		secrets   = map[string]string{}
		parts     []string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			parts = args[i+1:]
			i = len(args)
		case arg == "--raw":
			raw = true
		case arg == "--trace", arg == "-v":
			trace = true
		case arg == "--json":
			jsonOut = true
		case arg == "--plan", arg == "--dry-run":
			plan = true
		case arg == "--no-reuse":
			noReuse = true
		case arg == "--jobs", arg == "-j", arg == "--parallel":
			if i+1 >= len(args) {
				return remoteRunSpec{}, fmt.Errorf("%s requires a number", arg)
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 1 {
				return remoteRunSpec{}, fmt.Errorf("invalid jobs value %q", args[i])
			}
			workers = n
		case strings.HasPrefix(arg, "--jobs="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "--jobs="))
			if err != nil || n < 1 {
				return remoteRunSpec{}, fmt.Errorf("invalid --jobs value")
			}
			workers = n
		case arg == "--timeout":
			if i+1 >= len(args) {
				return remoteRunSpec{}, fmt.Errorf("--timeout requires a duration (e.g. 10s or 30)")
			}
			i++
			d, err := parseCLITimeout(args[i])
			if err != nil {
				return remoteRunSpec{}, err
			}
			timeout = d
		case strings.HasPrefix(arg, "--timeout="):
			d, err := parseCLITimeout(strings.TrimPrefix(arg, "--timeout="))
			if err != nil {
				return remoteRunSpec{}, err
			}
			timeout = d
		case arg == "--secret", arg == "-e":
			if i+1 >= len(args) {
				return remoteRunSpec{}, fmt.Errorf("%s requires NAME=value or NAME=@path", arg)
			}
			i++
			if err := parseSecretKV(args[i], secrets); err != nil {
				return remoteRunSpec{}, err
			}
		case strings.HasPrefix(arg, "--secret="):
			if err := parseSecretKV(strings.TrimPrefix(arg, "--secret="), secrets); err != nil {
				return remoteRunSpec{}, err
			}
		case arg == "-s", arg == "--script":
			fromStdin = true
		case arg == "-f", arg == "--file":
			if i+1 >= len(args) {
				return remoteRunSpec{}, fmt.Errorf("%s requires a path", arg)
			}
			i++
			filePaths = append(filePaths, args[i])
		case strings.HasPrefix(arg, "--file="):
			p := strings.TrimPrefix(arg, "--file=")
			if p == "" {
				return remoteRunSpec{}, fmt.Errorf("--file requires a path")
			}
			filePaths = append(filePaths, p)
		case arg == "--scripts":
			if i+1 >= len(args) {
				return remoteRunSpec{}, fmt.Errorf("--scripts requires comma-separated paths")
			}
			i++
			for _, p := range strings.Split(args[i], ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					filePaths = append(filePaths, p)
				}
			}
		case arg == "-h", arg == "--help":
			return remoteRunSpec{}, fmt.Errorf("help")
		case strings.HasPrefix(arg, "-") && arg != "-":
			return remoteRunSpec{}, fmt.Errorf("unknown run option: %s", arg)
		default:
			parts = args[i:]
			i = len(args)
		}
	}

	var scripts []ssh.ScriptSpec
	for _, p := range filePaths {
		data, err := os.ReadFile(p)
		if err != nil {
			return remoteRunSpec{}, fmt.Errorf("read script file %s: %w", p, err)
		}
		body := strings.TrimRight(string(data), "\r\n")
		if strings.TrimSpace(body) == "" {
			return remoteRunSpec{}, fmt.Errorf("script file is empty: %s", p)
		}
		scripts = append(scripts, ssh.ScriptSpec{Label: p, Body: body})
	}

	var cmd string
	fromArgs := false
	switch {
	case fromStdin:
		if len(scripts) > 0 || len(parts) > 0 {
			return remoteRunSpec{}, fmt.Errorf("use only one of: command args, -s/--script, or -f/--file")
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return remoteRunSpec{}, fmt.Errorf("read stdin script: %w", err)
		}
		cmd = strings.TrimRight(string(data), "\r\n")
		if strings.TrimSpace(cmd) == "" {
			return remoteRunSpec{}, fmt.Errorf("stdin script is empty")
		}
	case len(parts) > 0:
		if len(scripts) > 0 {
			return remoteRunSpec{}, fmt.Errorf("use either command args or -f/--scripts, not both")
		}
		cmd = ssh.JoinRemoteCommand(parts, raw)
		fromArgs = true
	case len(scripts) == 1:
		// classic single -f: body is the remote command
		cmd = scripts[0].Body
		scripts = nil
	case len(scripts) > 1:
		// multi-script parallel mode: bodies stay in Scripts
		if raw {
			return remoteRunSpec{}, fmt.Errorf("--raw cannot be combined with -f/--file")
		}
	default:
		return remoteRunSpec{}, fmt.Errorf("missing remote command (use args, -s/--script, or -f/--file/--scripts)")
	}

	if raw && fromStdin {
		return remoteRunSpec{}, fmt.Errorf("--raw cannot be combined with -s/--script")
	}

	return remoteRunSpec{
		Command:  cmd,
		Trace:    trace,
		Timeout:  timeout,
		JSON:     jsonOut,
		Plan:     plan,
		NoReuse:  noReuse,
		Secrets:  secrets,
		Workers:  workers,
		Scripts:  scripts,
		FromArgs: fromArgs,
	}, nil
}

func parseSecretKV(spec string, into map[string]string) error {
	eq := strings.IndexByte(spec, '=')
	if eq <= 0 {
		return fmt.Errorf("secret must be NAME=value or NAME=@path")
	}
	name := spec[:eq]
	val := spec[eq+1:]
	if strings.HasPrefix(val, "@") {
		path := val[1:]
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("secret file %s: %w", path, err)
		}
		val = strings.TrimRight(string(data), "\r\n")
	}
	into[name] = val
	return nil
}

func parseCLITimeout(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, fmt.Errorf("--timeout requires a duration (e.g. 10s or 30)")
	}
	if d, err := time.ParseDuration(v); err == nil {
		if d <= 0 {
			return 0, fmt.Errorf("--timeout must be positive")
		}
		return d, nil
	}
	var sec int
	if _, err := fmt.Sscanf(v, "%d", &sec); err == nil && sec > 0 {
		return time.Duration(sec) * time.Second, nil
	}
	return 0, fmt.Errorf("invalid --timeout %q (use 10s, 1m, or integer seconds)", v)
}

func applyRunSpecEnv(spec remoteRunSpec) {
	if spec.Trace {
		_ = os.Setenv("SSM_TRACE", "1")
	}
	if spec.Timeout > 0 {
		_ = os.Setenv("SSM_TIMEOUT", spec.Timeout.String())
	}
	if spec.NoReuse {
		_ = os.Setenv("SSM_REUSE", "0")
	}
}
