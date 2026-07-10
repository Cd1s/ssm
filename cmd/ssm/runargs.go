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

const maxSecretBytes = 1 << 20

// remoteRunSpec is the resolved remote command for sshctl run / ssm exec / map / plan.
type remoteRunSpec struct {
	Command   string
	Trace     bool
	Timeout   time.Duration
	JSON      bool
	Plan      bool
	NoReuse   bool
	Secrets   map[string]string
	Workers   int
	Scripts   []ssh.ScriptSpec // multi-script parallel (-f repeated or --scripts)
	FromArgs  bool             // command came from argv (not only scripts)
	Mode      string
	Preflight bool
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
		jsonOut   = machineJSON
		plan      bool
		noReuse   bool
		workers   int
		secrets   = map[string]string{}
		parts     []string
		shell     string
		argvMode  bool
		preflight bool
		afterDash bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			parts = args[i+1:]
			afterDash = true
			i = len(args)
		case arg == "--raw":
			raw = true
		case arg == "--argv":
			argvMode = true
		case arg == "--trace", arg == "-v":
			trace = true
		case arg == "--json":
			jsonOut = true
		case arg == "--plan", arg == "--dry-run":
			plan = true
		case arg == "--no-reuse":
			noReuse = true
		case arg == "--preflight":
			preflight = true
		case arg == "--no-preflight":
			preflight = false
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
		case arg == "--shell", arg == "--interpreter":
			remaining := args[i+1:]
			if len(remaining) == 0 {
				return remoteRunSpec{}, fmt.Errorf("%s requires a shell name", arg)
			}
			shell = remaining[0]
			i++
		case strings.HasPrefix(arg, "--shell="):
			shell = strings.TrimPrefix(arg, "--shell=")
		case strings.HasPrefix(arg, "--interpreter="):
			shell = strings.TrimPrefix(arg, "--interpreter=")
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

	if (fromStdin || len(filePaths) > 0) && (raw || argvMode) {
		return remoteRunSpec{}, fmt.Errorf("--raw/--argv cannot be combined with a script source")
	}

	var cmd string
	var scripts []ssh.ScriptSpec
	fromArgs := false
	mode := ""
	switch {
	case fromStdin:
		mode = "script"
		if len(filePaths) > 0 {
			return remoteRunSpec{}, fmt.Errorf("use only one of -s/--script or -f/--file/--scripts")
		}
		if len(parts) > 0 && !afterDash {
			return remoteRunSpec{}, fmt.Errorf("put script arguments after --")
		}
		data, err := io.ReadAll(io.LimitReader(os.Stdin, ssh.MaxScriptBytes+1))
		if err != nil {
			return remoteRunSpec{}, fmt.Errorf("read stdin script: %w", err)
		}
		script, err := ssh.PrepareScript("<stdin>", data, shell, parts)
		if err != nil {
			return remoteRunSpec{}, fmt.Errorf("stdin script: %w", err)
		}
		scripts = append(scripts, script)
	case len(parts) > 0:
		if len(filePaths) > 0 {
			if !afterDash {
				return remoteRunSpec{}, fmt.Errorf("put script arguments after --")
			}
			for _, p := range filePaths {
				data, err := readScriptFile(p)
				if err != nil {
					return remoteRunSpec{}, fmt.Errorf("read script file %s: %w", p, err)
				}
				script, err := ssh.PrepareScript(p, data, shell, parts)
				if err != nil {
					return remoteRunSpec{}, fmt.Errorf("script file %s: %w", p, err)
				}
				scripts = append(scripts, script)
			}
			break
		}
		if shell != "" {
			return remoteRunSpec{}, fmt.Errorf("--shell/--interpreter requires -s, -f, or --scripts")
		}
		if raw && argvMode {
			return remoteRunSpec{}, fmt.Errorf("use only one of --raw or --argv")
		}
		if argvMode {
			cmd = ssh.JoinRemoteArgv(parts)
			mode = "argv"
		} else {
			cmd = ssh.JoinRemoteCommand(parts, raw)
			if raw || len(parts) == 1 {
				mode = "shell_command"
			} else {
				mode = "argv"
			}
		}
		fromArgs = true
	case len(filePaths) > 0:
		mode = "script"
		for _, p := range filePaths {
			data, err := readScriptFile(p)
			if err != nil {
				return remoteRunSpec{}, fmt.Errorf("read script file %s: %w", p, err)
			}
			script, err := ssh.PrepareScript(p, data, shell, nil)
			if err != nil {
				return remoteRunSpec{}, fmt.Errorf("script file %s: %w", p, err)
			}
			scripts = append(scripts, script)
		}
	default:
		return remoteRunSpec{}, fmt.Errorf("missing remote command (use args, -s/--script, or -f/--file/--scripts)")
	}
	if preflight && len(scripts) == 0 {
		return remoteRunSpec{}, fmt.Errorf("--preflight requires -s, -f, or --scripts")
	}

	return remoteRunSpec{
		Command:   cmd,
		Trace:     trace,
		Timeout:   timeout,
		JSON:      jsonOut,
		Plan:      plan,
		NoReuse:   noReuse,
		Secrets:   secrets,
		Workers:   workers,
		Scripts:   scripts,
		FromArgs:  fromArgs,
		Mode:      mode,
		Preflight: preflight,
	}, nil
}

func parseSecretKV(spec string, into map[string]string) error {
	eq := strings.IndexByte(spec, '=')
	if eq <= 0 {
		return fmt.Errorf("secret must be NAME=value or NAME=@path")
	}
	name := spec[:eq]
	if !ssh.ValidEnvName(name) {
		return fmt.Errorf("invalid secret environment name %q", name)
	}
	val := spec[eq+1:]
	if strings.HasPrefix(val, "@") {
		path := val[1:]
		data, err := readLimitedFile(path, maxSecretBytes)
		if err != nil {
			return fmt.Errorf("secret file %s: %w", path, err)
		}
		val = strings.TrimRight(string(data), "\r\n")
	}
	if len(val) > maxSecretBytes {
		return fmt.Errorf("secret value exceeds %d bytes", maxSecretBytes)
	}
	if strings.IndexByte(val, 0) >= 0 {
		return fmt.Errorf("secret value contains a NUL byte")
	}
	into[name] = val
	return nil
}

func readScriptFile(path string) ([]byte, error) {
	return readLimitedFile(path, ssh.MaxScriptBytes)
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // scripts and secret files are explicit CLI inputs
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
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

func exitRemoteRunArgError(tool, alias string, args []string, err error) {
	if hasJSONFlag(args) {
		ssh.WriteRunResult(ssh.RunResult{
			OK:    false,
			Alias: alias,
			Exit:  2,
			Error: "invalid_arguments",
			Hint:  redactError(err),
		}, true)
		os.Exit(2)
	}
	if alias != "" {
		fmt.Fprintf(os.Stderr, "%s: error=invalid_arguments alias=%s\n", tool, alias)
	} else {
		fmt.Fprintf(os.Stderr, "%s: error=invalid_arguments\n", tool)
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", tool, redactError(err))
	os.Exit(2)
}
