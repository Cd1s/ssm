package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"ssm/internal/machinecontract"
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
	// Stdin and StdinFile carry the stdin forwarding choice. Only run/exec
	// honor them; the zero value never forwards (map jobs, argv streams).
	Stdin          ssh.StdinMode
	StdinFile      string
	RetryDial      int
	RetryBackoff   time.Duration
	ConnectTimeout time.Duration
	ExecTimeout    time.Duration
}

// runValueOptions are the sshctl run/exec/plan/map options that consume the
// next token as their value; runFlagOptions take no value. Together they are
// the option table shared by remoteArgvStart and the unknown-option
// suggestions, and a test keeps them in step with parseRemoteRunArgs.
// --refresh belongs to the "run <alias> --stream" form.
var (
	runValueOptions = []string{
		"--jobs", "-j", "--parallel", "--timeout", "--secret", "-e",
		"--shell", "--interpreter", "-f", "--file", "--scripts", "--refresh", "--retry-dial", "--connect-timeout", "--exec-timeout",
		"--stdin-file",
	}
	runFlagOptions = []string{
		"--raw", "--argv", "--trace", "-v", "--json", "--plan", "--dry-run", "--no-reuse",
		"--preflight", "--no-preflight", "-s", "--script", "-h", "--help", "--stream",
		"--stdin", "--no-stdin",
	}
)

// runOptionTakesValue reports whether an sshctl run/exec/plan/map option
// consumes the next token as its value. It is the single source of truth used
// by remoteArgvStart so option scanning cannot drift from parseRemoteRunArgs.
func runOptionTakesValue(arg string) bool {
	for _, name := range runValueOptions {
		if arg == name {
			return true
		}
	}
	return false
}

// remoteArgvStart returns the index in args (the tokens after the host alias,
// or after the map target list) of the token that starts the remote argv, or
// len(args) when there is none. The boundary is "--argv", "--", or the first
// non-option token. Tokens at and after the boundary belong to the remote
// program and must never be scanned for sshctl options such as -h, --help,
// --json, or --timeout.
func remoteArgvStart(args []string) int {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--" || arg == "--argv":
			return i
		case runOptionTakesValue(arg):
			i++
		case strings.HasPrefix(arg, "-") && arg != "-":
		default:
			return i
		}
	}
	return len(args)
}

// runOptionEnd returns the end of the sshctl-owned region of the tokens that
// follow "run", "exec", or "plan": an optional leading --json, the exact
// alias, and the options before the remote argv boundary.
func runOptionEnd(args []string) int {
	i := 0
	if len(args) > 0 && args[0] == "--json" {
		i = 1
	}
	if i < len(args) && !strings.HasPrefix(args[i], "-") {
		i++
	}
	return i + remoteArgvStart(args[i:])
}

// splitMapTargets separates the leading target list (aliases and globs) from
// the options and remote argv of "map".
func splitMapTargets(args []string) (targets, rest []string) {
	i := 0
	for ; i < len(args); i++ {
		if args[i] == "--" || strings.HasPrefix(args[i], "-") {
			break
		}
		targets = append(targets, args[i])
	}
	return targets, args[i:]
}

// mapOptionEnd is the map counterpart of runOptionEnd.
func mapOptionEnd(args []string) int {
	targets, rest := splitMapTargets(args)
	return len(targets) + remoteArgvStart(rest)
}

// parseRemoteRunArgs parses options and command parts after the host alias
// (or after map target list).
func parseRemoteRunArgs(args []string) (remoteRunSpec, error) {
	var (
		raw          bool
		fromStdin    bool
		filePaths    []string
		trace        bool
		timeout      time.Duration
		jsonOut      = machineJSON
		plan         bool
		noReuse      bool
		workers      int
		secrets      = map[string]string{}
		parts        []string
		shell        string
		interp       string
		argvMode     bool
		preflight    bool
		afterDash    bool
		stdinFlag    bool
		noStdin      bool
		stdinFile    string
		retryDial    int
		retryBackoff time.Duration
		retryErr     error
		connectTo    time.Duration
		execTo       time.Duration
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
			// --argv starts the remote argv: nothing after it is an sshctl
			// option. A redundant "--" right after it is accepted for
			// compatibility with "run <alias> --argv -- <command>".
			argvMode = true
			parts = args[i+1:]
			if len(parts) > 0 && parts[0] == "--" {
				parts = parts[1:]
				afterDash = true
			}
			i = len(args)
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
		case arg == "--connect-timeout", arg == "--exec-timeout":
			if i+1 >= len(args) {
				return remoteRunSpec{}, fmt.Errorf("%s requires a duration", arg)
			}
			i++
			d, err := parseCLIDuration(arg, args[i]) //nolint:gosec // i+1 was bounds-checked immediately above
			if err != nil {
				return remoteRunSpec{}, err
			}
			if arg == "--connect-timeout" {
				connectTo = d
			} else {
				execTo = d
			}
		case strings.HasPrefix(arg, "--connect-timeout="):
			d, err := parseCLIDuration("--connect-timeout", strings.TrimPrefix(arg, "--connect-timeout="))
			if err != nil {
				return remoteRunSpec{}, err
			}
			connectTo = d
		case strings.HasPrefix(arg, "--exec-timeout="):
			d, err := parseCLIDuration("--exec-timeout", strings.TrimPrefix(arg, "--exec-timeout="))
			if err != nil {
				return remoteRunSpec{}, err
			}
			execTo = d
		case arg == "--retry-dial":
			if i+1 >= len(args) {
				return remoteRunSpec{}, fmt.Errorf("--retry-dial requires N[:backoff]")
			}
			i++
			retryDial, retryBackoff, retryErr = parseRetryDial(args[i]) //nolint:gosec // i+1 was bounds-checked immediately above
			if retryErr != nil {
				return remoteRunSpec{}, retryErr
			}
		case strings.HasPrefix(arg, "--retry-dial="):
			retryDial, retryBackoff, retryErr = parseRetryDial(strings.TrimPrefix(arg, "--retry-dial="))
			if retryErr != nil {
				return remoteRunSpec{}, retryErr
			}
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
				return remoteRunSpec{}, fmt.Errorf("%s requires a shell or interpreter name", arg)
			}
			if arg == "--shell" {
				shell = remaining[0]
			} else {
				interp = remaining[0]
			}
			i++
		case strings.HasPrefix(arg, "--shell="):
			shell = strings.TrimPrefix(arg, "--shell=")
		case strings.HasPrefix(arg, "--interpreter="):
			interp = strings.TrimPrefix(arg, "--interpreter=")
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
		case arg == "--stdin":
			stdinFlag = true
		case arg == "--no-stdin":
			noStdin = true
		case arg == "--stdin-file":
			if i+1 >= len(args) {
				return remoteRunSpec{}, fmt.Errorf("--stdin-file requires a path")
			}
			if stdinFile != "" {
				return remoteRunSpec{}, fmt.Errorf("--stdin-file may be given only once")
			}
			stdinFile = args[i+1] //nolint:gosec // length is checked at the top of this case
			i++
		case strings.HasPrefix(arg, "--stdin-file="):
			if stdinFile != "" {
				return remoteRunSpec{}, fmt.Errorf("--stdin-file may be given only once")
			}
			stdinFile = strings.TrimPrefix(arg, "--stdin-file=")
			if stdinFile == "" {
				return remoteRunSpec{}, fmt.Errorf("--stdin-file requires a path")
			}
		case arg == "-h", arg == "--help":
			return remoteRunSpec{}, fmt.Errorf("help")
		case strings.HasPrefix(arg, "-") && arg != "-":
			return remoteRunSpec{}, unknownRunOptionError(arg)
		default:
			parts = args[i:]
			i = len(args)
		}
	}

	stdinMode, err := resolveStdinOptions(stdinFlag, noStdin, stdinFile, fromStdin || len(filePaths) > 0)
	if err != nil {
		return remoteRunSpec{}, err
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
		script, err := ssh.PrepareScriptWithInterpreter("<stdin>", data, shell, interp, parts)
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
				script, err := ssh.PrepareScriptWithInterpreter(p, data, shell, interp, parts)
				if err != nil {
					return remoteRunSpec{}, fmt.Errorf("script file %s: %w", p, err)
				}
				scripts = append(scripts, script)
			}
			break
		}
		if shell != "" || interp != "" {
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
			script, err := ssh.PrepareScriptWithInterpreter(p, data, shell, interp, nil)
			if err != nil {
				return remoteRunSpec{}, fmt.Errorf("script file %s: %w", p, err)
			}
			scripts = append(scripts, script)
		}
	default:
		return remoteRunSpec{}, fmt.Errorf("missing remote command (use args, -s/--script, or -f/--file/--scripts)")
	}
	for _, script := range scripts {
		if preflight && script.NonShell {
			return remoteRunSpec{}, fmt.Errorf("--preflight only checks shell syntax and is not supported with a non-shell --interpreter; remove --preflight")
		}
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
		Stdin:     stdinMode,
		StdinFile: stdinFile,
		RetryDial: retryDial, RetryBackoff: retryBackoff,
		ConnectTimeout: connectTo, ExecTimeout: execTo,
	}, nil
}

func parseCLIDuration(flag, value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if d, err := time.ParseDuration(value); err == nil && d > 0 {
		return d, nil
	}
	if sec, err := strconv.Atoi(value); err == nil && sec > 0 {
		return time.Duration(sec) * time.Second, nil
	}
	return 0, fmt.Errorf("invalid %s %q", flag, value)
}

func parseRetryDial(value string) (int, time.Duration, error) {
	parts := strings.Split(value, ":")
	if len(parts) > 2 || parts[0] == "" {
		return 0, 0, fmt.Errorf("invalid --retry-dial %q (use N[:backoff])", value)
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n < 0 {
		return 0, 0, fmt.Errorf("invalid --retry-dial %q (N must be non-negative)", value)
	}
	backoff := 250 * time.Millisecond
	if len(parts) == 2 {
		backoff, err = time.ParseDuration(parts[1])
		if err != nil || backoff <= 0 {
			return 0, 0, fmt.Errorf("invalid --retry-dial backoff %q", parts[1])
		}
	}
	return n, backoff, nil
}

// resolveStdinOptions validates the stdin forwarding options against each
// other and against script sources, whose body already travels over the
// remote stdin.
func resolveStdinOptions(forward, disable bool, file string, scriptSource bool) (ssh.StdinMode, error) {
	switch {
	case forward && disable:
		return 0, fmt.Errorf("--stdin and --no-stdin cannot be combined")
	case file != "" && (forward || disable):
		return 0, fmt.Errorf("--stdin-file cannot be combined with --stdin or --no-stdin")
	case scriptSource && (forward || file != ""):
		return 0, fmt.Errorf("--stdin/--stdin-file cannot be combined with -s, -f, or --scripts: the script body is sent over stdin")
	}
	if file != "" {
		info, err := os.Stat(file)
		if err != nil {
			return 0, fmt.Errorf("stdin file %s: %w", file, err)
		}
		if info.IsDir() {
			return 0, fmt.Errorf("stdin file %s is a directory", file)
		}
		return ssh.StdinForward, nil
	}
	switch {
	case forward:
		return ssh.StdinForward, nil
	case disable:
		return ssh.StdinDisable, nil
	}
	return ssh.StdinDefault, nil
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
	if spec.ConnectTimeout > 0 {
		_ = os.Setenv("SSM_CONNECT_TIMEOUT", spec.ConnectTimeout.String())
	}
	if spec.NoReuse {
		_ = os.Setenv("SSM_REUSE", "0")
	}
}

func exitRemoteRunArgError(tool, alias string, args []string, err error) {
	failure := machinecontract.Classify(machinecontract.InvalidRunArguments, machinecontract.Details{
		Cause: err,
		Alias: alias,
		Tool:  tool,
	})
	if machineJSON || hasJSONFlag(args[:remoteArgvStart(args)]) {
		ssh.WriteRunResult(ssh.RunResult{
			OK:             false,
			Alias:          alias,
			Exit:           machinecontract.ProcessExit(failure),
			ResultMetadata: failure.ResultMetadata(),
		}, true)
		os.Exit(machinecontract.ProcessExit(failure))
	}
	_ = machinecontract.WriteHuman(failure)
	os.Exit(machinecontract.ProcessExit(failure))
}
