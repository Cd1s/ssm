package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"ssm/internal/cloud"
	"ssm/internal/config"
	"ssm/internal/ssh"
)

type connectionJSON struct {
	Name  string `json:"name"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
	User  string `json:"user"`
	Group string `json:"group,omitempty"`
}

func runList(jsonOutput bool) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	if jsonOutput {
		items := make([]connectionJSON, len(v.Connections))
		for i, c := range v.Connections {
			items[i] = connectionJSON{
				Name:  c.Name,
				Host:  c.Host,
				Port:  c.Port,
				User:  c.User,
				Group: c.Group,
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(items); err != nil {
			printError(err)
			os.Exit(1)
		}
		return
	}

	if len(v.Connections) == 0 {
		fmt.Println("No connections.")
		return
	}
	for _, c := range v.Connections {
		group := ""
		if c.Group != "" {
			group = " [" + c.Group + "]"
		}
		fmt.Printf("%s\t%s@%s:%d%s\n", c.Name, c.User, c.Host, c.Port, group)
	}
}

func runRemove(name string) {
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	found := -1
	for i, c := range v.Connections {
		if c.Name == name {
			found = i
			break
		}
	}
	if found == -1 {
		fmt.Printf("Connection \"%s\" not found.\n", name)
		os.Exit(1)
	}

	v.Connections = append(v.Connections[:found], v.Connections[found+1:]...)
	if err := config.Save(v, masterPass); err != nil {
		printError(err)
		os.Exit(1)
	}
	cloud.AutoPush()
	fmt.Printf("Connection \"%s\" removed.\n", name)
}

func runExecSpec(name string, spec remoteRunSpec) {
	if len(spec.Scripts) > 1 {
		runMap([]string{name}, spec)
		return
	}
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	c, resolved, ok := resolveConnection(v, name)
	if !ok {
		connectionNotFound(name, v)
	}
	applyRunSpecEnv(spec)
	runOpts := ssh.RunOptions{
		Command:        spec.Command,
		Secrets:        spec.Secrets,
		Capture:        spec.JSON || spec.Plan,
		PlanOnly:       spec.Plan,
		NoReuse:        spec.NoReuse,
		RequestedAlias: name,
		ResolvedAlias:  resolved,
		Mode:           spec.Mode,
	}
	if len(spec.Scripts) == 1 {
		script := spec.Scripts[0]
		if spec.Preflight && !spec.Plan {
			preflight := ssh.RunScriptPreflight(c, v, script, spec.NoReuse, name, resolved)
			if !preflight.OK {
				ssh.WriteRunResult(preflight, spec.JSON)
				os.Exit(preflight.Exit)
			}
		}
		runOpts.Command = ssh.BuildScriptRunner(script)
		runOpts.Input = script.Body
		runOpts.RiskCommand = script.Body
		runOpts.Interpreter = script.Interpreter
		runOpts.ScriptLabel = script.Label
	}
	res := ssh.Run(c, v, runOpts)
	if len(spec.Scripts) == 1 && spec.Preflight {
		if spec.Plan {
			res.Preflight = "pending"
		} else {
			res.Preflight = "passed"
		}
	}
	if spec.JSON || spec.Plan {
		ssh.WriteRunResult(res, spec.JSON)
		if spec.Plan {
			os.Exit(0)
		}
		if !res.OK {
			os.Exit(res.Exit)
		}
		os.Exit(0)
	}
	os.Exit(res.Exit)
}

func runMap(targetPatterns []string, spec remoteRunSpec) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	aliases, err := config.MatchAliases(v, targetPatterns)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	if len(aliases) == 0 {
		if machineJSON {
			writeMachineError("no_targets", "no aliases matched the requested map targets", "refresh sshctl host list and use exact aliases or reviewed patterns", strings.Join(targetPatterns, ","), 2, nil)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "sshctl map: no targets matched")
		os.Exit(2)
	}
	applyRunSpecEnv(spec)
	workers := spec.Workers
	if workers <= 0 {
		workers = ssh.DefaultMapWorkers()
	}
	jobs := ssh.ExpandMapJobs(aliases, spec.Command, spec.Scripts, spec.Secrets, spec.Mode, spec.Preflight)
	if len(jobs) == 0 {
		fmt.Fprintln(os.Stderr, "sshctl map: nothing to run")
		os.Exit(2)
	}
	if spec.Plan {
		// Plan: expand jobs and print without dialing.
		var planned []ssh.RunResult
		for _, j := range jobs {
			c, resolved, ok := resolveConnection(v, j.RequestedAlias)
			remoteCommand := ssh.BuildRemoteCommand(j.Command, j.Secrets)
			if j.Input != "" {
				remoteCommand = ssh.BuildScriptRemoteCommand(j.Command, j.Secrets)
			}
			r := ssh.RunResult{
				OK:            true,
				Plan:          true,
				Alias:         j.RequestedAlias,
				ResolvedAlias: resolved,
				RemoteCommand: ssh.RedactSecrets(remoteCommand, j.Secrets),
				Risk:          ssh.AssessRisk(firstNonEmpty(j.RiskCommand, j.Command)),
				ScriptLabel:   j.ScriptLabel,
				Interpreter:   j.Interpreter,
				Mode:          j.Mode,
				Transport:     map[bool]string{true: "ssh_stdin", false: "ssh_exec"}[j.Input != ""],
				InputBytes:    len(j.Input),
			}
			if j.Input != "" {
				r.ScriptSHA256 = ssh.ScriptDigest(j.Input)
				if j.Preflight {
					r.Preflight = "pending"
				}
			}
			if ok {
				r.User, r.Host, r.Port = c.User, c.Host, c.Port
				if r.Port == 0 {
					r.Port = 22
				}
			} else {
				r.OK = false
				r.Error = ssh.ErrCodeAliasNotFound
			}
			planned = append(planned, r)
		}
		ssh.WriteMapResults(planned, spec.JSON)
		os.Exit(0)
	}
	results := ssh.Map(v, jobs, workers, spec.NoReuse)
	ssh.WriteMapResults(results, spec.JSON)
	os.Exit(ssh.MapExitCode(results))
}

type putOptions struct {
	name, localPath, remotePath string
	verifySHA256                bool
	timeout                     time.Duration
	resumeVersion               string
}

func parsePutArgs(args []string) (putOptions, error) {
	var opts putOptions
	positionals := make([]string, 0, 3)
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--json":
			machineJSON = true
		case args[i] == "--sha256":
			opts.verifySHA256 = true
		case args[i] == "--resume" && i+1 < len(args):
			i++
			opts.resumeVersion = args[i]
		case strings.HasPrefix(args[i], "--resume="):
			opts.resumeVersion = strings.TrimPrefix(args[i], "--resume=")
		case args[i] == "--timeout" && i+1 < len(args):
			i++
			duration, err := time.ParseDuration(args[i])
			if err != nil || duration <= 0 {
				return opts, fmt.Errorf("--timeout requires a positive duration")
			}
			opts.timeout = duration
		case strings.HasPrefix(args[i], "--timeout="):
			duration, err := time.ParseDuration(strings.TrimPrefix(args[i], "--timeout="))
			if err != nil || duration <= 0 {
				return opts, fmt.Errorf("--timeout requires a positive duration")
			}
			opts.timeout = duration
		case strings.HasPrefix(args[i], "-"):
			return opts, fmt.Errorf("unknown put option %q", args[i])
		default:
			positionals = append(positionals, args[i])
		}
	}
	if len(positionals) != 3 {
		return opts, fmt.Errorf("put requires alias, local path, and remote path")
	}
	if opts.resumeVersion != "" && opts.resumeVersion != "v1" {
		return opts, fmt.Errorf("--resume supports only version v1")
	}
	opts.name, opts.localPath, opts.remotePath = positionals[0], positionals[1], positionals[2]
	return opts, nil
}

func runPutArgs(args []string) {
	opts, err := parsePutArgs(args)
	if err != nil {
		writeCLIErrorStage("invalid_arguments", err.Error(), "use sshctl put <alias> <local> <remote> [--resume=v1] [--sha256] [--timeout <duration>] [--json]", "validate", 2)
		os.Exit(2)
	}
	runPutWithOptions(opts)
}

func runPutWithOptions(opts putOptions) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	c, _, ok := resolveConnection(v, opts.name)
	if !ok {
		connectionNotFound(opts.name, v)
	}
	result, err := ssh.UploadPathWithOptions(c, v, opts.localPath, opts.remotePath, ssh.UploadOptions{VerifySHA256: opts.verifySHA256, Timeout: opts.timeout, ResumeVersion: opts.resumeVersion})
	if err != nil {
		if machineJSON {
			code, stage, hint, bytesSent := ssh.ErrCodeTransfer, "remote_write", "retry after inspecting the transfer stage", result.BytesSent
			var transferErr *ssh.TransferError
			if errors.As(err, &transferErr) {
				code, stage, hint, bytesSent = transferErr.Code, transferErr.Stage, transferErr.Hint, transferErr.BytesSent
			} else {
				ce := ssh.ClassifyError(err, c)
				code, hint = ce.Code, ce.Hint
			}
			writeMachineValue(struct {
				OK        bool   `json:"ok"`
				Error     string `json:"error"`
				Message   string `json:"message"`
				Hint      string `json:"hint"`
				Exit      int    `json:"exit"`
				Stage     string `json:"stage"`
				Alias     string `json:"alias"`
				BytesSent int64  `json:"bytes_sent"`
				Integrity string `json:"integrity"`
				Atomic    bool   `json:"atomic"`
				Resume    string `json:"resume"`
			}{false, code, err.Error(), hint, ssh.ExitCodeFor(err), stage, opts.name, bytesSent, result.Integrity, result.Atomic, result.Resume})
			os.Exit(ssh.ExitCodeFor(err))
		}
		ssh.PrintAgentError(err, c)
		os.Exit(ssh.ExitCodeFor(err))
	}
	if machineJSON {
		writeMachineValue(struct {
			Action string `json:"action"`
			Alias  string `json:"alias"`
			Local  string `json:"local"`
			Remote string `json:"remote"`
			ssh.TransferResult
		}{Action: "put", Alias: opts.name, Local: opts.localPath, Remote: opts.remotePath, TransferResult: result})
	}
}

func runGet(name, remotePath, localPath string) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	c, _, ok := resolveConnection(v, name)
	if !ok {
		connectionNotFound(name, v)
	}
	if err := ssh.DownloadPath(c, v, remotePath, localPath); err != nil {
		if machineJSON {
			ce := ssh.ClassifyError(err, c)
			writeMachineError(ce.Code, ce.Error(), ce.Hint, name, ssh.ExitCodeFor(err), nil)
			os.Exit(ssh.ExitCodeFor(err))
		}
		ssh.PrintAgentError(err, c)
		os.Exit(ssh.ExitCodeFor(err))
	}
	if machineJSON {
		writeMachineValue(struct {
			OK     bool   `json:"ok"`
			Action string `json:"action"`
			Alias  string `json:"alias"`
			Remote string `json:"remote"`
			Local  string `json:"local"`
		}{OK: true, Action: "get", Alias: name, Remote: remotePath, Local: localPath})
	}
}

func runCheck(name string, asJSON bool) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	c, resolved, ok := resolveConnection(v, name)
	if !ok {
		connectionNotFound(name, v)
	}
	res := ssh.Check(c, v)
	res.Alias = name
	if resolved != name {
		// keep host fields from connection; alias shows request name
	}
	ssh.WriteCheckResult(res, asJSON)
	if !res.OK {
		os.Exit(ssh.ExitConnectionFailed)
	}
}

func runDoctor(alias string, deep, asJSON bool) {
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	rep := ssh.Doctor(v, alias, deep)
	ssh.WriteDoctorReport(rep, asJSON)
	if !rep.OK {
		os.Exit(ssh.ExitConnectionFailed)
	}
}

func runRedirect(args []string) {
	if len(args) == 0 {
		writeCLIError("invalid_arguments", "redirect action required", "use redirect list, set <old> <new>, or rm <old>", 2)
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		r := config.LoadRedirects()
		if len(r) == 0 {
			if machineJSON {
				writeMachineValue(struct {
					OK        bool              `json:"ok"`
					Redirects map[string]string `json:"redirects"`
				}{OK: true, Redirects: map[string]string{}})
				return
			}
			fmt.Println("(no redirects)")
			return
		}
		// stable order
		var keys []string
		for k := range r {
			keys = append(keys, k)
		}
		// simple sort
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				if keys[j] < keys[i] {
					keys[i], keys[j] = keys[j], keys[i]
				}
			}
		}
		if machineJSON {
			writeMachineValue(struct {
				OK        bool              `json:"ok"`
				Redirects map[string]string `json:"redirects"`
			}{OK: true, Redirects: r})
			return
		}
		for _, k := range keys {
			fmt.Printf("%s\t->\t%s\n", k, r[k])
		}
	case "set":
		if len(args) != 3 {
			writeCLIError("invalid_arguments", "redirect set requires old and target aliases", "use redirect set <old-alias> <target-alias>", 2)
			os.Exit(2)
		}
		r := config.LoadRedirects()
		r[args[1]] = args[2]
		if err := config.SaveRedirects(r); err != nil {
			printError(err)
			os.Exit(1)
		}
		if machineJSON {
			writeMachineValue(struct {
				OK     bool   `json:"ok"`
				Action string `json:"action"`
				From   string `json:"from"`
				To     string `json:"to"`
			}{OK: true, Action: "redirect_set", From: args[1], To: args[2]})
			return
		}
		fmt.Printf("redirect %s -> %s\n", args[1], args[2])
	case "rm", "remove":
		if len(args) != 2 {
			writeCLIError("invalid_arguments", "redirect remove requires an old alias", "use redirect rm <old-alias>", 2)
			os.Exit(2)
		}
		r := config.LoadRedirects()
		delete(r, args[1])
		if err := config.SaveRedirects(r); err != nil {
			printError(err)
			os.Exit(1)
		}
		if machineJSON {
			writeMachineValue(struct {
				OK     bool   `json:"ok"`
				Action string `json:"action"`
				Alias  string `json:"alias"`
			}{OK: true, Action: "redirect_removed", Alias: args[1]})
			return
		}
		fmt.Printf("removed redirect %s\n", args[1])
	default:
		writeCLIError("invalid_arguments", fmt.Sprintf("unknown redirect action %q", args[0]), "use redirect list, set, or rm", 2)
		os.Exit(2)
	}
}

func resolveConnection(v *config.Vault, name string) (config.Connection, string, bool) {
	return config.ResolveAlias(v, name)
}

func connectionNotFound(name string, v *config.Vault) {
	var suggestions []string
	if v != nil {
		names := make([]string, len(v.Connections))
		for i, c := range v.Connections {
			names[i] = c.Name
		}
		suggestions = ssh.SuggestNames(name, names, 5)
	}
	if machineJSON {
		writeMachineError(ssh.ErrCodeAliasNotFound, fmt.Sprintf("connection %q not found", name), "use sshctl host list --json and retry with an exact alias", name, ssh.ExitConnectionFailed, suggestions)
		os.Exit(ssh.ExitConnectionFailed)
	}
	fmt.Fprintf(os.Stderr, "ssm: error=%s alias=%s\n", ssh.ErrCodeAliasNotFound, name)
	fmt.Fprintf(os.Stderr, "Connection %q not found.\n", name)
	if len(suggestions) > 0 {
		fmt.Fprintf(os.Stderr, "ssm: did_you_mean=%s\n", strings.Join(suggestions, ","))
		fmt.Fprintf(os.Stderr, "Did you mean: %s\n", strings.Join(suggestions, ", "))
	}
	fmt.Fprintf(os.Stderr, "ssm: hint=use sshctl host list --json; or ssm redirect set <old> <new> after migration\n")
	os.Exit(ssh.ExitConnectionFailed)
}

func runImportJSON(args []string) {
	opts, err := parseImportJSONArgs(args)
	if err != nil {
		machineJSON = machineJSON || opts.asJSON || hasJSONFlagBeforeDash(args)
		writeCLIError("invalid_arguments", err.Error(), "use exactly one of --merge or --replace --yes", 2)
		if !machineJSON {
			fmt.Fprintln(os.Stderr, "Usage: ssm import-json <path> (--merge | --replace --yes) [--manifest <path>] [--expect-count <n>] [--json]")
		}
		os.Exit(2)
	}
	machineJSON = machineJSON || opts.asJSON

	imported, err := loadServerImport(opts.path, opts.manifestPath)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	if opts.expectCount > 0 && len(imported.Connections) != opts.expectCount {
		writeCLIError("import_count_mismatch", fmt.Sprintf("imported host count %d does not match expected %d", len(imported.Connections), opts.expectCount), "review the import source and expected count before retrying", 1)
		os.Exit(1)
	}

	current, err := config.Load(masterPass)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
	conflicts := []config.MergeConflict{}
	if opts.replace {
		current.Connections = imported.Connections
		current.Keys = imported.Keys
	} else {
		var report config.MergeReport
		current, report = config.MergeVaultsWithReport(current, imported)
		conflicts = report.Conflicts
		if err := config.SaveMergeReport(report); err != nil {
			writeCLIError("merge_report_error", redactError(err), "vault was not changed; verify config directory permissions", 1)
			os.Exit(1)
		}
	}

	if err := config.Save(current, masterPass); err != nil {
		printError(err)
		os.Exit(1)
	}

	if machineJSON {
		writeMachineValue(struct {
			OK          bool                   `json:"ok"`
			Action      string                 `json:"action"`
			Connections int                    `json:"connections"`
			Keys        int                    `json:"keys"`
			Conflicts   []config.MergeConflict `json:"conflicts,omitempty"`
		}{OK: true, Action: map[bool]string{true: "replaced", false: "merged"}[opts.replace], Connections: len(imported.Connections), Keys: len(imported.Keys), Conflicts: conflicts})
		return
	}
	fmt.Printf("Imported %d connections and %d keys.\n", len(imported.Connections), len(imported.Keys))
}

type importJSONOptions struct {
	path         string
	manifestPath string
	expectCount  int
	replace      bool
	modeSet      bool
	confirm      bool
	asJSON       bool
}

func parseImportJSONArgs(args []string) (importJSONOptions, error) {
	var opts importJSONOptions
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--manifest":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--manifest requires a path")
			}
			opts.manifestPath = args[i+1]
			i++
		case strings.HasPrefix(arg, "--manifest="):
			opts.manifestPath = strings.TrimPrefix(arg, "--manifest=")
		case arg == "--expect-count":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--expect-count requires a number")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return opts, fmt.Errorf("--expect-count: %w", err)
			}
			if n < 0 {
				return opts, fmt.Errorf("--expect-count must be non-negative")
			}
			opts.expectCount = n
			i++
		case strings.HasPrefix(arg, "--expect-count="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "--expect-count="))
			if err != nil {
				return opts, fmt.Errorf("--expect-count: %w", err)
			}
			if n < 0 {
				return opts, fmt.Errorf("--expect-count must be non-negative")
			}
			opts.expectCount = n
		case arg == "--replace":
			if opts.modeSet && !opts.replace {
				return opts, fmt.Errorf("use only one of --merge or --replace")
			}
			opts.replace = true
			opts.modeSet = true
		case arg == "--merge":
			if opts.modeSet && opts.replace {
				return opts, fmt.Errorf("use only one of --merge or --replace")
			}
			opts.replace = false
			opts.modeSet = true
		case arg == "--yes":
			opts.confirm = true
		case arg == "--json":
			opts.asJSON = true
		case strings.HasPrefix(arg, "-"):
			return opts, fmt.Errorf("unknown flag %s", arg)
		default:
			if opts.path != "" {
				return opts, fmt.Errorf("multiple import paths provided")
			}
			opts.path = arg
		}
	}
	if opts.path == "" {
		return opts, fmt.Errorf("import path required")
	}
	if !opts.modeSet {
		return opts, fmt.Errorf("import mode required: use --merge or --replace --yes")
	}
	if opts.replace && !opts.confirm {
		return opts, fmt.Errorf("full vault replacement requires --replace --yes")
	}
	if !opts.replace && opts.confirm {
		return opts, fmt.Errorf("--yes is only valid with --replace")
	}
	return opts, nil
}
