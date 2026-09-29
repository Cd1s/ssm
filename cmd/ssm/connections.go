package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"ssm/internal/config"
	"ssm/internal/inventorytransaction"
	"ssm/internal/machinecontract"
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
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
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
		writeMachineValue(items)
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
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}

	result, err := inventorytransaction.New(inventorytransaction.Options{
		MasterPass: masterPass,
	}).ApplyHost(v, inventorytransaction.HostChange{
		Action: inventorytransaction.HostRemove,
		Alias:  name,
	})
	if err != nil {
		if failure, ok := machinecontract.FailureFromError(err); ok &&
			failure.Error == machinecontract.CodeAliasNotFound {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{
				Message: fmt.Sprintf("connection %q not found", name),
				Alias:   name,
				Tool:    "legacy_not_found",
				Script:  "connection",
			}))
		}
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	if machineJSON {
		writeMachineValue(result)
		return
	}
	fmt.Printf("Connection \"%s\" removed.\n", name)
}

func runExecSpec(name string, spec remoteRunSpec) {
	if len(spec.Scripts) > 1 {
		runMap([]string{name}, spec)
		return
	}
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}

	res := executeRunSpec(v, name, spec)
	if res.Error == machinecontract.CodeAliasNotFound {
		connectionNotFound(name, v)
	}
	if res.Preflight == "failed" && !spec.JSON && !spec.Plan {
		ssh.WriteRunResult(res, false)
		os.Exit(machinecontract.ResultExit(machinecontract.ResultState{OK: res.OK, Exit: res.Exit}))
	}
	if spec.JSON || spec.Plan {
		ssh.WriteRunResult(res, spec.JSON)
		if spec.Plan {
			os.Exit(0)
		}
		if !res.OK {
			os.Exit(machinecontract.ResultExit(machinecontract.ResultState{OK: res.OK, Exit: res.Exit}))
		}
		os.Exit(0)
	}
	os.Exit(machinecontract.ResultExit(machinecontract.ResultState{OK: res.OK, Exit: res.Exit}))
}

// executeRunSpec performs one already-parsed run without syncing, decrypting,
// printing, or exiting. The streaming fast path uses it repeatedly with the
// same vault and process-local SSH pool.
func executeRunSpec(v *config.Vault, name string, spec remoteRunSpec) ssh.RunResult {
	c, resolved, ok := resolveConnection(v, name)
	if !ok {
		failure := machinecontract.Classify(machinecontract.RunAliasNotFound, machinecontract.Details{
			Message: fmt.Sprintf("connection %q not found", name),
			Alias:   name,
		})
		return ssh.RunResult{
			OK:             false,
			Alias:          name,
			Exit:           machinecontract.ProcessExit(failure),
			ResultMetadata: failure.ResultMetadata(),
			InventoryStale: inventoryStale, InventoryUnsynced: inventoryUnsynced,
			InventorySyncError: inventorySyncError,
		}
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
		Stdin:          spec.Stdin,
		StdinFile:      spec.StdinFile,
	}
	if len(spec.Scripts) == 1 {
		script := spec.Scripts[0]
		if spec.Preflight && !spec.Plan {
			preflight := ssh.RunScriptPreflight(c, v, script, spec.NoReuse, name, resolved)
			if !preflight.OK {
				return preflight
			}
		}
		runOpts.Command = ssh.BuildScriptRunner(script)
		runOpts.Input = script.Body
		runOpts.RiskCommand = script.Body
		runOpts.Interpreter = script.Interpreter
		runOpts.ScriptLabel = script.Label
	}
	res := ssh.Run(c, v, runOpts)
	res.InventoryStale, res.InventoryUnsynced, res.InventorySyncError = inventoryStale, inventoryUnsynced, inventorySyncError
	if len(spec.Scripts) == 1 && spec.Preflight {
		if spec.Plan {
			res.Preflight = "pending"
		} else {
			res.Preflight = "passed"
		}
	}
	return res
}

func runMap(targetPatterns []string, spec remoteRunSpec) {
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	aliases, err := config.MatchAliases(v, targetPatterns)
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	if len(aliases) == 0 {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.MapNoTargets, machinecontract.Details{
			Message: "no aliases matched the requested map targets", Alias: strings.Join(targetPatterns, ","),
		}))
	}
	applyRunSpecEnv(spec)
	workers := spec.Workers
	if workers <= 0 {
		workers = ssh.DefaultMapWorkers()
	}
	jobs := ssh.ExpandMapJobs(aliases, spec.Command, spec.Scripts, spec.Secrets, spec.Mode, spec.Preflight)
	if len(jobs) == 0 {
		os.Exit(machinecontract.WriteClassified(machineJSON || spec.JSON, machinecontract.InvalidSSHCTLArguments, machinecontract.Details{
			Message: "sshctl map: nothing to run", Tool: "legacy_message", Script: "map_empty",
		}))
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
				r.Error = machinecontract.Classify(machinecontract.MapAliasNotFound, machinecontract.Details{
					Message: "requested alias was not found",
					Alias:   j.RequestedAlias,
				}).Error
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
	dirMode                     os.FileMode
	// transfer overrides the host's transfer mode for this operation: "" keeps
	// the host setting, "shell" or "sftp" force that protocol.
	transfer string
	sftp     bool
}

// parseRequestTransfer validates the request-v1 transfer field. "auto" and the
// empty value keep the host setting.
func parseRequestTransfer(value string) (string, error) {
	mode, ok := config.NormalizeTransfer(value)
	if !ok {
		return "", fmt.Errorf("transfer must be auto, shell, or sftp")
	}
	return mode, nil
}

// withTransferOverride applies a per-operation protocol choice to a resolved
// connection copy; the stored host setting is never modified.
func withTransferOverride(c config.Connection, transfer string, sftp bool) config.Connection {
	switch {
	case sftp:
		c.Transfer = config.TransferSFTP
	case transfer != "":
		c.Transfer = transfer
	}
	return c
}

var errInvalidDirMode = errors.New("invalid --dir-mode")

// parseDirMode parses an octal directory permission such as 0755 or 750.
func parseDirMode(value string) (os.FileMode, error) {
	mode, err := strconv.ParseUint(strings.TrimSpace(value), 8, 32)
	if err != nil || mode > 0o777 {
		return 0, fmt.Errorf("%w: %q must be an octal permission such as 0755 (at most 0777)", errInvalidDirMode, value)
	}
	if mode&0o300 != 0o300 {
		return 0, fmt.Errorf("%w: %q lacks owner write and execute (0300), so creating nested directories would fail", errInvalidDirMode, value)
	}
	return os.FileMode(mode), nil
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
		case args[i] == "--sftp":
			opts.sftp = true
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
		case args[i] == "--dir-mode" && i+1 < len(args):
			i++
			mode, err := parseDirMode(args[i])
			if err != nil {
				return opts, err
			}
			opts.dirMode = mode
		case strings.HasPrefix(args[i], "--dir-mode="):
			mode, err := parseDirMode(strings.TrimPrefix(args[i], "--dir-mode="))
			if err != nil {
				return opts, err
			}
			opts.dirMode = mode
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
		kind := machinecontract.TransferArgumentsInvalid
		if errors.Is(err, errInvalidDirMode) {
			kind = machinecontract.TransferDirModeInvalid
		}
		os.Exit(machinecontract.WriteClassified(machineJSON, kind, machinecontract.Details{Cause: err}))
	}
	runPutWithOptions(opts)
}

func runPutWithOptions(opts putOptions) {
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}

	c, _, ok := resolveConnection(v, opts.name)
	if !ok {
		connectionNotFound(opts.name, v)
	}
	c = withTransferOverride(c, opts.transfer, opts.sftp)
	result, err := ssh.UploadPathWithOptions(c, v, opts.localPath, opts.remotePath, ssh.UploadOptions{VerifySHA256: opts.verifySHA256, Timeout: opts.timeout, ResumeVersion: opts.resumeVersion, DirMode: opts.dirMode})
	if err != nil {
		context := machinecontract.SSHContext{Alias: c.Name, Host: c.Host, Port: c.Port}
		bytesSent := result.BytesSent
		carried := machinecontract.Failure{}
		var transferErr *ssh.TransferError
		if errors.As(err, &transferErr) {
			bytesSent = transferErr.BytesSent
			carried = transferErr.ContractFailure()
		}
		failure := machinecontract.ClassifyTransferOperation(err, context, carried)
		if machineJSON {
			atomic := result.Atomic
			sent := bytesSent
			document := machinecontract.TransferFailureOutcome(failure, machinecontract.TransferOutcome{
				Direction: result.Direction, Kind: result.Kind, Alias: opts.name,
				BytesSent: &sent, Integrity: result.Integrity, Atomic: &atomic, Resume: result.Resume,
			})
			os.Exit(machinecontract.WriteFailure(true, failure, document))
		}
		_ = machinecontract.WriteHuman(failure)
		os.Exit(machinecontract.ProcessExit(failure))
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

type getOptions struct {
	name, remotePath, localPath string
	verifySHA256                bool
	timeout                     time.Duration
	transfer                    string
	sftp                        bool
}

// parseGetArgs accepts the flag set shared with put (except --resume and
// --dir-mode) in any position around the three positional arguments.
func parseGetArgs(args []string) (getOptions, error) {
	var opts getOptions
	positionals := make([]string, 0, 3)
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--json":
			machineJSON = true
		case args[i] == "--sha256":
			opts.verifySHA256 = true
		case args[i] == "--sftp":
			opts.sftp = true
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
		case args[i] == "--resume" || strings.HasPrefix(args[i], "--resume="):
			return opts, fmt.Errorf("get does not support --resume")
		case strings.HasPrefix(args[i], "-"):
			return opts, fmt.Errorf("unknown get option %q", args[i])
		default:
			positionals = append(positionals, args[i])
		}
	}
	if len(positionals) != 3 {
		return opts, fmt.Errorf("get requires alias, remote path, and local path")
	}
	opts.name, opts.remotePath, opts.localPath = positionals[0], positionals[1], positionals[2]
	return opts, nil
}

func runGetArgs(args []string) {
	opts, err := parseGetArgs(args)
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GetArgumentsInvalid, machinecontract.Details{Cause: err}))
	}
	runGet(opts)
}

func runGet(opts getOptions) {
	name, remotePath, localPath := opts.name, opts.remotePath, opts.localPath
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}

	c, _, ok := resolveConnection(v, name)
	if !ok {
		connectionNotFound(name, v)
	}
	c = withTransferOverride(c, opts.transfer, opts.sftp)
	result, err := ssh.DownloadPathWithOptions(c, v, remotePath, localPath, ssh.DownloadOptions{VerifySHA256: opts.verifySHA256, Timeout: opts.timeout})
	if err != nil {
		context := machinecontract.SSHContext{
			Alias: name, ResolvedAlias: c.Name, Host: c.Host, Port: c.Port, Stage: result.Stage,
		}
		failure := machinecontract.ClassifyDownload(err, context)
		if machineJSON {
			var atomic *bool
			var received *int64
			if result.Kind == "file" || result.Kind == "directory" {
				atomic = &result.Atomic
			}
			if result.Kind == "file" {
				received = &result.BytesReceived
			}
			document := machinecontract.TransferFailureOutcome(failure, machinecontract.TransferOutcome{
				Direction: result.Direction, Kind: result.Kind, Alias: name,
				Remote: remotePath, Local: localPath, BytesReceived: received,
				Integrity: result.Integrity, Atomic: atomic, Resume: result.Resume,
				LocalSHA256: result.LocalSHA256, RemoteSHA256: result.RemoteSHA256,
			})
			os.Exit(machinecontract.WriteFailure(true, failure, document))
		}
		_ = machinecontract.WriteHuman(failure)
		os.Exit(machinecontract.ProcessExit(failure))
	}
	if machineJSON {
		atomic := result.Atomic
		var received *int64
		if result.Kind == "file" {
			received = &result.BytesReceived
		}
		writeMachineValue(machinecontract.TransferOutcome{
			OK: true, Action: "get", Direction: result.Direction, Kind: result.Kind,
			Alias: name, Remote: remotePath, Local: localPath, Stage: result.Stage,
			BytesReceived: received, Integrity: result.Integrity, Atomic: &atomic, Resume: result.Resume,
			LocalSHA256: result.LocalSHA256, RemoteSHA256: result.RemoteSHA256,
		})
	}
}

func runCheck(name string, asJSON bool) {
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}

	c, _, ok := resolveConnection(v, name)
	if !ok {
		connectionNotFound(name, v)
	}
	res := ssh.Check(c, v)
	res.Alias = name
	ssh.WriteCheckResult(res, asJSON)
	if !res.OK {
		os.Exit(machinecontract.ConnectionResultExit(res.OK))
	}
}

func runDoctor(alias string, deep, asJSON bool) {
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	syncFacts := syncTransaction(false).Facts()
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	rep := ssh.Doctor(v, alias, deep, syncFacts)
	ssh.WriteDoctorReport(rep, asJSON)
	if !rep.OK {
		os.Exit(machinecontract.ConnectionResultExit(rep.OK))
	}
}

func runRedirect(args []string) {
	if len(args) == 0 {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.RedirectActionRequired, machinecontract.Details{Message: "redirect action required"}))
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
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.RedirectSetArgumentsInvalid, machinecontract.Details{
				Message: "redirect set requires old and target aliases",
			}))
		}
		r := config.LoadRedirects()
		r[args[1]] = args[2]
		if err := config.SaveRedirects(r); err != nil {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
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
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.RedirectRemoveArgumentsInvalid, machinecontract.Details{
				Message: "redirect remove requires an old alias",
			}))
		}
		r := config.LoadRedirects()
		delete(r, args[1])
		if err := config.SaveRedirects(r); err != nil {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
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
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.RedirectActionInvalid, machinecontract.Details{
			Message: fmt.Sprintf("unknown redirect action %q", args[0]),
		}))
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
	// "sshctl <alias> <cmd>" shorthand: the word may be a mistyped command
	// rather than an alias. This runs only after the exact alias lookup missed
	// and reuses the already-loaded vault, so it never unlocks or connects.
	if aliasShorthand {
		if suggestion, ok := suggestCommand(true, name); ok && !aliasIsCloser(name, suggestion, v, config.LoadRedirects()) {
			exitUnknownCommandSuggestion(true, name, suggestion)
		}
	}
	exit := machinecontract.WriteClassified(machineJSON, machinecontract.AliasNotFound, machinecontract.Details{
		Message: fmt.Sprintf("connection %q not found", name), Alias: name, Candidates: suggestions,
	})
	os.Exit(exit)
}

func runImportJSON(args []string) {
	opts, err := parseImportJSONArgs(args)
	if err != nil {
		machineJSON = machineJSON || opts.asJSON || hasJSONFlagBeforeDash(args)
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.ImportArgumentsInvalid, machinecontract.Details{Cause: err}))
	}
	machineJSON = machineJSON || opts.asJSON
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}

	imported, err := loadServerImport(opts.path, opts.manifestPath)
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	if opts.expectCount > 0 && len(imported.Connections) != opts.expectCount {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.ImportCountMismatch, machinecontract.Details{
			Message: fmt.Sprintf("imported host count %d does not match expected %d", len(imported.Connections), opts.expectCount),
		}))
	}

	current, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	result, err := inventorytransaction.New(inventorytransaction.Options{
		MasterPass: masterPass,
	}).ApplyImport(current, imported, opts.replace)
	if err != nil {
		var mergeReportError *inventorytransaction.MergeReportError
		if errors.As(err, &mergeReportError) {
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.MergeReportFailed, machinecontract.Details{Cause: err}))
		}
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}

	if machineJSON {
		writeMachineValue(result)
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
