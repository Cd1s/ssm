package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"ssm/internal/ssh"
)

const maxAgentRequestBytes = 1 << 20

type agentRequest struct {
	Version      int               `json:"version"`
	Op           string            `json:"op"`
	Alias        string            `json:"alias,omitempty"`
	Argv         []string          `json:"argv,omitempty"`
	ShellCommand *string           `json:"shell_command,omitempty"`
	ScriptFile   string            `json:"script_file,omitempty"`
	ScriptArgs   []string          `json:"script_args,omitempty"`
	Shell        string            `json:"shell,omitempty"`
	SecretFiles  map[string]string `json:"secret_files,omitempty"`
	Timeout      string            `json:"timeout,omitempty"`
	NoReuse      bool              `json:"no_reuse,omitempty"`
	Preflight    *bool             `json:"preflight,omitempty"`
	Deep         bool              `json:"deep,omitempty"`
	Host         *agentHostRequest `json:"host,omitempty"`
	LocalPath    string            `json:"local_path,omitempty"`
	RemotePath   string            `json:"remote_path,omitempty"`
	Resume       string            `json:"resume,omitempty"`
	SHA256       bool              `json:"sha256,omitempty"`
}

type agentHostRequest struct {
	Address      *string `json:"address,omitempty"`
	Port         *int    `json:"port,omitempty"`
	User         *string `json:"user,omitempty"`
	Group        *string `json:"group,omitempty"`
	SavedKey     *string `json:"saved_key,omitempty"`
	KeyFile      *string `json:"key_file,omitempty"`
	KeyName      *string `json:"key_name,omitempty"`
	PasswordFile *string `json:"password_file,omitempty"`
	Offline      bool    `json:"offline,omitempty"`
	Verify       *bool   `json:"verify,omitempty"`
	Push         bool    `json:"push,omitempty"`
	Confirm      bool    `json:"confirm,omitempty"`
	PruneKey     bool    `json:"prune_key,omitempty"`
}

func runAgentRequest(args []string) {
	machineJSON = true
	req, err := loadAgentRequest(args)
	if err != nil {
		writeMachineError("invalid_request", err.Error(), "use schema version 1 and exactly one typed operation", "", 2, nil)
		os.Exit(2)
	}

	switch req.Op {
	case "run", "plan":
		spec, err := requestRunSpec(req)
		if err != nil {
			writeMachineError("invalid_request", err.Error(), "use exactly one of argv, shell_command, or script_file", req.Alias, 2, nil)
			os.Exit(2)
		}
		unlock()
		if req.Op == "plan" {
			spec.Plan = true
		}
		runExecSpec(req.Alias, spec)
	case "check":
		if err := validateRequestAlias(req); err != nil {
			writeMachineError("invalid_request", err.Error(), "provide one exact inventory alias", req.Alias, 2, nil)
			os.Exit(2)
		}
		if err := rejectRunRequestFields(req); err != nil {
			writeMachineError("invalid_request", err.Error(), "check accepts only version, op, and alias", req.Alias, 2, nil)
			os.Exit(2)
		}
		unlock()
		runCheck(req.Alias, true)
	case "doctor":
		if req.Host != nil || hasRunRequestFields(req) {
			writeMachineError("invalid_request", "doctor does not accept run or host mutation fields", "use alias and optional deep only", req.Alias, 2, nil)
			os.Exit(2)
		}
		if req.Alias != "" {
			if err := validateRequestAlias(req); err != nil {
				writeMachineError("invalid_request", err.Error(), "doctor alias must be an exact inventory name", req.Alias, 2, nil)
				os.Exit(2)
			}
		}
		unlock()
		runDoctor(req.Alias, req.Deep, true)
	case "host.list", "host.search", "host.show", "host.add", "host.update", "host.upsert", "host.remove":
		hostArgs, err := requestHostArgs(req)
		if err != nil {
			writeMachineError("invalid_request", err.Error(), "host operations accept structured host fields and file-based credentials only", req.Alias, 2, nil)
			os.Exit(2)
		}
		unlock()
		runHostCommand(hostArgs)
	case "put":
		if err := validateRequestAlias(req); err != nil {
			writeMachineError("invalid_request", err.Error(), "provide one exact inventory alias", req.Alias, 2, nil)
			os.Exit(2)
		}
		if req.Host != nil || req.Deep || req.Argv != nil || req.ShellCommand != nil || req.ScriptFile != "" || len(req.ScriptArgs) > 0 || req.Shell != "" || len(req.SecretFiles) > 0 || req.NoReuse || req.Preflight != nil {
			writeMachineError("invalid_request", "put accepts only alias, local_path, remote_path, resume, sha256, and timeout", "use file paths; never place file contents or credentials in the request", req.Alias, 2, nil)
			os.Exit(2)
		}
		if strings.TrimSpace(req.LocalPath) == "" || strings.TrimSpace(req.RemotePath) == "" || (req.Resume != "" && req.Resume != "v1") {
			writeMachineError("invalid_request", "put requires local_path and remote_path; resume supports only v1", "use resume:\"v1\" explicitly for regular-file retry", req.Alias, 2, nil)
			os.Exit(2)
		}
		timeout := time.Duration(0)
		if req.Timeout != "" {
			var err error
			timeout, err = parseCLITimeout(req.Timeout)
			if err != nil {
				writeMachineError("invalid_request", err.Error(), "timeout must be a positive duration", req.Alias, 2, nil)
				os.Exit(2)
			}
		}
		unlock()
		runPutWithOptions(putOptions{name: req.Alias, localPath: req.LocalPath, remotePath: req.RemotePath, resumeVersion: req.Resume, verifySHA256: req.SHA256, timeout: timeout})
	default:
		writeMachineError("invalid_request", fmt.Sprintf("unsupported request op %q", req.Op), "use run, plan, check, doctor, put, or host.list/search/show/add/update/upsert/remove", req.Alias, 2, nil)
		os.Exit(2)
	}
}

func loadAgentRequest(args []string) (agentRequest, error) {
	path := "-"
	pathSet := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--file":
			if pathSet {
				return agentRequest{}, fmt.Errorf("request input may be specified only once")
			}
			if i+1 >= len(args) {
				return agentRequest{}, fmt.Errorf("--file requires a path or -")
			}
			path = args[i+1] //nolint:gosec // length is checked immediately above
			pathSet = true
			i++
		case strings.HasPrefix(args[i], "--file="):
			if pathSet {
				return agentRequest{}, fmt.Errorf("request input may be specified only once")
			}
			path = strings.TrimPrefix(args[i], "--file=")
			pathSet = true
		case args[i] == "-" && len(args) == 1:
			path = "-"
			pathSet = true
		default:
			return agentRequest{}, fmt.Errorf("unknown request option %q", args[i])
		}
	}
	if path == "" {
		return agentRequest{}, fmt.Errorf("request file path is empty")
	}

	var reader io.Reader = os.Stdin
	var file *os.File
	if path != "-" {
		var err error
		file, err = os.Open(path) //nolint:gosec // explicit request input
		if err != nil {
			return agentRequest{}, fmt.Errorf("open request file: %w", err)
		}
		defer func() { _ = file.Close() }()
		reader = file
	}

	limited := io.LimitReader(reader, maxAgentRequestBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return agentRequest{}, fmt.Errorf("read request: %w", err)
	}
	if len(data) > maxAgentRequestBytes {
		return agentRequest{}, fmt.Errorf("request exceeds %d bytes", maxAgentRequestBytes)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var req agentRequest
	if err := dec.Decode(&req); err != nil {
		return agentRequest{}, fmt.Errorf("decode request JSON: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return agentRequest{}, fmt.Errorf("request must contain exactly one JSON object")
		}
		return agentRequest{}, fmt.Errorf("trailing request data: %w", err)
	}
	if req.Version != 1 {
		return agentRequest{}, fmt.Errorf("unsupported request version %d; expected 1", req.Version)
	}
	if strings.TrimSpace(req.Op) == "" {
		return agentRequest{}, fmt.Errorf("request op is required")
	}
	return req, nil
}

func requestRunSpec(req agentRequest) (remoteRunSpec, error) {
	if err := validateRequestAlias(req); err != nil {
		return remoteRunSpec{}, err
	}
	if req.Host != nil || req.Deep || req.LocalPath != "" || req.RemotePath != "" || req.Resume != "" || req.SHA256 {
		return remoteRunSpec{}, fmt.Errorf("run requests do not accept host or deep fields")
	}
	sources := 0
	if req.Argv != nil {
		sources++
	}
	if req.ShellCommand != nil {
		sources++
	}
	if req.ScriptFile != "" {
		sources++
	}
	if sources != 1 {
		return remoteRunSpec{}, fmt.Errorf("exactly one of argv, shell_command, or script_file is required")
	}

	spec := remoteRunSpec{JSON: true, NoReuse: req.NoReuse, Secrets: map[string]string{}}

	switch {
	case req.Argv != nil:
		if len(req.Argv) == 0 {
			return remoteRunSpec{}, fmt.Errorf("argv must contain at least one item")
		}
		if req.Shell != "" || len(req.ScriptArgs) > 0 || req.Preflight != nil {
			return remoteRunSpec{}, fmt.Errorf("shell, script_args, and preflight are only valid with script_file")
		}
		for _, arg := range req.Argv {
			if strings.IndexByte(arg, 0) >= 0 {
				return remoteRunSpec{}, fmt.Errorf("argv contains a NUL byte")
			}
		}
		spec.Command = ssh.JoinRemoteArgv(req.Argv)
		spec.FromArgs = true
		spec.Mode = "argv"
	case req.ShellCommand != nil:
		if req.Shell != "" || len(req.ScriptArgs) > 0 || req.Preflight != nil {
			return remoteRunSpec{}, fmt.Errorf("shell, script_args, and preflight are only valid with script_file")
		}
		if strings.TrimSpace(*req.ShellCommand) == "" || strings.IndexByte(*req.ShellCommand, 0) >= 0 {
			return remoteRunSpec{}, fmt.Errorf("shell_command must be non-empty and contain no NUL byte")
		}
		spec.Command = *req.ShellCommand
		spec.FromArgs = true
		spec.Mode = "shell_command"
	case req.ScriptFile != "":
		data, err := readScriptFile(req.ScriptFile)
		if err != nil {
			return remoteRunSpec{}, fmt.Errorf("read script file %s: %w", req.ScriptFile, err)
		}
		script, err := ssh.PrepareScript(req.ScriptFile, data, req.Shell, req.ScriptArgs)
		if err != nil {
			return remoteRunSpec{}, fmt.Errorf("script file %s: %w", req.ScriptFile, err)
		}
		spec.Scripts = []ssh.ScriptSpec{script}
		spec.Mode = "script"
		spec.Preflight = true
		if req.Preflight != nil {
			spec.Preflight = *req.Preflight
		}
	}
	if req.Timeout != "" {
		timeout, err := parseCLITimeout(req.Timeout)
		if err != nil {
			return remoteRunSpec{}, err
		}
		spec.Timeout = timeout
	}
	for _, name := range sortedRequestKeys(req.SecretFiles) {
		path := req.SecretFiles[name]
		if strings.TrimSpace(path) == "" {
			return remoteRunSpec{}, fmt.Errorf("secret_files[%q] path is empty", name)
		}
		if err := parseSecretKV(name+"=@"+path, spec.Secrets); err != nil {
			return remoteRunSpec{}, err
		}
	}
	return spec, nil
}

func requestHostArgs(req agentRequest) ([]string, error) {
	if hasRunRequestFields(req) || req.Deep {
		return nil, fmt.Errorf("host requests do not accept run or deep fields")
	}
	action := strings.TrimPrefix(req.Op, "host.")
	args := []string{action}
	if action != "list" {
		if err := validateRequestAlias(req); err != nil {
			return nil, err
		}
		args = append(args, req.Alias)
	} else if req.Alias != "" {
		return nil, fmt.Errorf("host.list does not accept alias")
	}
	host := req.Host
	if host == nil {
		host = &agentHostRequest{}
	}
	appendString := func(flag string, value *string) {
		if value != nil {
			args = append(args, flag, *value)
		}
	}
	appendString("--host", host.Address)
	if host.Port != nil {
		args = append(args, "--port", strconv.Itoa(*host.Port))
	}
	appendString("--user", host.User)
	appendString("--group", host.Group)
	appendString("--key", host.SavedKey)
	appendString("--key-file", host.KeyFile)
	appendString("--key-name", host.KeyName)
	appendString("--password-file", host.PasswordFile)
	if host.Offline {
		args = append(args, "--offline")
	}
	verify := action == "add" || action == "update" || action == "upsert"
	if host.Verify != nil {
		verify = *host.Verify
	}
	if verify {
		args = append(args, "--verify")
	}
	if host.Push {
		args = append(args, "--push")
	}
	if host.Confirm {
		args = append(args, "--yes")
	}
	if host.PruneKey {
		args = append(args, "--prune-key")
	}
	args = append(args, "--json")
	return args, nil
}

func validateRequestAlias(req agentRequest) error {
	if strings.TrimSpace(req.Alias) == "" || strings.HasPrefix(req.Alias, "-") || strings.IndexByte(req.Alias, 0) >= 0 {
		return fmt.Errorf("exact alias is required")
	}
	return nil
}

func hasRunRequestFields(req agentRequest) bool {
	return req.Argv != nil || req.ShellCommand != nil || req.ScriptFile != "" || len(req.ScriptArgs) > 0 ||
		req.Shell != "" || len(req.SecretFiles) > 0 || req.Timeout != "" || req.NoReuse || req.Preflight != nil ||
		req.LocalPath != "" || req.RemotePath != "" || req.Resume != "" || req.SHA256
}

func rejectRunRequestFields(req agentRequest) error {
	if req.Host != nil || req.Deep || hasRunRequestFields(req) {
		return fmt.Errorf("operation contains fields that are not valid for check")
	}
	return nil
}

func sortedRequestKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
