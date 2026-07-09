package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"ssm/internal/ssh"
)

// remoteRunSpec is the resolved remote command for sshctl run / ssm exec.
type remoteRunSpec struct {
	Command string
	Trace   bool
}

// parseRemoteRunArgs parses options and command parts after the host alias.
//
// Supported forms:
//
//	<command...>                 # multi-arg: argv-safe quoting; 1 arg: shell script
//	-- <command...>              # same, after end-of-options
//	--raw <command...>           # OpenSSH-style space join, no quoting
//	-s | --script                # read remote script from stdin (heredoc-friendly)
//	-f <path> | --file <path>    # read remote script from a local file
//	--trace | -v                 # print exact remote command line to stderr
func parseRemoteRunArgs(args []string) (remoteRunSpec, error) {
	var (
		raw       bool
		fromStdin bool
		filePath  string
		trace     bool
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
		case arg == "-s", arg == "--script":
			fromStdin = true
		case arg == "-f", arg == "--file":
			if i+1 >= len(args) {
				return remoteRunSpec{}, fmt.Errorf("%s requires a path", arg)
			}
			i++
			filePath = args[i]
		case strings.HasPrefix(arg, "--file="):
			filePath = strings.TrimPrefix(arg, "--file=")
			if filePath == "" {
				return remoteRunSpec{}, fmt.Errorf("--file requires a path")
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

	sources := 0
	if fromStdin {
		sources++
	}
	if filePath != "" {
		sources++
	}
	if len(parts) > 0 {
		sources++
	}
	if sources == 0 {
		return remoteRunSpec{}, fmt.Errorf("missing remote command (use args, -s/--script, or -f/--file)")
	}
	if sources > 1 {
		return remoteRunSpec{}, fmt.Errorf("use only one of: command args, -s/--script, or -f/--file")
	}
	if raw && (fromStdin || filePath != "") {
		return remoteRunSpec{}, fmt.Errorf("--raw cannot be combined with -s/--script or -f/--file")
	}

	var cmd string
	switch {
	case fromStdin:
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return remoteRunSpec{}, fmt.Errorf("read stdin script: %w", err)
		}
		cmd = strings.TrimRight(string(data), "\r\n")
		if strings.TrimSpace(cmd) == "" {
			return remoteRunSpec{}, fmt.Errorf("stdin script is empty")
		}
	case filePath != "":
		data, err := os.ReadFile(filePath)
		if err != nil {
			return remoteRunSpec{}, fmt.Errorf("read script file: %w", err)
		}
		cmd = strings.TrimRight(string(data), "\r\n")
		if strings.TrimSpace(cmd) == "" {
			return remoteRunSpec{}, fmt.Errorf("script file is empty")
		}
	default:
		cmd = ssh.JoinRemoteCommand(parts, raw)
	}
	return remoteRunSpec{Command: cmd, Trace: trace}, nil
}
