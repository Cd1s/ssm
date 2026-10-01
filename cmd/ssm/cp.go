package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"ssm/internal/machinecontract"
	"ssm/internal/ssh"
)

// cpOptions are the parsed arguments of sshctl cp.
type cpOptions struct {
	srcAlias, srcPath string
	dstAlias, dstPath string
	timeout           time.Duration
	direct, yes       bool
}

// splitCopyEndpoint parses <alias>:<path>. The alias ends at the first colon,
// so paths may contain colons; an alias is never a path, so a slash before the
// first colon means the operand is not an endpoint.
func splitCopyEndpoint(operand string) (alias, path string, err error) {
	index := strings.Index(operand, ":")
	if index <= 0 || index == len(operand)-1 || strings.ContainsAny(operand[:index], "/\\") {
		return "", "", fmt.Errorf("%q is not <alias>:<path>", operand)
	}
	return operand[:index], operand[index+1:], nil
}

func parseCpArgs(args []string) (cpOptions, error) {
	var opts cpOptions
	positionals := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--json":
			machineJSON = true
		case args[i] == "--direct":
			opts.direct = true
		case args[i] == "--yes":
			opts.yes = true
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
			return opts, fmt.Errorf("unknown cp option %q", args[i])
		default:
			positionals = append(positionals, args[i])
		}
	}
	if len(positionals) != 2 {
		return opts, fmt.Errorf("cp requires <alias>:<path> for the source and the destination")
	}
	if opts.yes && !opts.direct {
		return opts, fmt.Errorf("--yes only confirms --direct; plain cp needs no confirmation")
	}
	var err error
	if opts.srcAlias, opts.srcPath, err = splitCopyEndpoint(positionals[0]); err != nil {
		return opts, err
	}
	if opts.dstAlias, opts.dstPath, err = splitCopyEndpoint(positionals[1]); err != nil {
		return opts, err
	}
	return opts, nil
}

func runCpArgs(args []string) {
	opts, err := parseCpArgs(args)
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.CopyArgumentsInvalid, machinecontract.Details{Cause: err}))
	}
	if opts.direct && !opts.yes {
		// Refused before any sync, vault read or connection: --direct lets
		// the source host use the destination's key while the copy runs.
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.CopyDirectConfirmationRequired, machinecontract.Details{
			Message: "cp --direct needs explicit confirmation: host A can use B's key through a forwarded agent while the copy runs, and anyone who controls A can use it too",
		}))
	}
	runCp(opts)
}

func runCp(opts cpOptions) {
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	src, _, ok := resolveConnection(v, opts.srcAlias)
	if !ok {
		connectionNotFound(opts.srcAlias, v)
	}
	dst, _, ok := resolveConnection(v, opts.dstAlias)
	if !ok {
		connectionNotFound(opts.dstAlias, v)
	}

	if src.Name == dst.Name && path.Clean(opts.srcPath) == path.Clean(opts.dstPath) {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.CopyArgumentsInvalid, machinecontract.Details{
			Message: fmt.Sprintf("source and destination are the same file (%s:%s)", src.Name, opts.srcPath),
		}))
	}

	route := "local_relay"
	if opts.direct {
		route = "direct"
	}
	base := machinecontract.CopyOutcome{
		Direction: "cp", Kind: "file", Route: route,
		Source:      machinecontract.CopyEndpoint{Alias: opts.srcAlias, Path: opts.srcPath},
		Destination: machinecontract.CopyEndpoint{Alias: opts.dstAlias, Path: opts.dstPath},
	}
	result, err := ssh.CopyFile(src, opts.srcPath, dst, opts.dstPath, v, ssh.CopyOptions{Timeout: opts.timeout, Direct: opts.direct})
	if err != nil {
		carried := machinecontract.Failure{}
		var transferErr *ssh.TransferError
		if errors.As(err, &transferErr) {
			carried = transferErr.ContractFailure()
		}
		failure := machinecontract.ClassifyTransferOperation(err, machinecontract.SSHContext{}, carried)
		if machineJSON {
			bytes := result.Bytes
			atomic := result.Atomic
			document := base
			document.Bytes, document.Atomic = &bytes, &atomic
			document.Integrity = result.Integrity
			document.SourceSHA256, document.LocalSHA256, document.DestinationSHA256 = result.SourceSHA256, result.LocalSHA256, result.DestinationSHA256
			os.Exit(machinecontract.WriteFailure(true, failure, machinecontract.CopyFailureOutcome(failure, document)))
		}
		_ = machinecontract.WriteHuman(failure)
		os.Exit(machinecontract.ProcessExit(failure))
	}
	if machineJSON {
		bytes := result.Bytes
		atomic := result.Atomic
		document := base
		document.OK, document.Action, document.Stage = true, "cp", result.Stage
		document.Bytes, document.Atomic, document.Integrity = &bytes, &atomic, result.Integrity
		document.SourceSHA256, document.LocalSHA256, document.DestinationSHA256 = result.SourceSHA256, result.LocalSHA256, result.DestinationSHA256
		writeMachineValue(document)
		return
	}
	fmt.Printf("ok=1\nsource=%s:%s\ndestination=%s:%s\nbytes=%d\nsha256=%s\n", opts.srcAlias, opts.srcPath, opts.dstAlias, opts.dstPath, result.Bytes, result.SourceSHA256)
	if opts.direct {
		fmt.Print("route=direct\n")
	}
}
