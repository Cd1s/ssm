package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"ssm/internal/config"
	"ssm/internal/ssh"
)

type hostKeyCommandOptions struct {
	action      string
	alias       string
	fingerprint string
	confirm     bool
	asJSON      bool
}

func runHostKeyCommand(args []string) {
	opts, err := parseHostKeyCommand(args)
	if err != nil {
		writeCLIError("invalid_arguments", err.Error(), "use host-key inspect <alias> or host-key accept <alias> --fingerprint SHA256:... --yes", 2)
		os.Exit(2)
	}
	machineJSON = machineJSON || opts.asJSON
	pullIfChanged()
	v, err := config.Load(masterPass)
	if err != nil {
		writeCLIError("vault_error", err.Error(), "unlock the vault and retry", 1)
		os.Exit(1)
	}
	c, _, ok := resolveConnection(v, opts.alias)
	if !ok {
		connectionNotFound(opts.alias, v)
	}

	var report ssh.HostKeyInspection
	if opts.action == "inspect" {
		report, err = ssh.InspectHostKey(c)
	} else {
		report, err = ssh.AcceptHostKey(c, opts.fingerprint)
	}
	report.Alias = opts.alias
	if report.ResolvedAlias == opts.alias {
		report.ResolvedAlias = ""
	}
	if err != nil {
		code, hint := "host_key_operation_failed", "inspect the endpoint and retry"
		var operationErr *ssh.HostKeyOperationError
		if ok := errors.As(err, &operationErr); ok {
			code, hint = operationErr.Code, operationErr.Hint
		} else if classified, ok := err.(*ssh.ClassifiedError); ok {
			code, hint = classified.Code, classified.Hint
		}
		if machineJSON {
			writeMachineValue(struct {
				OK      bool                  `json:"ok"`
				Error   string                `json:"error"`
				Message string                `json:"message"`
				Hint    string                `json:"hint,omitempty"`
				Report  ssh.HostKeyInspection `json:"inspection"`
			}{OK: false, Error: code, Message: redactError(err), Hint: hint, Report: report})
		} else {
			writeCLIError(code, err.Error(), hint, 1)
		}
		os.Exit(1)
	}
	if machineJSON {
		writeMachineValue(report)
		return
	}
	fmt.Printf("alias=%s\naddress=%s\nstatus=%s\nalgorithm=%s\nfingerprint=%s\n", report.Alias, report.Address, report.Status, report.Algorithm, report.Fingerprint)
	if report.ResolvedAlias != "" {
		fmt.Printf("resolved_alias=%s\n", report.ResolvedAlias)
	}
	for _, fingerprint := range report.KnownFingerprints {
		fmt.Printf("known_fingerprint=%s\n", fingerprint)
	}
	if report.Accepted {
		fmt.Println("accepted=1")
	}
}

func parseHostKeyCommand(args []string) (hostKeyCommandOptions, error) {
	opts := hostKeyCommandOptions{asJSON: machineJSON}
	if len(args) < 2 {
		return opts, fmt.Errorf("host-key action and exact alias are required")
	}
	opts.action, opts.alias = args[0], args[1]
	if opts.action != "inspect" && opts.action != "accept" {
		return opts, fmt.Errorf("unknown host-key action %q", opts.action)
	}
	if strings.TrimSpace(opts.alias) == "" || strings.HasPrefix(opts.alias, "-") {
		return opts, fmt.Errorf("exact alias is required")
	}
	for i := 2; i < len(args); i++ {
		switch {
		case args[i] == "--json":
			opts.asJSON = true
		case args[i] == "--yes":
			opts.confirm = true
		case args[i] == "--fingerprint":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--fingerprint requires a SHA-256 fingerprint")
			}
			opts.fingerprint = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--fingerprint="):
			opts.fingerprint = strings.TrimPrefix(args[i], "--fingerprint=")
		default:
			return opts, fmt.Errorf("unknown host-key option %q", args[i])
		}
	}
	if opts.action == "inspect" && (opts.confirm || opts.fingerprint != "") {
		return opts, fmt.Errorf("host-key inspect accepts only alias and --json")
	}
	if opts.action == "accept" {
		if !opts.confirm {
			return opts, fmt.Errorf("host-key accept requires --yes")
		}
		if !strings.HasPrefix(opts.fingerprint, "SHA256:") {
			return opts, fmt.Errorf("host-key accept requires the full SHA256: fingerprint")
		}
	}
	return opts, nil
}
