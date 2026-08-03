package main

import (
	"fmt"
	"os"
	"strings"

	"ssm/internal/machinecontract"
	"ssm/internal/ssh"
)

type hostKeyCommandOptions struct {
	action      string
	alias       string
	fingerprint string
	confirm     bool
	asJSON      bool
}

type hostKeyFailure struct {
	OK bool `json:"ok"`
	machinecontract.Metadata
	Report ssh.HostKeyInspection `json:"inspection"`
}

func runHostKeyCommand(args []string) {
	opts, err := parseHostKeyCommand(args)
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.HostKeyArgumentsInvalid, machinecontract.Details{Cause: err}))
	}
	machineJSON = machineJSON || opts.asJSON
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.HostKeyVaultFailed, machinecontract.Details{Cause: err}))
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
		failure := machinecontract.ClassifyHostKeyOperation(err)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, hostKeyFailure{
			OK: false, Metadata: failure.Metadata(), Report: report,
		}))
	}
	if machineJSON {
		writeMachineValue(report)
		return
	}
	fmt.Printf("alias=%s\naddress=%s\nstatus=%s\nclassification=%s\nalgorithm=%s\nobserved_fingerprint=%s\n", report.Alias, report.Address, report.Status, report.Classification, report.Algorithm, report.ObservedFingerprint)
	if report.ResolvedAlias != "" {
		fmt.Printf("resolved_alias=%s\n", report.ResolvedAlias)
	}
	for _, fingerprint := range report.KnownFingerprints {
		fmt.Printf("known_fingerprint=%s\n", fingerprint)
	}
	if report.Accepted {
		fmt.Println("accepted=1")
	}
	if report.Message != "" {
		fmt.Printf("message=%s\n", report.Message)
	}
	if report.Hint != "" {
		fmt.Printf("hint=%s\n", report.Hint)
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
