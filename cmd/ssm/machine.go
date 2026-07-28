package main

import (
	"io"
	"os"

	"ssm/internal/machinecontract"
)

// machineJSON is enabled by a global --json or by a command-specific JSON
// option before any operation that can fail. It guarantees one JSON value on
// stdout and keeps diagnostics off stderr for agent callers.
var machineJSON bool

// writeMachineValue serializes typed success payloads without rewriting their
// fields. Failures must use machinecontract.WriteFailure or WriteClassified.
func writeMachineValue(value any) {
	if err := renderMachineValue(os.Stdout, value); err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
}

func renderMachineValue(output io.Writer, value any) error {
	return machinecontract.Render(
		machinecontract.JSONDocument,
		machinecontract.Streams{Stdout: output, Stderr: os.Stderr},
		value,
	)
}

func hasJSONFlagBeforeDash(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--json" {
			return true
		}
	}
	return false
}
