package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// machineJSON is enabled by a global --json or by a command-specific JSON
// option before any operation that can fail. It guarantees one JSON value on
// stdout and keeps diagnostics off stderr for agent callers.
var machineJSON bool

type machineErrorOutput struct {
	OK         bool     `json:"ok"`
	Error      string   `json:"error"`
	Message    string   `json:"message"`
	Hint       string   `json:"hint,omitempty"`
	Stage      string   `json:"stage,omitempty"`
	Alias      string   `json:"alias,omitempty"`
	Exit       int      `json:"exit"`
	Candidates []string `json:"candidates,omitempty"`
}

func writeMachineValue(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}

func writeMachineError(code, message, hint, alias string, exit int, candidates []string) {
	writeMachineErrorStage(code, message, hint, "", alias, exit, candidates)
}

func writeMachineErrorStage(code, message, hint, stage, alias string, exit int, candidates []string) {
	writeMachineValue(machineErrorOutput{
		OK:         false,
		Error:      code,
		Message:    redactString(message),
		Hint:       redactString(hint),
		Stage:      stage,
		Alias:      alias,
		Exit:       exit,
		Candidates: candidates,
	})
}

func writeCLIError(code, message, hint string, exit int) {
	writeCLIErrorStage(code, message, hint, "", exit)
}

func writeCLIErrorStage(code, message, hint, stage string, exit int) {
	if machineJSON {
		writeMachineErrorStage(code, message, hint, stage, "", exit, nil)
		return
	}
	fmt.Fprintf(os.Stderr, "ssm: error=%s", code)
	if stage != "" {
		fmt.Fprintf(os.Stderr, " stage=%s", stage)
	}
	fmt.Fprintf(os.Stderr, "\nError: %s\n", redactString(message))
	if hint != "" {
		fmt.Fprintf(os.Stderr, "ssm: hint=%s\n", redactString(hint))
	}
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
