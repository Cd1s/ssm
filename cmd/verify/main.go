package main

import (
	"context"
	"fmt"
	"io"
	"os"
)

func main() {
	repoRoot, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: determine repository root: %v\n", err)
		os.Exit(1)
	}
	deps := runtimeDependencies{
		repoRoot: repoRoot,
		stdout:   os.Stdout,
		stderr:   os.Stderr,
		prerequisites: func(prerequisite Prerequisite) prerequisiteState {
			return checkPrerequisite(repoRoot, prerequisite)
		},
		actions: systemActionExecutor{},
	}
	if err := runCLI(context.Background(), os.Args[1:], os.Stdout, os.Stderr, deps); err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(ctx context.Context, args []string, stdout, stderr io.Writer, deps runtimeDependencies) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: go run ./cmd/verify <list|fast|ci|release>")
	}

	manifest := verificationManifest()
	if args[0] == "list" {
		data, err := renderManifest(manifest)
		if err != nil {
			return err
		}
		_, err = stdout.Write(data)
		return err
	}

	deps.stdout = stdout
	deps.stderr = stderr
	result, err := executeProfile(ctx, manifest, args[0], deps)
	reportErr := writeProfileResult(stderr, result)
	if err == nil {
		err = reportErr
	}
	return err
}

func writeProfileResult(writer io.Writer, result profileResult) error {
	for _, check := range result.Checks {
		if check.Detail == "" {
			if _, err := fmt.Fprintf(writer, "verify %s: %s %s\n", result.Profile, check.Status, check.ID); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(writer, "verify %s: %s %s: %s\n", result.Profile, check.Status, check.ID, check.Detail); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(writer, "verify %s: %s\n", result.Profile, result.Status)
	return err
}
