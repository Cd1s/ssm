package ssh

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"

	"ssm/internal/config"
)

// MapJob is one unit of parallel work: one host (+ optional script label).
type MapJob struct {
	RequestedAlias string
	ScriptLabel    string
	Command        string
	Input          string
	RiskCommand    string
	Interpreter    string
	Secrets        map[string]string
}

// Map runs jobs with bounded parallelism. Each job resolves alias redirects
// independently. Failures on one job do not cancel others.
func Map(v *config.Vault, jobs []MapJob, workers int, noReuse bool) []RunResult {
	if workers < 1 {
		workers = 8
	}
	if workers > 64 {
		workers = 64
	}
	if len(jobs) == 0 {
		return nil
	}

	results := make([]RunResult, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	for i, job := range jobs {
		wg.Add(1)
		go func(i int, job MapJob) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[i] = runMapJob(v, job, noReuse)
		}(i, job)
	}
	wg.Wait()
	return results
}

func runMapJob(v *config.Vault, job MapJob, noReuse bool) RunResult {
	c, resolved, ok := config.ResolveAlias(v, job.RequestedAlias)
	if !ok {
		remoteCommand := BuildRemoteCommand(job.Command, job.Secrets)
		if job.Input != "" {
			remoteCommand = BuildScriptRemoteCommand(job.Command, job.Secrets)
		}
		return RunResult{
			OK:            false,
			Alias:         job.RequestedAlias,
			ResolvedAlias: resolved,
			Exit:          ExitConnectionFailed,
			Error:         ErrCodeAliasNotFound,
			Hint:          "use sshctl list --json; alias may have been renamed after migration",
			RemoteCommand: RedactSecrets(remoteCommand, job.Secrets),
			ScriptLabel:   job.ScriptLabel,
			Risk:          AssessRisk(firstNonEmptyString(job.RiskCommand, job.Command)),
			Interpreter:   job.Interpreter,
			InputBytes:    len(job.Input),
			ScriptSHA256:  digestIfNotEmpty(job.Input),
		}
	}
	res := Run(c, v, RunOptions{
		Command:        job.Command,
		Input:          job.Input,
		RiskCommand:    job.RiskCommand,
		Secrets:        job.Secrets,
		Capture:        true,
		NoReuse:        noReuse,
		RequestedAlias: job.RequestedAlias,
		ResolvedAlias:  resolved,
		Interpreter:    job.Interpreter,
		ScriptLabel:    job.ScriptLabel,
	})
	res.ScriptLabel = job.ScriptLabel
	return res
}

// ExpandMapJobs builds host×script jobs. If scripts is empty, one job per alias
// with command. If scripts is non-empty, each script body is a job (label=path).
func ExpandMapJobs(aliases []string, command string, scripts []ScriptSpec, secrets map[string]string) []MapJob {
	var jobs []MapJob
	if len(scripts) == 0 {
		for _, a := range aliases {
			jobs = append(jobs, MapJob{
				RequestedAlias: a,
				Command:        command,
				Secrets:        secrets,
			})
		}
		return jobs
	}
	for _, a := range aliases {
		for _, s := range scripts {
			jobs = append(jobs, MapJob{
				RequestedAlias: a,
				ScriptLabel:    s.Label,
				Command:        BuildScriptRunner(s),
				Input:          s.Body,
				RiskCommand:    s.Body,
				Interpreter:    s.Interpreter,
				Secrets:        secrets,
			})
		}
	}
	return jobs
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func digestIfNotEmpty(value string) string {
	if value == "" {
		return ""
	}
	return ScriptDigest(value)
}

// WriteMapResults prints map results as text table or JSON array.
func WriteMapResults(results []RunResult, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}
	// Stable display order already matches job order.
	for _, r := range results {
		label := r.Alias
		if r.ScriptLabel != "" {
			label = r.Alias + "/" + r.ScriptLabel
		}
		status := "ok"
		if !r.OK {
			status = "fail"
		}
		err := r.Error
		if err == "" && !r.OK {
			err = fmt.Sprintf("exit_%d", r.Exit)
		}
		fmt.Printf("%s\t%s\texit=%d\tlatency_ms=%d", label, status, r.Exit, r.LatencyMS)
		if err != "" {
			fmt.Printf("\terror=%s", err)
		}
		fmt.Println()
		if r.Stdout != "" {
			// Indent stdout blocks for readability
			fmt.Print(r.Stdout)
			if !endsWithNL(r.Stdout) {
				fmt.Println()
			}
		}
		if r.Stderr != "" {
			fmt.Fprint(os.Stderr, r.Stderr)
			if !endsWithNL(r.Stderr) {
				fmt.Fprintln(os.Stderr)
			}
		}
	}
	// Summary line
	okN, failN := 0, 0
	for _, r := range results {
		if r.OK {
			okN++
		} else {
			failN++
		}
	}
	fmt.Printf("summary\tok=%d\tfail=%d\ttotal=%d\n", okN, failN, len(results))
}

func endsWithNL(s string) bool {
	return len(s) > 0 && s[len(s)-1] == '\n'
}

// MapExitCode returns 0 only if every job succeeded.
func MapExitCode(results []RunResult) int {
	for _, r := range results {
		if !r.OK {
			if r.Exit != 0 {
				return r.Exit
			}
			return 1
		}
	}
	return 0
}

// DefaultMapWorkers returns concurrency from env or default 8.
func DefaultMapWorkers() int {
	return 8
}

// SortedAliasList helper for tests.
func SortedAliasList(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}
