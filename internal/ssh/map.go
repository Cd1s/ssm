package ssh

import (
	"fmt"
	"os"
	"sync"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
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
	Mode           string
	Preflight      bool
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
		result := RunResult{
			Alias:         job.RequestedAlias,
			ResolvedAlias: resolved,
			RemoteCommand: RedactSecrets(remoteCommand, job.Secrets),
			ScriptLabel:   job.ScriptLabel,
			Risk:          AssessRisk(firstNonEmptyString(job.RiskCommand, job.Command)),
			Interpreter:   job.Interpreter,
			InputBytes:    len(job.Input),
			ScriptSHA256:  digestIfNotEmpty(job.Input),
		}
		applyRunFailure(&result, machinecontract.Classify(machinecontract.MapAliasNotFound, machinecontract.Details{
			Message: "requested alias was not found",
			Alias:   job.RequestedAlias,
		}))
		return result
	}
	if job.Input != "" && job.Preflight {
		script := ScriptSpec{Label: job.ScriptLabel, Body: job.Input, Interpreter: job.Interpreter}
		preflight := RunScriptPreflight(c, v, script, noReuse, job.RequestedAlias, resolved)
		if !preflight.OK {
			return preflight
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
		Mode:           job.Mode,
	})
	if job.Input != "" && job.Preflight {
		res.Preflight = "passed"
	}
	res.ScriptLabel = job.ScriptLabel
	return res
}

// ExpandMapJobs builds host×script jobs. If scripts is empty, one job per alias
// with command. If scripts is non-empty, each script body is a job (label=path).
func ExpandMapJobs(aliases []string, command string, scripts []ScriptSpec, secrets map[string]string, mode string, preflight bool) []MapJob {
	var jobs []MapJob
	if len(scripts) == 0 {
		for _, a := range aliases {
			jobs = append(jobs, MapJob{
				RequestedAlias: a,
				Command:        command,
				Secrets:        secrets,
				Mode:           mode,
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
				Mode:           "script",
				Preflight:      preflight,
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
		results = redactFailedMapResults(results)
		_ = machinecontract.WriteJSON(results)
		return
	}
	for _, result := range results {
		if !result.OK {
			views := make([]machinecontract.MapResultView, len(results))
			for i, item := range results {
				views[i] = machinecontract.MapResultView{
					OK: item.OK, Alias: item.Alias, Script: item.ScriptLabel,
					Exit: item.Exit, LatencyMS: item.LatencyMS, Error: item.Error,
					Stdout: item.Stdout, Stderr: item.Stderr, SensitiveValues: item.sensitiveValues,
				}
			}
			_ = machinecontract.RenderMapFailure(
				machinecontract.Streams{Stdout: os.Stdout, Stderr: os.Stderr},
				views,
			)
			return
		}
	}
	// Stable display order already matches job order.
	for _, r := range results {
		label := r.Alias
		if r.ScriptLabel != "" {
			label = r.Alias + "/" + r.ScriptLabel
		}
		fmt.Printf("%s\tok\texit=%d\tlatency_ms=%d", label, r.Exit, r.LatencyMS)
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

func redactFailedMapResults(results []RunResult) []RunResult {
	var safe []RunResult
	for i, result := range results {
		if result.OK {
			continue
		}
		if safe == nil {
			safe = append([]RunResult(nil), results...)
		}
		safe[i] = redactRunFailure(result)
	}
	if safe != nil {
		return safe
	}
	return results
}

func endsWithNL(s string) bool {
	return len(s) > 0 && s[len(s)-1] == '\n'
}

// MapExitCode returns 0 only if every job succeeded.
func MapExitCode(results []RunResult) int {
	states := make([]machinecontract.ResultState, len(results))
	for i, result := range results {
		states[i] = machinecontract.ResultState{OK: result.OK, Exit: result.Exit}
	}
	return machinecontract.AggregateResultExit(states)
}

// DefaultMapWorkers returns concurrency from env or default 8.
func DefaultMapWorkers() int {
	return 8
}
