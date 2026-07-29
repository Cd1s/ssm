package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"ssm/internal/machinecontract"
	"ssm/internal/ssh"
	"ssm/internal/synctransaction"
)

const (
	maxArgvStreamLineBytes = 1 << 20
	defaultStreamRefresh   = 30 * time.Second
)

type runStreamOptions struct {
	refresh time.Duration
}

// parseRunStreamArgs recognizes only the dedicated stream form. A remote
// command containing "--stream" after -- or --argv remains a normal command.
func parseRunStreamArgs(args []string) (runStreamOptions, bool, error) {
	opts := runStreamOptions{refresh: defaultStreamRefresh}
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "--json" {
			filtered = append(filtered, arg)
		}
	}
	if len(filtered) == 0 || filtered[0] != "--stream" {
		return opts, false, nil
	}
	for i := 1; i < len(filtered); i++ {
		switch {
		case filtered[i] == "--refresh":
			if i+1 >= len(filtered) {
				return opts, true, fmt.Errorf("--refresh requires a duration or 0")
			}
			i++
			refresh, err := parseStreamRefresh(filtered[i])
			if err != nil {
				return opts, true, err
			}
			opts.refresh = refresh
		case strings.HasPrefix(filtered[i], "--refresh="):
			refresh, err := parseStreamRefresh(strings.TrimPrefix(filtered[i], "--refresh="))
			if err != nil {
				return opts, true, err
			}
			opts.refresh = refresh
		default:
			return opts, true, fmt.Errorf("unknown stream option %q", filtered[i])
		}
	}
	return opts, true, nil
}

func parseStreamRefresh(value string) (time.Duration, error) {
	if value == "0" {
		return 0, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("--refresh requires a positive duration or 0")
	}
	return duration, nil
}

// runArgvStream reads one JSON argv array per line and writes one compact JSON
// result per line. Sync, vault decryption, and SSH setup are amortized across
// the stream; a bounded refresh keeps long sessions from silently going stale.
func runArgvStream(alias string, opts runStreamOptions, input io.Reader, output io.Writer) int {
	defer ssh.ClosePool()

	pullIfChanged()
	v, err := loadVault()
	if err != nil {
		failure := machinecontract.Classify(machinecontract.StreamVaultUnlockFailed, machinecontract.Details{Cause: err})
		_ = machinecontract.WriteFailureNDJSON(output, failure)
		return machinecontract.ProcessExit(failure)
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxArgvStreamLineBytes+1)
	lastRefresh := time.Now()
	exitCode := 0

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if opts.refresh > 0 && time.Since(lastRefresh) >= opts.refresh {
			changed, refreshErr := refreshVaultIfChangedResult()
			if refreshErr != nil {
				failure := machinecontract.Classify(machinecontract.StreamSyncPullFailed, machinecontract.Details{Cause: refreshErr})
				if errors.Is(refreshErr, synctransaction.ErrConfiguration) {
					failure = machinecontract.ClassifySyncFailure(refreshErr, machinecontract.StreamSyncPullFailed)
				}
				_ = machinecontract.WriteFailureNDJSON(output, failure)
				return machinecontract.ProcessExit(failure)
			}
			if changed {
				ssh.ClosePool()
				v, err = loadVault()
				if err != nil {
					failure := machinecontract.Classify(machinecontract.StreamVaultUnlockFailed, machinecontract.Details{Cause: err})
					_ = machinecontract.WriteFailureNDJSON(output, failure)
					return machinecontract.ProcessExit(failure)
				}
			}
			lastRefresh = time.Now()
		}

		argv, decodeErr := decodeArgvStreamLine(line)
		if decodeErr != nil {
			failure := machinecontract.Classify(machinecontract.StreamDecodeFailed, machinecontract.Details{Cause: decodeErr})
			if err := machinecontract.WriteFailureNDJSON(output, failure); err != nil {
				return machinecontract.ProcessExit(machinecontract.Classify(machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
			}
			exitCode = machinecontract.ProcessExit(failure)
			continue
		}
		spec := remoteRunSpec{
			Command:  ssh.JoinRemoteArgv(argv),
			JSON:     true,
			Secrets:  map[string]string{},
			FromArgs: true,
			Mode:     "argv",
		}
		result := executeRunSpec(v, alias, spec)
		if err := ssh.WriteRunResultNDJSON(output, result); err != nil {
			return machinecontract.ProcessExit(machinecontract.Classify(machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
		}
		if !result.OK {
			exitCode = machinecontract.ResultExit(machinecontract.ResultState{OK: result.OK, Exit: result.Exit})
			if result.Error == machinecontract.CodeAliasNotFound {
				return exitCode
			}
		}
	}
	if err := scanner.Err(); err != nil {
		failure := machinecontract.Classify(machinecontract.StreamReadFailed, machinecontract.Details{
			Message: "stream line exceeds 1 MiB or could not be read",
		})
		_ = machinecontract.WriteFailureNDJSON(output, failure)
		return machinecontract.ProcessExit(failure)
	}
	return exitCode
}

func decodeArgvStreamLine(line []byte) ([]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	var argv []string
	if err := decoder.Decode(&argv); err != nil {
		return nil, fmt.Errorf("decode argv JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("stream line must contain exactly one JSON array")
		}
		return nil, fmt.Errorf("trailing stream data: %w", err)
	}
	if len(argv) == 0 {
		return nil, fmt.Errorf("argv must contain at least one item")
	}
	for _, arg := range argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return nil, fmt.Errorf("argv contains a NUL byte")
		}
	}
	return argv, nil
}

func exitRunArgvStream(alias string, opts runStreamOptions) {
	machineJSON = true
	os.Exit(runArgvStream(alias, opts, os.Stdin, os.Stdout))
}
