package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"ssm/internal/ssh"
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
		_ = writeStreamError(output, "vault_unlock_failed", err.Error(), "verify the master pass file belongs to this encrypted vault", "vault", 1)
		return 1
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxArgvStreamLineBytes+1)
	encoder := json.NewEncoder(output)
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
				_ = writeStreamError(output, "sync_pull_failed", refreshErr.Error(), "fix sync connectivity or restart explicitly with --offline", "sync_pull", 1)
				return 1
			}
			if changed {
				ssh.ClosePool()
				v, err = loadVault()
				if err != nil {
					_ = writeStreamError(output, "vault_unlock_failed", err.Error(), "verify the master pass file belongs to this encrypted vault", "vault", 1)
					return 1
				}
			}
			lastRefresh = time.Now()
		}

		argv, decodeErr := decodeArgvStreamLine(line)
		if decodeErr != nil {
			if err := writeStreamError(output, "invalid_request", decodeErr.Error(), "send one non-empty JSON string array per line", "decode", 2); err != nil {
				return 1
			}
			exitCode = 2
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
		if err := encoder.Encode(result); err != nil {
			return 1
		}
		if !result.OK {
			if result.Exit != 0 {
				exitCode = result.Exit
			} else {
				exitCode = 1
			}
			if result.Error == ssh.ErrCodeAliasNotFound {
				return exitCode
			}
		}
	}
	if err := scanner.Err(); err != nil {
		_ = writeStreamError(output, "invalid_request", "stream line exceeds 1 MiB or could not be read", "send smaller argv arrays", "read", 2)
		return 2
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

func writeStreamError(output io.Writer, code, message, hint, stage string, exit int) error {
	return json.NewEncoder(output).Encode(machineErrorOutput{
		OK:      false,
		Error:   code,
		Message: redactString(message),
		Hint:    redactString(hint),
		Stage:   stage,
		Exit:    exit,
	})
}

func exitRunArgvStream(alias string, opts runStreamOptions) {
	machineJSON = true
	os.Exit(runArgvStream(alias, opts, os.Stdin, os.Stdout))
}
