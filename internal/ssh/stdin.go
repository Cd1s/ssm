package ssh

import (
	"io"
	"os"

	"golang.org/x/term"
)

// StdinMode selects how Run treats local stdin. The zero value never forwards
// and never reports, which is what internal callers (check, doctor, map jobs,
// argv streams) need.
type StdinMode int

const (
	// StdinInternal never forwards stdin and adds no stdin fields to results.
	StdinInternal StdinMode = iota
	// StdinDefault applies the CLI rules: SSM_FORWARD_STDIN, then the mode
	// default (human forwards a non-TTY stdin, capture does not).
	StdinDefault
	// StdinForward forwards local stdin in every mode (--stdin).
	StdinForward
	// StdinDisable never forwards local stdin (--no-stdin, like ssh -n).
	StdinDisable
)

// StdinWarning explains a non-forwarded piped stdin in capture (--json) mode.
const StdinWarning = "local stdin was not forwarded because --json does not forward stdin by default; " +
	"add --stdin (or set SSM_FORWARD_STDIN=1) to forward it, or --no-stdin to silence this warning"

type stdinSource int

const (
	stdinNone stdinSource = iota
	// stdinTTY hands an interactive terminal straight to the session.
	stdinTTY
	// stdinPipe copies local stdin to the remote command until EOF.
	stdinPipe
	// stdinFromFile copies a file to the remote command until EOF.
	stdinFromFile
)

type stdinDecision struct {
	Source stdinSource
	// Forwarded is the value reported as stdin_forwarded; nil omits it.
	Forwarded *bool
	Warning   string
}

func boolPtr(value bool) *bool { return &value }

// decideStdin applies the stdin forwarding rules. env is SSM_FORWARD_STDIN.
func decideStdin(mode StdinMode, file, env string, capture, isTTY, isNull bool) stdinDecision {
	if file != "" {
		return stdinDecision{Source: stdinFromFile, Forwarded: boolPtr(true)}
	}
	if mode == StdinInternal {
		return stdinDecision{}
	}
	if mode == StdinDefault {
		switch env {
		case "1":
			mode = StdinForward
		case "0":
			mode = StdinDisable
		}
	}
	switch mode {
	case StdinForward:
		return stdinDecision{Source: stdinPipe, Forwarded: boolPtr(true)}
	case StdinDisable:
		return stdinDecision{}
	}
	if !capture {
		if isTTY {
			return stdinDecision{Source: stdinTTY}
		}
		return stdinDecision{Source: stdinPipe, Forwarded: boolPtr(true)}
	}
	if isTTY || isNull {
		return stdinDecision{}
	}
	return stdinDecision{Forwarded: boolPtr(false), Warning: StdinWarning}
}

// decideRunStdin resolves the stdin rule for one run. A script body owns the
// remote stdin, so scripts never forward or report local stdin.
func decideRunStdin(opts RunOptions) stdinDecision {
	if opts.Input != "" {
		return stdinDecision{}
	}
	isTTY := term.IsTerminal(int(os.Stdin.Fd())) //nolint:gosec // file descriptors always fit in int
	isNull := !isTTY && stdinIsNullDevice()
	return decideStdin(opts.Stdin, opts.StdinFile, os.Getenv("SSM_FORWARD_STDIN"), opts.Capture, isTTY, isNull)
}

// forwardStdin copies src to the remote command and closes the remote stdin on
// EOF. It runs in its own goroutine so a blocked local read never delays the
// end of the run once the remote command has exited.
func forwardStdin(dst io.WriteCloser, src io.Reader) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
}
