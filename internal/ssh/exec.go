package ssh

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"ssm/internal/config"
)

func Exec(c config.Connection, v *config.Vault, cmd string) int {
	if traceEnabled() {
		fmt.Fprintf(os.Stderr, "ssm: remote command: %s\n", cmd)
	}

	client, err := dialSSH(c, v)
	if err != nil {
		PrintAgentError(err, c)
		return ExitCodeFor(err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		PrintAgentError(err, c)
		return ExitConnectionFailed
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	stdinIsTTY := term.IsTerminal(int(os.Stdin.Fd()))
	if os.Getenv("SSM_FORWARD_STDIN") == "1" || (!stdinIsTTY && stdinHasReadableData()) {
		stdin, err := session.StdinPipe()
		if err != nil {
			PrintAgentError(err, c)
			return 1
		}
		go func() {
			_, _ = io.Copy(stdin, os.Stdin)
			_ = stdin.Close()
		}()
	} else if stdinIsTTY {
		session.Stdin = os.Stdin
	}

	if err := session.Run(cmd); err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			return exitErr.ExitStatus()
		}
		PrintAgentError(err, c)
		return ExitCodeFor(err)
	}
	return 0
}
