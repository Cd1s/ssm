package ssh

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"ssm/internal/config"
)

func Exec(c config.Connection, v *config.Vault, cmd string) int {
	auth, err := buildAuth(c, v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	port := c.Port
	if port == 0 {
		port = 22
	}

	hostKeyCallback := buildHostKeyCallback()

	client, err := ssh.Dial("tcp", net.JoinHostPort(c.Host, strconv.Itoa(port)), &ssh.ClientConfig{
		User:            c.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         dialTimeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	stdinIsTTY := term.IsTerminal(int(os.Stdin.Fd()))
	if os.Getenv("SSM_FORWARD_STDIN") == "1" || (!stdinIsTTY && stdinHasReadableData()) {
		stdin, err := session.StdinPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}
