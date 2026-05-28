package ssh

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"

	"ssm/internal/config"
)

const dialTimeout = 15 * time.Second

func ConnectWithManager(c config.Connection, v *config.Vault, picker PickerFunc) {
	fmt.Printf("Connecting to %s...\n", c.Display())

	mgr := NewSessionManager(v, picker)
	fmt.Print("\033[?1049h")
	if err := mgr.Start(); err != nil {
		fmt.Print("\033[?1049l")
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	if err := mgr.AddSession(c, v); err != nil {
		mgr.Stop()
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	mgr.Run()
}

func Connect(c config.Connection, v *config.Vault) {
	fmt.Printf("Connecting to %s...\n", c.Display())

	if c.Password != "" || c.KeyName != "" {
		if err := nativeConnect(c, v); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		return
	}

	shellConnect(c)
}

func ConnectInteractive(c config.Connection, v *config.Vault) error {
	return nativeConnect(c, v)
}

func nativeConnect(c config.Connection, v *config.Vault) error {
	auth, err := buildAuth(c, v)
	if err != nil {
		return err
	}

	port := c.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(port))

	hostKeyCallback := buildHostKeyCallback()

	cfg := &ssh.ClientConfig{
		User:            c.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         dialTimeout,
	}

	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		if isHostKeyError(err) {
			handleHostKeyFailure(c, v)
			return nil
		}
		return fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("session failed: %w", err)
	}
	defer session.Close()

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("terminal raw mode: %w", err)
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	width, height, _ := term.GetSize(int(os.Stdout.Fd()))

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
		return fmt.Errorf("PTY: %w", err)
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	sigChan := make(chan os.Signal, 1)
	notifyResize(sigChan)
	go func() {
		for range sigChan {
			w, h, _ := term.GetSize(int(os.Stdout.Fd()))
			_ = session.WindowChange(h, w)
		}
	}()
	defer signal.Stop(sigChan)

	if err := session.Shell(); err != nil {
		return fmt.Errorf("shell: %w", err)
	}

	_ = session.Wait()
	return nil
}

func buildAuth(c config.Connection, v *config.Vault) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if c.KeyName != "" {
		key := v.GetKey(c.KeyName)
		if key == nil {
			return nil, fmt.Errorf("key \"%s\" not found", c.KeyName)
		}
		signer, err := ssh.ParsePrivateKey([]byte(key.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("invalid SSH key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if c.Password != "" {
		methods = append(methods, ssh.Password(c.Password))
	}

	return methods, nil
}

func buildHostKeyCallback() ssh.HostKeyCallback {
	home, _ := os.UserHomeDir()
	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")

	if _, err := os.Stat(knownHostsPath); err != nil {
		return acceptAndSaveHostKey(knownHostsPath)
	}

	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return acceptAndSaveHostKey(knownHostsPath)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
			return err
		}
		return saveHostKey(knownHostsPath, hostname, key)
	}
}

func acceptAndSaveHostKey(path string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return saveHostKey(path, hostname, key)
	}
}

func saveHostKey(path, hostname string, key ssh.PublicKey) error {
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	line := knownhosts.Line([]string{hostname}, key)
	_, err = fmt.Fprintln(f, line)
	return err
}

func isHostKeyError(err error) bool {
	return strings.Contains(err.Error(), "host key") ||
		strings.Contains(err.Error(), "knownhosts")
}

func shellConnect(c config.Connection) {
	cmd := exec.Command("ssh", c.SSHArgs()...) //nolint:gosec
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout

	stderrBuf := &bytes.Buffer{}
	cmd.Stderr = io.MultiWriter(os.Stderr, stderrBuf)

	err := cmd.Run()

	if err != nil && strings.Contains(stderrBuf.String(), "Host key verification failed") {
		handleHostKeyFailure(c, nil)
	}
}

func handleHostKeyFailure(c config.Connection, v *config.Vault) {
	host := c.Host
	if c.Port != 0 && c.Port != 22 {
		host = fmt.Sprintf("[%s]:%d", c.Host, c.Port)
	}

	fmt.Println()
	fmt.Printf("  Host key for \"%s\" (%s) has changed.\n", c.Name, c.Host)
	fmt.Printf("  Update known_hosts? [y/n]: ")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))

	if answer == "y" || answer == "yes" {
		rm := exec.Command("ssh-keygen", "-R", host)
		rm.Stdout = os.Stdout
		rm.Stderr = os.Stderr
		_ = rm.Run()
		fmt.Println("  Reconnecting...")
		Connect(c, v)
	}
}
