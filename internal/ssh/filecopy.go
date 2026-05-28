package ssh

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"ssm/internal/config"
)

func UploadFile(c config.Connection, v *config.Vault, localPath, remotePath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", localPath)
	}

	auth, err := buildAuth(c, v)
	if err != nil {
		return err
	}

	port := c.Port
	if port == 0 {
		port = 22
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(c.Host, strconv.Itoa(port)), &ssh.ClientConfig{
		User:            c.User,
		Auth:            auth,
		HostKeyCallback: buildHostKeyCallback(),
		Timeout:         dialTimeout,
	})
	if err != nil {
		return err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	cmd := uploadCommand(remotePath, info.Mode())
	if err := session.Start(cmd); err != nil {
		return err
	}
	if _, err := io.Copy(stdin, f); err != nil {
		_ = stdin.Close()
		_ = session.Close()
		return err
	}
	if err := stdin.Close(); err != nil {
		_ = session.Close()
		return err
	}
	return session.Wait()
}

func uploadCommand(remotePath string, mode os.FileMode) string {
	quotedPath := shellQuote(remotePath)
	return fmt.Sprintf("umask 077; cat > %s && chmod %04o %s", quotedPath, uint32(mode.Perm()), quotedPath)
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
