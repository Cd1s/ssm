package ssh

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

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

	client, err := dialSSH(c, v)
	if err != nil {
		return err
	}
	defer releaseClient(client, false)

	session, err := client.NewSession()
	if err != nil {
		return ClassifyError(err, c)
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
	if err := session.Wait(); err != nil {
		return err
	}
	return nil
}

// DownloadFile copies remotePath from the server to localPath.
// Parent directories of localPath are created as needed.
func DownloadFile(c config.Connection, v *config.Vault, remotePath, localPath string) error {
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return fmt.Errorf("create local parent dir: %w", err)
	}

	// Write via temp then rename so a failed download never leaves a partial file
	// at the final path.
	dir := filepath.Dir(localPath)
	tmp, err := os.CreateTemp(dir, ".ssm-get-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	keepTemp := false
	defer func() {
		_ = tmp.Close()
		if !keepTemp {
			_ = os.Remove(tmpName)
		}
	}()

	client, err := dialSSH(c, v)
	if err != nil {
		return err
	}
	defer releaseClient(client, false)

	session, err := client.NewSession()
	if err != nil {
		return ClassifyError(err, c)
	}
	defer session.Close()

	session.Stdout = tmp
	session.Stderr = os.Stderr

	cmd := downloadCommand(remotePath)
	if err := session.Run(cmd); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, localPath); err != nil {
		return err
	}
	keepTemp = true // renamed into place; do not remove
	return nil
}

func uploadCommand(remotePath string, mode os.FileMode) string {
	quotedPath := ShellQuote(remotePath)
	parent := RemoteParentDir(remotePath)
	prefix := "umask 077; "
	if parent != "" {
		prefix += "mkdir -p " + ShellQuote(parent) + " && "
	}
	return fmt.Sprintf("%scat > %s && chmod %04o %s", prefix, quotedPath, uint32(mode.Perm()), quotedPath)
}

func downloadCommand(remotePath string) string {
	// cat is enough for regular files; fail clearly on missing paths.
	return "cat -- " + ShellQuote(remotePath)
}
