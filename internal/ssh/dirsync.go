package ssh

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"ssm/internal/config"
)

// UploadPath uploads a file or directory tree to the remote host.
// Directories use tar-over-ssh in one session (creates remote parent).
func UploadPath(c config.Connection, v *config.Vault, localPath, remotePath string) error {
	_, err := UploadPathWithOptions(c, v, localPath, remotePath, UploadOptions{})
	return err
}

func UploadPathWithOptions(c config.Connection, v *config.Vault, localPath, remotePath string, opts UploadOptions) (TransferResult, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return TransferResult{Stage: "local_read", Integrity: "not_checked", Resume: "unsupported"}, transferError("local_read_failed", "local_read", "verify the local path and read permissions", 0, err)
	}
	if info.Mode().IsRegular() {
		return UploadFileWithOptions(c, v, localPath, remotePath, opts)
	}
	if !info.IsDir() {
		return TransferResult{Stage: "local_read", Integrity: "not_checked", Resume: "unsupported"}, transferError("local_read_failed", "local_read", "use a regular file or directory", 0, fmt.Errorf("%s is not a regular file or directory", localPath))
	}
	if opts.VerifySHA256 || opts.Timeout > 0 || opts.ResumeVersion != "" {
		return TransferResult{Stage: "validate", Integrity: "not_available", Resume: "unsupported"}, transferError("unsupported_transfer_option", "validate", "SHA-256, timeout, and resume v1 options support regular-file put only", 0, errors.New("directory transfer does not support requested reliability options"))
	}
	err = uploadDirTar(c, v, localPath, remotePath)
	if err != nil {
		return TransferResult{Stage: "remote_write", Integrity: "not_available", Resume: "unsupported"}, err
	}
	return TransferResult{OK: true, Stage: "complete", Integrity: "not_available", Atomic: false, Resume: "unsupported"}, nil
}

// DownloadPath downloads a remote file or directory tree.
// Directories use tar-over-ssh; remotePath should be a directory.
func DownloadPath(c config.Connection, v *config.Vault, remotePath, localPath string) error {
	// Probe: if remote is a directory, tar it; else single file.
	isDir, err := remoteIsDir(c, v, remotePath)
	if err != nil {
		// Fall back to single-file download.
		return DownloadFile(c, v, remotePath, localPath)
	}
	if !isDir {
		return DownloadFile(c, v, remotePath, localPath)
	}
	return downloadDirTar(c, v, remotePath, localPath)
}

func remoteIsDir(c config.Connection, v *config.Vault, remotePath string) (bool, error) {
	client, err := dialSSH(c, v)
	if err != nil {
		return false, err
	}
	defer releaseClient(client, false)

	session, err := client.NewSession()
	if err != nil {
		return false, err
	}
	defer session.Close()

	cmd := fmt.Sprintf("if [ -d %s ]; then echo DIR; elif [ -f %s ]; then echo FILE; else echo MISSING; fi",
		ShellQuote(remotePath), ShellQuote(remotePath))
	out, err := session.CombinedOutput(cmd)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(string(out)) {
	case "DIR":
		return true, nil
	case "FILE":
		return false, nil
	default:
		return false, fmt.Errorf("remote path %s not found", remotePath)
	}
}

func uploadDirTar(c config.Connection, v *config.Vault, localDir, remoteDir string) error {
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

	// Ensure remote dir exists, then extract tar into it.
	remoteCmd := fmt.Sprintf("mkdir -p %s && tar -C %s -xf -", ShellQuote(remoteDir), ShellQuote(remoteDir))
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	if err := session.Start(remoteCmd); err != nil {
		return err
	}

	// Prefer system tar for correct metadata; fall back to pure Go walk+files.
	tarCmd := exec.Command("tar", "-C", localDir, "-cf", "-", ".")
	tarCmd.Stdout = stdin
	tarCmd.Stderr = os.Stderr
	if err := tarCmd.Run(); err != nil {
		_ = stdin.Close()
		_ = session.Close()
		// Fallback: recursive single-file upload
		return uploadDirWalk(c, v, localDir, remoteDir)
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	return session.Wait()
}

func downloadDirTar(c config.Connection, v *config.Vault, remoteDir, localDir string) error {
	if err := os.MkdirAll(localDir, 0o700); err != nil {
		return err
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

	tarLocal := exec.Command("tar", "-C", localDir, "-xf", "-")
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	session.Stderr = os.Stderr
	tarLocal.Stdin = stdout
	tarLocal.Stdout = os.Stdout
	tarLocal.Stderr = os.Stderr

	remoteCmd := fmt.Sprintf("tar -C %s -cf - .", ShellQuote(remoteDir))
	if err := session.Start(remoteCmd); err != nil {
		return err
	}
	if err := tarLocal.Start(); err != nil {
		_ = session.Close()
		return fmt.Errorf("local tar: %w", err)
	}
	if err := session.Wait(); err != nil {
		_ = tarLocal.Process.Kill()
		return err
	}
	return tarLocal.Wait()
}

func uploadDirWalk(c config.Connection, v *config.Vault, localDir, remoteDir string) error {
	return filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}
		// remote always uses forward slashes
		rel = filepath.ToSlash(rel)
		remote := strings.TrimRight(remoteDir, "/") + "/" + rel
		return UploadFile(c, v, path, remote)
	})
}

// LocalTreeFiles lists relative slash-paths of regular files under dir (tests).
func LocalTreeFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out, err
}

// Ensure no unused import if tar path always works — io used? remove if unused
var _ = io.Discard
