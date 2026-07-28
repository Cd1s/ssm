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
	"ssm/internal/machinecontract"
)

func UploadPathWithOptions(c config.Connection, v *config.Vault, localPath, remotePath string, opts UploadOptions) (TransferResult, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return TransferResult{Direction: "put", Kind: "unknown", Stage: "local_read", Integrity: "not_checked", Resume: "unsupported"}, transferError(machinecontract.TransferLocalRead, 0, err)
	}
	if info.Mode().IsRegular() {
		result, err := UploadFileWithOptions(c, v, localPath, remotePath, opts)
		result.Direction, result.Kind = "put", "file"
		return result, err
	}
	if !info.IsDir() {
		return TransferResult{Direction: "put", Kind: "unknown", Stage: "local_read", Integrity: "not_checked", Resume: "unsupported"}, transferError(machinecontract.TransferDirectorySourceUnsupported, 0, fmt.Errorf("%s is not a regular file or directory", localPath))
	}
	if opts.VerifySHA256 || opts.Timeout > 0 || opts.ResumeVersion != "" {
		return TransferResult{Direction: "put", Kind: "directory", Stage: "validate", Integrity: "not_available", Resume: "unsupported"}, transferError(machinecontract.TransferDirectoryOptionsUnsupported, 0, errors.New("directory transfer does not support requested reliability options"))
	}
	err = uploadDirTar(c, v, localPath, remotePath)
	if err != nil {
		return TransferResult{Direction: "put", Kind: "directory", Stage: "remote_write", Integrity: "not_available", Resume: "unsupported"}, err
	}
	return TransferResult{OK: true, Direction: "put", Kind: "directory", Stage: "complete", Integrity: "not_available", Atomic: false, Resume: "unsupported"}, nil
}

// DownloadPath downloads a remote file or directory tree.
// Directories use tar-over-ssh; remotePath should be a directory.
func DownloadPath(c config.Connection, v *config.Vault, remotePath, localPath string) (TransferResult, error) {
	// Probe: if remote is a directory, tar it; else single file.
	isDir, err := remoteIsDir(c, v, remotePath)
	if err != nil {
		return TransferResult{Direction: "get", Kind: "unknown", Stage: "discovery"}, err
	}
	if !isDir {
		return DownloadFile(c, v, remotePath, localPath)
	}
	result := TransferResult{Direction: "get", Kind: "directory", Stage: "remote_read", Integrity: "not_available", Atomic: false, Resume: "unsupported"}
	err = downloadDirTar(c, v, remotePath, localPath)
	if err != nil {
		return result, err
	}
	result.OK = true
	result.Stage = "complete"
	return result, nil
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

func uploadDirTar(c config.Connection, v *config.Vault, localDir, remoteDir string) (resultErr error) {
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
	stdoutSpool, err := machinecontract.NewDiagnosticSpool(os.Stdout)
	if err != nil {
		return err
	}
	defer func() { _ = stdoutSpool.Close() }()
	stderrSpool, err := machinecontract.NewDiagnosticSpool(os.Stderr)
	if err != nil {
		return errors.Join(err, stdoutSpool.Close())
	}
	defer func() { _ = stderrSpool.Close() }()
	diagnostics := []*machinecontract.DiagnosticSpool{stdoutSpool, stderrSpool}
	diagnosticsSucceeded := false
	defer func() {
		if replayErr := replayDiagnosticSpools(diagnosticsSucceeded, diagnostics...); resultErr == nil {
			resultErr = replayErr
		}
	}()
	session.Stdout = stdoutSpool
	session.Stderr = stderrSpool
	if err := session.Start(remoteCmd); err != nil {
		return err
	}

	// Prefer system tar for correct metadata; fall back to pure Go walk+files.
	tarCmd := exec.Command("tar", "-C", localDir, "-cf", "-", ".")
	tarCmd.Stdout = stdin
	tarCmd.Stderr = stderrSpool
	if err := tarCmd.Run(); err != nil {
		_ = stdin.Close()
		// Drain the failed tar session before falling back so diagnostics already
		// emitted by the remote extractor retain their historical ordering and
		// bytes. Its failure does not override a successful walk fallback.
		_ = session.Wait()
		// Fallback: recursive single-file upload
		resultErr = uploadDirWalk(c, v, localDir, remoteDir)
		diagnosticsSucceeded = resultErr == nil
		return resultErr
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	resultErr = session.Wait()
	diagnosticsSucceeded = resultErr == nil
	return resultErr
}

func downloadDirTar(c config.Connection, v *config.Vault, remoteDir, localDir string) (resultErr error) {
	staging, err := newDirectoryDownloadStaging(localDir)
	if err != nil {
		return err
	}
	defer staging.cleanup()
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

	tarLocal := exec.Command("tar", "-C", staging.path, "-xf", "-") //nolint:gosec // fixed binary/argv; staging is created internally with os.MkdirTemp
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderrSpool, err := machinecontract.NewDiagnosticSpool(os.Stderr)
	if err != nil {
		return err
	}
	defer func() { _ = stderrSpool.Close() }()
	session.Stderr = stderrSpool
	tarLocal.Stdin = stdout
	stdoutSpool, err := machinecontract.NewDiagnosticSpool(os.Stdout)
	if err != nil {
		return errors.Join(err, stderrSpool.Close())
	}
	defer func() { _ = stdoutSpool.Close() }()
	diagnostics := []*machinecontract.DiagnosticSpool{stdoutSpool, stderrSpool}
	diagnosticsSucceeded := false
	defer func() {
		if replayErr := replayDiagnosticSpools(diagnosticsSucceeded, diagnostics...); resultErr == nil {
			resultErr = replayErr
		}
	}()
	tarLocal.Stdout = stdoutSpool
	tarLocal.Stderr = stderrSpool

	remoteCmd := fmt.Sprintf("tar -C %s -cf - .", ShellQuote(remoteDir))
	if err := session.Start(remoteCmd); err != nil {
		return err
	}
	if err := tarLocal.Start(); err != nil {
		_ = session.Close()
		return transferError(machinecontract.TransferDownloadLocalWrite, 0, fmt.Errorf("local tar: %w", err))
	}
	if err := session.Wait(); err != nil {
		_ = tarLocal.Process.Kill()
		_ = tarLocal.Wait()
		return transferError(machinecontract.TransferDownloadRemoteRead, 0, err)
	}
	resultErr = tarLocal.Wait()
	if resultErr != nil {
		return transferError(machinecontract.TransferDownloadLocalWrite, 0, resultErr)
	}
	if err := staging.publish(localDir, systemDirectoryDownloadPublishOperations()); err != nil {
		return err
	}
	diagnosticsSucceeded = resultErr == nil
	return resultErr
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

func replayDiagnosticSpools(success bool, spools ...*machinecontract.DiagnosticSpool) error {
	var result error
	for _, spool := range spools {
		result = errors.Join(result, spool.Replay(success))
	}
	return result
}

// Ensure no unused import if tar path always works — io used? remove if unused
var _ = io.Discard
