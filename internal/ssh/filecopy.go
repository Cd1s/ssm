package ssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

type UploadOptions struct {
	VerifySHA256  bool
	Timeout       time.Duration
	ResumeVersion string
}

type TransferResult struct {
	OK           bool   `json:"ok"`
	Stage        string `json:"stage"`
	BytesSent    int64  `json:"bytes_sent"`
	Integrity    string `json:"integrity"`
	LocalSHA256  string `json:"local_sha256,omitempty"`
	RemoteSHA256 string `json:"remote_sha256,omitempty"`
	Atomic       bool   `json:"atomic"`
	Resume       string `json:"resume"`
	BytesReused  int64  `json:"bytes_reused,omitempty"`
}

type TransferError struct {
	failure   machinecontract.Failure
	BytesSent int64
	Cause     error
}

func (e *TransferError) Error() string { return e.Cause.Error() }
func (e *TransferError) Unwrap() error { return e.Cause }
func (e *TransferError) ContractFailure() machinecontract.Failure {
	return e.failure
}

func UploadFile(c config.Connection, v *config.Vault, localPath, remotePath string) error {
	_, err := UploadFileWithOptions(c, v, localPath, remotePath, UploadOptions{})
	return err
}

func UploadFileWithOptions(c config.Connection, v *config.Vault, localPath, remotePath string, opts UploadOptions) (TransferResult, error) {
	if opts.ResumeVersion != "" {
		return uploadFileResumable(c, v, localPath, remotePath, opts)
	}
	result := TransferResult{Stage: "local_read", Integrity: "not_checked", Atomic: true, Resume: "unsupported"}
	f, err := os.Open(localPath)
	if err != nil {
		return result, transferError(machinecontract.TransferLocalRead, 0, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return result, transferError(machinecontract.TransferLocalFileStat, 0, err)
	}
	if !info.Mode().IsRegular() {
		return result, transferError(machinecontract.TransferRegularFileRequired, 0, fmt.Errorf("%s is not a regular file", localPath))
	}

	localDigest := ""
	if opts.VerifySHA256 {
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return result, transferError(machinecontract.TransferIntegritySourceRead, 0, err)
		}
		localDigest = hex.EncodeToString(h.Sum(nil))
		result.LocalSHA256 = localDigest
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return result, transferError(machinecontract.TransferSeekableSourceRequired, 0, err)
		}
	}

	result.Stage = "dial"
	client, err := dialSSH(c, v)
	if err != nil {
		classified := ClassifyError(err, c)
		return result, transferClassifiedError(classified.Failure, 0, classified)
	}
	defer releaseClient(client, false)

	session, err := client.NewSession()
	if err != nil {
		return result, transferError(machinecontract.TransferSessionOpenFailed, 0, err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return result, transferError(machinecontract.TransferStdinOpenFailed, 0, err)
	}
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	cmd := uploadCommandWithIntegrity(remotePath, info.Mode(), info.Size(), localDigest)
	if err := session.Start(cmd); err != nil {
		return result, transferError(machinecontract.TransferStartFailed, 0, err)
	}
	var timedOut atomic.Bool
	var timer *time.Timer
	if opts.Timeout > 0 {
		timer = time.AfterFunc(opts.Timeout, func() {
			timedOut.Store(true)
			_ = session.Close()
		})
		defer timer.Stop()
	}
	result.Stage = "remote_write"
	written, copyErr := io.Copy(stdin, f)
	result.BytesSent = written
	if copyErr != nil {
		_ = stdin.Close()
		_ = session.Close()
		if timedOut.Load() {
			return result, transferError(machinecontract.TransferTimedOut, written, copyErr)
		}
		return result, transferError(machinecontract.TransferRemoteWriteFailed, written, copyErr)
	}
	if err := stdin.Close(); err != nil {
		_ = session.Close()
		return result, transferError(machinecontract.TransferRemoteCloseFailed, written, err)
	}
	if err := session.Wait(); err != nil {
		if timedOut.Load() {
			return result, transferError(machinecontract.TransferTimedOut, written, err)
		}
		if strings.Contains(stdout.String(), "SSM_INTEGRITY_MISMATCH") {
			result.Stage = "integrity"
			result.Integrity = "mismatch"
			return result, transferError(machinecontract.TransferIntegrityMismatch, written, errors.New("remote integrity verification failed"))
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return result, transferError(machinecontract.TransferRemotePermissionsFailed, written, errors.New(message))
	}
	remoteSize, remoteDigest, err := parseUploadReceipt(stdout.String())
	if err != nil || remoteSize != info.Size() || (opts.VerifySHA256 && remoteDigest != localDigest) {
		result.Stage = "integrity"
		result.Integrity = "mismatch"
		return result, transferError(machinecontract.TransferReceiptInvalid, written, errors.New("invalid remote integrity receipt"))
	}
	result.OK = true
	result.Stage = "complete"
	result.RemoteSHA256 = remoteDigest
	if opts.VerifySHA256 {
		result.Integrity = "sha256_verified"
	} else {
		result.Integrity = "size_verified"
	}
	return result, nil
}

func transferError(kind machinecontract.Kind, bytesSent int64, cause error) *TransferError {
	return transferClassifiedError(machinecontract.Classify(kind, machinecontract.Details{Cause: cause}), bytesSent, cause)
}

func transferClassifiedError(failure machinecontract.Failure, bytesSent int64, cause error) *TransferError {
	return &TransferError{failure: failure, BytesSent: bytesSent, Cause: cause}
}

// DownloadFile copies remotePath from the server to localPath.
// Parent directories of localPath are created as needed.
func DownloadFile(c config.Connection, v *config.Vault, remotePath, localPath string) (resultErr error) {
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
	sessionStderr, err := machinecontract.NewDiagnosticSpool(os.Stderr)
	if err != nil {
		return err
	}
	defer func() { _ = sessionStderr.Close() }()
	diagnosticsSucceeded := false
	defer func() {
		if replayErr := sessionStderr.Replay(diagnosticsSucceeded); resultErr == nil {
			resultErr = replayErr
		}
	}()
	session.Stderr = sessionStderr

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
	diagnosticsSucceeded = true
	return nil
}

func uploadCommand(remotePath string, mode os.FileMode) string {
	return uploadCommandWithIntegrity(remotePath, mode, -1, "")
}

func uploadCommandWithIntegrity(remotePath string, mode os.FileMode, size int64, digest string) string {
	quotedPath := ShellQuote(remotePath)
	parent := RemoteParentDir(remotePath)
	prefix := "umask 077; "
	if parent != "" {
		prefix += "mkdir -p " + ShellQuote(parent) + " && "
	}
	// Stream into a sibling temporary file and rename only after the complete
	// payload and mode have been written. A failed transfer leaves the previous
	// destination intact and the trap removes the partial upload.
	checks := "actual_size=$(wc -c < \"$tmp\" | tr -d ' ') || exit 74; "
	if size >= 0 {
		checks += fmt.Sprintf("[ \"$actual_size\" = %d ] || { echo SSM_INTEGRITY_MISMATCH; exit 65; }; ", size)
	}
	if digest != "" {
		checks += fmt.Sprintf("actual_sha=$(sha256sum -- \"$tmp\" | awk '{print $1}') || exit 74; [ \"$actual_sha\" = %s ] || { echo SSM_INTEGRITY_MISMATCH; exit 65; }; ", ShellQuote(digest))
	} else {
		checks += "actual_sha=-; "
	}
	return fmt.Sprintf("%stmp=%s.ssm-upload.$$; trap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM; cat > \"$tmp\" && chmod %04o \"$tmp\" || exit $?; %smv -f -- \"$tmp\" %s && trap - EXIT HUP INT TERM && printf 'SSM_TRANSFER %%s %%s\\n' \"$actual_size\" \"$actual_sha\"", prefix, quotedPath, uint32(mode.Perm()), checks, quotedPath)
}

func parseUploadReceipt(output string) (int64, string, error) {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) != 3 || fields[0] != "SSM_TRANSFER" {
		return 0, "", fmt.Errorf("missing upload receipt")
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, "", err
	}
	digest := fields[2]
	if digest == "-" {
		digest = ""
	}
	return size, digest, nil
}

func downloadCommand(remotePath string) string {
	// cat is enough for regular files; fail clearly on missing paths.
	return "cat -- " + ShellQuote(remotePath)
}
