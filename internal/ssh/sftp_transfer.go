package ssh

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

// SFTP transfer (issue #87) serves targets without a POSIX login shell. It is
// selected explicitly (transfer: sftp on the host or --sftp), never by silently
// falling back from the shell path, and covers single regular files only.
// Every guarantee it reports is one the sftp subsystem actually provides:
//
//   - get streams into the local staging file and publishes it atomically;
//   - put writes a private sibling temporary file and renames it over the
//     destination. Only servers with posix-rename@openssh.com replace the
//     destination atomically (atomic=true); otherwise the previous destination
//     is moved aside first and Atomic is reported false;
//   - SHA-256 is computed locally over the bytes that crossed the wire, and put
//     reads the uploaded temporary file back over SFTP to compare digests.

const posixRenameExtension = "posix-rename@openssh.com"

// sftpReplacesAtomically reports whether the server can replace an existing
// destination in one step (posix-rename@openssh.com).
func sftpReplacesAtomically(client *sftp.Client) bool {
	_, ok := client.HasExtension(posixRenameExtension)
	return ok
}

// sftpDeadline closes the sftp client when the transfer timeout expires, which
// fails every in-flight request; callers ask expired() to tell a timeout from
// other failures.
type sftpDeadline struct {
	timedOut atomic.Bool
	timer    *time.Timer
}

func startSFTPDeadline(client *sftp.Client, timeout time.Duration) *sftpDeadline {
	deadline := &sftpDeadline{}
	if timeout > 0 {
		deadline.timer = time.AfterFunc(timeout, func() {
			deadline.timedOut.Store(true)
			_ = client.Close()
		})
	}
	return deadline
}

func (d *sftpDeadline) stop() {
	if d.timer != nil {
		d.timer.Stop()
	}
}

func (d *sftpDeadline) expired() bool { return d.timedOut.Load() }

// fail reports kind, or a timeout when the deadline fired first.
func (d *sftpDeadline) fail(result *TransferResult, kind machinecontract.Kind, sent int64, cause error) *TransferError {
	if d.expired() {
		result.Stage = "timeout"
		return transferError(machinecontract.TransferTimedOut, sent, cause)
	}
	return transferError(kind, sent, cause)
}

func sftpUnsupported(message string) *TransferError {
	return transferKindError(machinecontract.TransferSFTPUnsupported, 0, errors.New(message))
}

// hashingWriter feeds a digest while forwarding bytes and remembers the first
// write error, so a local write failure is not mistaken for a remote one.
type hashingWriter struct {
	dst  io.Writer
	hash io.Writer
	err  error
}

func (w *hashingWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if err != nil {
		w.err = err
		return n, err
	}
	if w.hash != nil {
		_, _ = w.hash.Write(p[:n])
	}
	return n, nil
}

// downloadFileSFTP downloads one regular file over SFTP.
func downloadFileSFTP(c config.Connection, v *config.Vault, remotePath, localPath string, opts DownloadOptions) (result TransferResult, resultErr error) {
	result = TransferResult{Direction: "get", Kind: "unknown", Stage: "dial", Integrity: "not_checked", Atomic: true, Resume: "unsupported"}
	client, err := dialSSH(c, v)
	if err != nil {
		return result, err
	}
	defer releaseClient(client, false)

	result.Stage = "capability"
	sc, err := sftp.NewClient(client, sftp.UseConcurrentWrites(true))
	if err != nil {
		return result, transferKindError(machinecontract.TransferSFTPUnavailable, 0, err)
	}
	defer func() { _ = sc.Close() }()
	deadline := startSFTPDeadline(sc, opts.Timeout)
	defer deadline.stop()

	result.Stage = "remote_read"
	info, err := sc.Stat(remotePath)
	if err != nil {
		return result, deadline.fail(&result, machinecontract.TransferDownloadRemoteRead, 0, err)
	}
	if info.IsDir() {
		result.Kind, result.Stage, result.Integrity, result.Atomic = "directory", "validate", "not_available", false
		return result, sftpUnsupported("SFTP transfer does not support directories yet; get single files or use the shell transfer")
	}
	if !info.Mode().IsRegular() {
		return result, deadline.fail(&result, machinecontract.TransferDownloadRemoteRead, 0, fmt.Errorf("remote path %s is not a regular file", remotePath))
	}
	result.Kind = "file"

	result.Stage = "local_write"
	staging, err := newFileDownloadStaging(localPath)
	if err != nil {
		return result, err
	}
	defer staging.cleanup()

	remote, err := sc.Open(remotePath)
	if err != nil {
		result.Stage = "remote_read"
		return result, deadline.fail(&result, machinecontract.TransferDownloadRemoteRead, 0, err)
	}
	defer func() { _ = remote.Close() }()

	hash := sha256.New()
	sink := &hashingWriter{dst: staging.file}
	if opts.VerifySHA256 {
		sink.hash = hash
	}
	result.Stage = "remote_read"
	received, copyErr := io.Copy(sink, remote)
	if copyErr != nil {
		if sink.err != nil && !deadline.expired() {
			result.Stage = "local_write"
			return result, transferError(machinecontract.TransferDownloadLocalWrite, 0, sink.err)
		}
		return result, deadline.fail(&result, machinecontract.TransferDownloadRemoteRead, 0, copyErr)
	}
	if opts.VerifySHA256 {
		result.Stage = "integrity"
		streamDigest := hex.EncodeToString(hash.Sum(nil))
		result.RemoteSHA256 = streamDigest
		if received != info.Size() {
			result.Integrity = "mismatch"
			return result, transferError(machinecontract.TransferDownloadIntegrityMismatch, 0, fmt.Errorf("received %d bytes, the server reported %d", received, info.Size()))
		}
		stagedDigest, err := fileSHA256(staging.path)
		if err != nil {
			return result, transferError(machinecontract.TransferDownloadLocalWrite, 0, err)
		}
		result.LocalSHA256 = stagedDigest
		if stagedDigest != streamDigest {
			result.Integrity = "mismatch"
			return result, transferError(machinecontract.TransferDownloadIntegrityMismatch, 0, errors.New("staged file SHA-256 does not match the received stream"))
		}
	}
	result.BytesReceived, err = staging.publish(localPath, systemFileDownloadPublishOperations())
	if err != nil {
		if failure, ok := machinecontract.FailureFromError(err); ok {
			result.Stage = failure.Stage
		}
		return result, err
	}
	result.OK = true
	result.Stage = "complete"
	if opts.VerifySHA256 {
		result.Integrity = "sha256_verified"
	}
	return result, nil
}

// uploadPathSFTP is UploadPathWithOptions for hosts that use SFTP.
func uploadPathSFTP(c config.Connection, v *config.Vault, localPath, remotePath string, opts UploadOptions) (TransferResult, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return TransferResult{Direction: "put", Kind: "unknown", Stage: "local_read", Integrity: "not_checked", Resume: "unsupported"}, transferError(machinecontract.TransferLocalRead, 0, err)
	}
	if info.IsDir() {
		return TransferResult{Direction: "put", Kind: "directory", Stage: "validate", Integrity: "not_available", Resume: "unsupported"},
			sftpUnsupported("SFTP transfer does not support directories yet; put single files or use the shell transfer")
	}
	if !info.Mode().IsRegular() {
		return TransferResult{Direction: "put", Kind: "unknown", Stage: "local_read", Integrity: "not_checked", Resume: "unsupported"},
			transferError(machinecontract.TransferDirectorySourceUnsupported, 0, fmt.Errorf("%s is not a regular file or directory", localPath))
	}
	result, err := uploadFileSFTP(c, v, localPath, remotePath, opts)
	result.Direction, result.Kind = "put", "file"
	return result, err
}

func uploadFileSFTP(c config.Connection, v *config.Vault, localPath, remotePath string, opts UploadOptions) (TransferResult, error) {
	result := TransferResult{Stage: "validate", Integrity: "not_checked", Atomic: true, Resume: "unsupported"}
	if opts.ResumeVersion != "" {
		return result, sftpUnsupported("SFTP transfer does not support --resume")
	}
	result.Stage = "local_read"
	local, err := os.Open(localPath) //nolint:gosec // localPath is the operator-chosen upload source
	if err != nil {
		return result, transferError(machinecontract.TransferLocalRead, 0, err)
	}
	defer func() { _ = local.Close() }()
	info, err := local.Stat()
	if err != nil {
		return result, transferError(machinecontract.TransferLocalFileStat, 0, err)
	}
	if !info.Mode().IsRegular() {
		return result, transferError(machinecontract.TransferRegularFileRequired, 0, fmt.Errorf("%s is not a regular file", localPath))
	}
	localDigest := ""
	if opts.VerifySHA256 {
		h := sha256.New()
		if _, err := io.Copy(h, local); err != nil {
			return result, transferError(machinecontract.TransferIntegritySourceRead, 0, err)
		}
		localDigest = hex.EncodeToString(h.Sum(nil))
		result.LocalSHA256 = localDigest
		if _, err := local.Seek(0, io.SeekStart); err != nil {
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

	result.Stage = "capability"
	sc, err := sftp.NewClient(client, sftp.UseConcurrentWrites(true))
	if err != nil {
		return result, transferKindError(machinecontract.TransferSFTPUnavailable, 0, err)
	}
	defer func() { _ = sc.Close() }()
	deadline := startSFTPDeadline(sc, opts.Timeout)
	defer deadline.stop()
	atomicReplace := sftpReplacesAtomically(sc)
	result.Atomic = atomicReplace

	result.Stage = "remote_write"
	if parent := RemoteParentDir(remotePath); parent != "" {
		if err := sftpMkdirParents(sc, parent, opts.dirMode()); err != nil {
			return result, deadline.fail(&result, machinecontract.TransferRemoteWriteFailed, 0, err)
		}
	}
	tmpPath, err := sftpSiblingName(remotePath, "ssm-upload")
	if err != nil {
		return result, transferError(machinecontract.TransferRemoteWriteFailed, 0, err)
	}
	remote, err := sc.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return result, deadline.fail(&result, machinecontract.TransferRemoteWriteFailed, 0, err)
	}
	published := false
	defer func() {
		if !published {
			_ = remote.Close()
			_ = sc.Remove(tmpPath)
		}
	}()
	// Keep the temporary file private until the payload is complete, like the
	// umask 077 of the shell path. Servers that ignore setstat still work.
	_ = remote.Chmod(0o600)
	written, err := io.Copy(remote, local)
	result.BytesSent = written
	if err != nil {
		return result, deadline.fail(&result, machinecontract.TransferRemoteWriteFailed, written, err)
	}
	if err := remote.Chmod(info.Mode().Perm()); err != nil {
		return result, deadline.fail(&result, machinecontract.TransferRemotePermissionsFailed, written, err)
	}
	if err := remote.Close(); err != nil {
		return result, deadline.fail(&result, machinecontract.TransferRemoteCloseFailed, written, err)
	}

	result.Stage = "integrity"
	stored, err := sc.Stat(tmpPath)
	if err != nil {
		return result, deadline.fail(&result, machinecontract.TransferReceiptInvalid, written, err)
	}
	if stored.Size() != info.Size() {
		result.Integrity = "mismatch"
		return result, transferError(machinecontract.TransferIntegrityMismatch, written, fmt.Errorf("remote temporary file has %d bytes, expected %d", stored.Size(), info.Size()))
	}
	if opts.VerifySHA256 {
		readBack, err := sc.Open(tmpPath)
		if err != nil {
			result.Integrity = "not_available"
			return result, deadline.fail(&result, machinecontract.TransferSFTPReadbackUnavailable, written, err)
		}
		h := sha256.New()
		_, copyErr := io.Copy(h, readBack)
		_ = readBack.Close()
		if copyErr != nil {
			result.Integrity = "not_available"
			return result, deadline.fail(&result, machinecontract.TransferSFTPReadbackUnavailable, written, copyErr)
		}
		result.RemoteSHA256 = hex.EncodeToString(h.Sum(nil))
		if result.RemoteSHA256 != localDigest {
			result.Integrity = "mismatch"
			return result, transferError(machinecontract.TransferIntegrityMismatch, written, errors.New("remote integrity verification failed"))
		}
	}

	result.Stage = "remote_write"
	if atomicReplace {
		err = sc.PosixRename(tmpPath, remotePath)
	} else {
		err = sftpReplaceWithoutPosixRename(sc, tmpPath, remotePath)
	}
	if err != nil {
		return result, deadline.fail(&result, machinecontract.TransferRemoteWriteFailed, written, err)
	}
	published = true
	result.OK = true
	result.Stage = "complete"
	if opts.VerifySHA256 {
		result.Integrity = "sha256_verified"
	} else {
		result.Integrity = "size_verified"
	}
	return result, nil
}

// sftpMkdirParents creates dir and its missing ancestors with permission mode,
// whatever the server umask, and leaves existing directories untouched.
func sftpMkdirParents(sc *sftp.Client, dir string, mode os.FileMode) error {
	if dir == "" || dir == "/" || dir == "." {
		return nil
	}
	if info, err := sc.Stat(dir); err == nil {
		if info.IsDir() {
			return nil
		}
		return fmt.Errorf("mkdir %s: exists and is not a directory", dir)
	}
	if err := sftpMkdirParents(sc, path.Dir(dir), mode); err != nil {
		return err
	}
	if err := sc.Mkdir(dir); err != nil {
		if info, statErr := sc.Stat(dir); statErr == nil && info.IsDir() {
			return nil
		}
		return err
	}
	return sc.Chmod(dir, mode)
}

// sftpReplaceWithoutPosixRename publishes tmpPath for servers whose plain
// rename refuses to overwrite. The previous destination is moved aside rather
// than deleted so a failed publish can put it back; the result is still not
// atomic (a reader can briefly see no destination) and is reported as such.
func sftpReplaceWithoutPosixRename(sc *sftp.Client, tmpPath, remotePath string) error {
	if _, err := sc.Lstat(remotePath); err != nil {
		return sc.Rename(tmpPath, remotePath)
	}
	backup, err := sftpSiblingName(remotePath, "ssm-old")
	if err != nil {
		return err
	}
	if err := sc.Rename(remotePath, backup); err != nil {
		return fmt.Errorf("move the previous destination aside: %w", err)
	}
	if err := sc.Rename(tmpPath, remotePath); err != nil {
		if restoreErr := sc.Rename(backup, remotePath); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore the previous destination from %s: %w", backup, restoreErr))
		}
		return err
	}
	_ = sc.Remove(backup)
	return nil
}

func sftpSiblingName(remotePath, label string) (string, error) {
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return remotePath + "." + label + "." + hex.EncodeToString(random[:]), nil
}
