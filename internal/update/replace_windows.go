//go:build windows

package update

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsReplacementPhaseAfterLock        = "after_lock"
	windowsReplacementPhaseBeforeTargetMove = "before_target_move"
	windowsReplacementPhaseAfterBackup      = "after_backup"
	windowsReplacementPhaseBeforeStageMove  = "before_stage_move"
	windowsReplacementPhaseTargetRenameGap  = "target_rename_gap"
	windowsReplacementPhaseStageRenameGap   = "stage_rename_gap"
	windowsReplacementPhaseSecurityClose    = "security_close"
	windowsReplacementPhaseLockClose        = "lock_close"
)

var (
	renameWindowsReplacementHandle         = renameWindowsFileHandle
	linkWindowsReplacementHandle           = linkWindowsFileHandle
	unlinkWindowsMappedReplacementHandle   = unlinkWindowsMappedFileHandle
	windowsReplacementHandleIsCurrentImage = windowsReplacementHandleIsCurrentExecutable
	getWindowsFileInformationByHandleEx    = windows.GetFileInformationByHandleEx
	getWindowsFinalPathNameByHandle        = windows.GetFinalPathNameByHandle
	getWindowsLongPathName                 = windows.GetLongPathName
	openWindowsReplacementInspectionFile   = openWindowsReplacementFile
	windowsReplacementTestHook             func(string) error
	windowsRollbackAuthenticationTestHook  func(
		string,
		*windowsReplacementSecurityState,
	) error
)

func replaceExecutable(
	staged,
	target string,
	expectedDigest [sha256.Size]byte,
	_ os.FileMode,
) (resultErr error) {
	committed := false
	stagedDirectory, err := filepath.Abs(filepath.Clean(filepath.Dir(staged)))
	if err != nil {
		return fmt.Errorf("resolve Windows replacement staging directory: %w", err)
	}
	targetDirectory, err := filepath.Abs(filepath.Clean(filepath.Dir(target)))
	if err != nil {
		return fmt.Errorf("resolve Windows executable directory: %w", err)
	}
	if !strings.EqualFold(stagedDirectory, targetDirectory) {
		return fmt.Errorf("Windows replacement staging is not on the executable filesystem")
	}

	updateLock, err := acquireWindowsReplacementLock(target)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := updateLock.close()
		if hookErr := runWindowsReplacementTestHook(windowsReplacementPhaseLockClose); hookErr != nil {
			closeErr = errors.Join(closeErr, hookErr)
		}
		if closeErr != nil && !committed {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("release Windows executable update lock: %w", closeErr),
			)
		}
	}()
	if err := runWindowsReplacementTestHook(windowsReplacementPhaseAfterLock); err != nil {
		return fmt.Errorf("pause after Windows executable update lock: %w", err)
	}
	if err := cleanupCompletedWindowsRollbackUnderLockWithPolicy(target, updateLock.policy); err != nil {
		return fmt.Errorf("clean previous Windows executable: %w", blockOnRecoveryEvidence(err))
	}

	security, err := prepareWindowsReplacementSecurity(
		staged,
		target,
	)
	if err != nil {
		return fmt.Errorf("preserve Windows executable security descriptor: %w", err)
	}
	targetIdentity := security.targetIdentity
	stageIdentity := security.stageIdentity
	closeSecurity := func() error {
		if security == nil {
			return nil
		}
		err := security.close()
		if hookErr := runWindowsReplacementTestHook(windowsReplacementPhaseSecurityClose); hookErr != nil {
			err = errors.Join(err, hookErr)
		}
		security = nil
		return err
	}
	failBeforeRecord := func(operation string, operationErr error) error {
		if closeErr := closeSecurity(); closeErr != nil {
			operationErr = errors.Join(
				operationErr,
				fmt.Errorf("release Windows security state: %w", closeErr),
			)
		}
		return fmt.Errorf("%s: %w", operation, operationErr)
	}
	if err := requireWindowsReplacementHandleDigest(
		security.staged,
		expectedDigest,
		"verified Windows replacement",
	); err != nil {
		return failBeforeRecord("authenticate verified Windows replacement bytes", err)
	}
	rollbackDigest, err := digestWindowsReplacementHandle(
		security.target,
		"current Windows executable",
	)
	if err != nil {
		return failBeforeRecord("authenticate Windows rollback bytes", err)
	}

	if err := runWindowsReplacementTestHook(windowsReplacementPhaseBeforeTargetMove); err != nil {
		return failBeforeRecord("continue before preserving Windows executable", err)
	}
	securityBinding, err := bindWindowsSecurityDescriptor(
		security.sourceDescriptor.descriptor,
		security.tier.full,
	)
	if err != nil {
		return failBeforeRecord("bind Windows executable security descriptor", err)
	}

	record, err := createWindowsReplacementRecord(
		target,
		targetIdentity,
		stageIdentity,
		rollbackDigest,
		securityBinding,
		updateLock.policy,
	)
	if err != nil {
		return failBeforeRecord("record Windows rollback ownership", err)
	}
	failBeforeBackup := func(operation string, operationErr error) error {
		if removeErr := record.remove(); removeErr != nil {
			operationErr = errors.Join(
				operationErr,
				fmt.Errorf("remove Windows rollback ownership record: %w", removeErr),
			)
		}
		if closeErr := record.close(); closeErr != nil {
			operationErr = errors.Join(
				operationErr,
				fmt.Errorf("close Windows rollback ownership record: %w", closeErr),
			)
		}
		if closeErr := closeSecurity(); closeErr != nil {
			operationErr = errors.Join(
				operationErr,
				fmt.Errorf("release Windows security state: %w", closeErr),
			)
		}
		return fmt.Errorf("%s: %w", operation, operationErr)
	}
	failAfterBackup := func(operation string, operationErr error) error {
		rollbackErr := rollbackWindowsReplacement(
			target,
			security,
			record.data.rollbackDigest,
			record.data.securityBinding,
		)
		if rollbackErr == nil {
			if removeErr := record.remove(); removeErr != nil {
				operationErr = errors.Join(
					operationErr,
					fmt.Errorf("remove Windows rollback ownership record: %w", removeErr),
				)
			}
		}
		if closeErr := record.close(); closeErr != nil {
			operationErr = errors.Join(
				operationErr,
				fmt.Errorf("close Windows rollback ownership record: %w", closeErr),
			)
		}
		if closeErr := closeSecurity(); closeErr != nil {
			operationErr = errors.Join(
				operationErr,
				fmt.Errorf("release Windows security state: %w", closeErr),
			)
		}
		if rollbackErr != nil {
			failure := fmt.Errorf("%s: %w (rollback failed: %v)", operation, operationErr, rollbackErr)
			if IsRecoveryRequired(rollbackErr) {
				return requireRecovery(failure)
			}
			return blockOnRecoveryEvidence(failure)
		}
		return fmt.Errorf("%s: %w", operation, operationErr)
	}

	backup := windowsReplacementBackup(target)
	if err := renameExpectedWindowsReplacementHandle(
		security.target,
		backup,
		targetIdentity,
		false,
		windowsReplacementPhaseTargetRenameGap,
		"current Windows executable",
		"Windows rollback image",
	); err != nil {
		if targetErr := requireWindowsReplacementPathIdentity(
			target,
			targetIdentity,
			"current Windows executable",
		); targetErr == nil {
			return failBeforeBackup("preserve running Windows executable", err)
		}
		return failAfterBackup("preserve running Windows executable", err)
	}
	if err := runWindowsReplacementTestHook(windowsReplacementPhaseAfterBackup); err != nil {
		return failAfterBackup("continue after preserving running Windows executable", err)
	}
	if err := runWindowsReplacementTestHook(windowsReplacementPhaseBeforeStageMove); err != nil {
		return failAfterBackup("revalidate verified Windows replacement before install", err)
	}
	if err := renameExpectedWindowsReplacementHandle(
		security.staged,
		target,
		stageIdentity,
		true,
		windowsReplacementPhaseStageRenameGap,
		"verified Windows replacement",
		"canonical Windows executable",
	); err != nil {
		return failAfterBackup("install verified Windows executable", err)
	}
	if err := requireWindowsReplacementPathIdentity(
		backup,
		targetIdentity,
		"Windows rollback image",
	); err != nil {
		return failAfterBackup("verify preserved Windows rollback image", err)
	}
	if err := security.apply(); err != nil {
		return failAfterBackup("apply preserved Windows security descriptor", err)
	}
	if err := security.verify(); err != nil {
		return failAfterBackup("verify preserved Windows security descriptor", err)
	}
	if err := requireWindowsReplacementPathIdentity(
		target,
		stageIdentity,
		"installed Windows executable",
	); err != nil {
		return failAfterBackup("verify installed Windows executable identity", err)
	}
	if err := security.restorePrivileges(); err != nil {
		return failAfterBackup("restore Windows security privileges before commit", err)
	}
	if err := record.markCompleted(); err != nil {
		return failAfterBackup("mark Windows replacement complete", err)
	}
	committed = true
	// The completed, authenticated record makes the rollback image deferred
	// cleanup state. Close failures after this point must not retroactively
	// report update_failed while the verified replacement is canonical.
	_ = record.close()
	_ = closeSecurity()
	return nil
}

func runWindowsReplacementTestHook(phase string) error {
	if windowsReplacementTestHook == nil {
		return nil
	}
	return windowsReplacementTestHook(phase)
}

type windowsFileIdentity struct {
	volumeSerialNumber uint64
	fileID             [16]byte
}

type windowsFileIDInfo struct {
	volumeSerialNumber uint64
	fileID             [16]byte
}

func inspectWindowsReplacementPath(path, description string) (windowsFileIdentity, error) {
	handle, err := openWindowsReplacementInspectionFile(path, 0)
	if err != nil {
		return windowsFileIdentity{}, fmt.Errorf("inspect %s: %w", description, err)
	}
	identity, inspectErr := inspectWindowsReplacementHandle(handle, description)
	closeErr := windows.CloseHandle(handle)
	if inspectErr != nil {
		return windowsFileIdentity{}, inspectErr
	}
	if closeErr != nil {
		return windowsFileIdentity{}, fmt.Errorf("close %s inspection handle: %w", description, closeErr)
	}
	return identity, nil
}

func inspectOptionalWindowsReplacementPath(
	path,
	description string,
) (windowsFileIdentity, bool, error) {
	identity, err := inspectWindowsReplacementPath(path, description)
	if err != nil && isWindowsPathNotFound(err) {
		return windowsFileIdentity{}, false, nil
	}
	if err != nil {
		return windowsFileIdentity{}, false, err
	}
	return identity, true, nil
}

func inspectWindowsReplacementHandle(
	handle windows.Handle,
	description string,
) (windowsFileIdentity, error) {
	identity, links, err := inspectWindowsReplacementHandleObject(handle, description)
	if err != nil {
		return windowsFileIdentity{}, err
	}
	if links != 1 {
		return windowsFileIdentity{}, fmt.Errorf("%s has %d hard links", description, links)
	}
	return identity, nil
}

func inspectWindowsReplacementHandleObject(
	handle windows.Handle,
	description string,
) (windowsFileIdentity, uint32, error) {
	fileType, err := windows.GetFileType(handle)
	if err != nil {
		return windowsFileIdentity{}, 0, fmt.Errorf("inspect %s file type: %w", description, err)
	}
	if fileType != windows.FILE_TYPE_DISK {
		return windowsFileIdentity{}, 0, fmt.Errorf("%s is not a disk file", description)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return windowsFileIdentity{}, 0, fmt.Errorf("inspect %s identity: %w", description, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return windowsFileIdentity{}, 0, fmt.Errorf("%s is a reparse point", description)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return windowsFileIdentity{}, 0, fmt.Errorf("%s is a directory", description)
	}
	var strongInfo windowsFileIDInfo
	if err := getWindowsFileInformationByHandleEx(
		handle,
		windows.FileIdInfo,
		(*byte)(unsafe.Pointer(&strongInfo)),
		uint32(unsafe.Sizeof(strongInfo)),
	); err != nil {
		return windowsFileIdentity{}, 0, fmt.Errorf(
			"inspect %s strong file identity: %w",
			description,
			err,
		)
	}
	return windowsFileIdentity{
		volumeSerialNumber: strongInfo.volumeSerialNumber,
		fileID:             strongInfo.fileID,
	}, info.NumberOfLinks, nil
}

func digestWindowsReplacementHandle(
	handle windows.Handle,
	description string,
) ([sha256.Size]byte, error) {
	if _, err := windows.SetFilePointer(handle, 0, nil, windows.FILE_BEGIN); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("seek %s for digest: %w", description, err)
	}
	digest := sha256.New()
	buffer := make([]byte, 32<<10)
	for {
		var read uint32
		err := windows.ReadFile(handle, buffer, &read, nil)
		if read > 0 {
			_, _ = digest.Write(buffer[:read])
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, windows.ERROR_HANDLE_EOF) {
				break
			}
			return [sha256.Size]byte{}, fmt.Errorf("read %s for digest: %w", description, err)
		}
		if read == 0 {
			break
		}
	}
	if _, err := windows.SetFilePointer(handle, 0, nil, windows.FILE_BEGIN); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("rewind %s after digest: %w", description, err)
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func requireWindowsReplacementHandleDigest(
	handle windows.Handle,
	expected [sha256.Size]byte,
	description string,
) error {
	actual, err := digestWindowsReplacementHandle(handle, description)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("%s digest does not match authenticated bytes", description)
	}
	return nil
}

func requireWindowsReplacementHandleIdentity(
	handle windows.Handle,
	expected windowsFileIdentity,
	description string,
) error {
	identity, err := inspectWindowsReplacementHandle(handle, description)
	if err != nil {
		return err
	}
	if identity != expected {
		return fmt.Errorf("%s identity changed after inspection", description)
	}
	return nil
}

func requireWindowsReplacementHandleObjectIdentity(
	handle windows.Handle,
	expected windowsFileIdentity,
	expectedLinks uint32,
	description string,
) error {
	identity, links, err := inspectWindowsReplacementHandleObject(handle, description)
	if err != nil {
		return err
	}
	if identity != expected {
		return fmt.Errorf("%s identity changed after inspection", description)
	}
	if links != expectedLinks {
		return fmt.Errorf("%s has %d hard links", description, links)
	}
	return nil
}

func requireWindowsReplacementPathIdentity(
	path string,
	expected windowsFileIdentity,
	description string,
) error {
	identity, err := inspectWindowsReplacementPath(path, description)
	if err != nil {
		return err
	}
	if identity != expected {
		return fmt.Errorf("%s identity changed after inspection", description)
	}
	return nil
}

func requireWindowsReplacementPathObjectIdentity(
	path string,
	expected windowsFileIdentity,
	expectedLinks uint32,
	description string,
) error {
	handle, err := openWindowsReplacementFile(path, 0)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", description, err)
	}
	identity, links, inspectErr := inspectWindowsReplacementHandleObject(handle, description)
	closeErr := windows.CloseHandle(handle)
	if inspectErr != nil {
		return inspectErr
	}
	if closeErr != nil {
		return fmt.Errorf("close %s inspection handle: %w", description, closeErr)
	}
	if identity != expected {
		return fmt.Errorf("%s identity changed after inspection", description)
	}
	if links != expectedLinks {
		return fmt.Errorf("%s has %d hard links", description, links)
	}
	return nil
}

func requireWindowsReplacementPathAbsent(path, description string) error {
	_, exists, err := inspectOptionalWindowsReplacementPath(path, description)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%s appeared unexpectedly", description)
	}
	return nil
}

func isWindowsPathNotFound(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func openWindowsReplacementFile(path string, access uint32) (windows.Handle, error) {
	return openWindowsReplacementFileWithShare(
		path,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
	)
}

func openWindowsProtectedReplacementFile(path string, access uint32) (windows.Handle, error) {
	return openWindowsReplacementFileWithShare(path, access, windows.FILE_SHARE_READ)
}

func openWindowsReplacementDeleteGuard(path string) (windows.Handle, error) {
	// DELETE access makes this open fail while an existing handle withholds
	// delete sharing and prevents a later such handle from opening. Share delete
	// from this handle so the guard does not block the POSIX replacement itself.
	return openWindowsReplacementFile(path, windows.DELETE)
}

func windowsReplacementHandleIsCurrentExecutable(handle windows.Handle) (bool, error) {
	targetIdentity, _, err := inspectWindowsReplacementHandleObject(
		handle,
		"canonical Windows executable awaiting recovery",
	)
	if err != nil {
		return false, err
	}
	currentPath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("resolve current Windows executable for recovery: %w", err)
	}
	currentHandle, err := openWindowsReplacementFile(currentPath, 0)
	if err != nil {
		return false, fmt.Errorf("open current Windows executable for recovery: %w", err)
	}
	currentIdentity, _, inspectErr := inspectWindowsReplacementHandleObject(
		currentHandle,
		"current mapped Windows executable",
	)
	closeErr := windows.CloseHandle(currentHandle)
	if inspectErr != nil {
		return false, inspectErr
	}
	if closeErr != nil {
		return false, fmt.Errorf("close current Windows executable inspection handle: %w", closeErr)
	}
	return currentIdentity == targetIdentity, nil
}

func openWindowsReplacementFileWithShare(
	path string,
	access,
	share uint32,
) (windows.Handle, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(
		pathPointer,
		access,
		share,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|
			windows.FILE_FLAG_BACKUP_SEMANTICS|
			windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

const windowsFinalPathNameMaxLength = 32768

func inspectWindowsReplacementHandleFinalPath(
	handle windows.Handle,
	description string,
) (string, error) {
	bufferSize := uint32(256)
	for {
		buffer := make([]uint16, bufferSize)
		length, err := getWindowsFinalPathNameByHandle(
			handle,
			&buffer[0],
			bufferSize,
			0,
		)
		if err != nil {
			return "", fmt.Errorf("inspect %s final path: %w", description, err)
		}
		if length == 0 {
			return "", fmt.Errorf("inspect %s final path: empty name", description)
		}
		if length < bufferSize {
			return windows.UTF16ToString(buffer[:length]), nil
		}
		if length > windowsFinalPathNameMaxLength {
			return "", fmt.Errorf("inspect %s final path: name is too long", description)
		}
		bufferSize = length + 1
	}
}

func inspectWindowsReplacementLongPath(
	path,
	description string,
) (string, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("encode %s parent path: %w", description, err)
	}
	bufferSize := uint32(windows.MAX_PATH)
	for {
		buffer := make([]uint16, bufferSize)
		length, err := getWindowsLongPathName(
			pathPointer,
			&buffer[0],
			bufferSize,
		)
		if err != nil {
			return "", fmt.Errorf("canonicalize %s parent path: %w", description, err)
		}
		if length == 0 {
			return "", fmt.Errorf("canonicalize %s parent path: empty name", description)
		}
		if length < bufferSize {
			return windows.UTF16ToString(buffer[:length]), nil
		}
		if length > windowsFinalPathNameMaxLength {
			return "", fmt.Errorf("canonicalize %s parent path: name is too long", description)
		}
		bufferSize = length + 1
	}
}

func normalizeWindowsReplacementPath(path string) (string, error) {
	path = stripWindowsExtendedPathPrefix(path)
	cleaned := filepath.Clean(path)
	absolute, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve Windows path %q: %w", path, err)
	}
	absolute = stripWindowsExtendedPathPrefix(filepath.Clean(absolute))
	return strings.ToLower(absolute), nil
}

func stripWindowsExtendedPathPrefix(path string) string {
	const extendedPrefix = `\\?\`
	if len(path) < len(extendedPrefix) ||
		!strings.EqualFold(path[:len(extendedPrefix)], extendedPrefix) {
		return path
	}
	path = path[len(extendedPrefix):]
	const uncPrefix = `UNC\`
	if len(path) >= len(uncPrefix) &&
		strings.EqualFold(path[:len(uncPrefix)], uncPrefix) {
		return `\\` + path[len(uncPrefix):]
	}
	return path
}

func windowsReplacementLongPathQueryPath(parent, destination string) string {
	const extendedPrefix = `\\?\`
	const extendedUNCPathPrefix = `\\?\UNC\`
	if len(destination) >= len(extendedUNCPathPrefix) &&
		strings.EqualFold(destination[:len(extendedUNCPathPrefix)], extendedUNCPathPrefix) {
		return extendedUNCPathPrefix + strings.TrimPrefix(parent, `\\`)
	}
	if len(destination) >= len(extendedPrefix) &&
		strings.EqualFold(destination[:len(extendedPrefix)], extendedPrefix) {
		return extendedPrefix + parent
	}
	if len(parent) >= windows.MAX_PATH {
		if strings.HasPrefix(parent, `\\`) {
			return extendedUNCPathPrefix + strings.TrimPrefix(parent, `\\`)
		}
		return extendedPrefix + parent
	}
	return parent
}

func canonicalizeWindowsReplacementDestination(
	destination,
	description string,
) (string, error) {
	intended, err := normalizeWindowsReplacementPath(destination)
	if err != nil {
		return "", fmt.Errorf("normalize %s destination: %w", description, err)
	}
	parent := filepath.Dir(intended)
	base := filepath.Base(intended)
	queryParent := windowsReplacementLongPathQueryPath(parent, destination)
	canonicalParent, err := inspectWindowsReplacementLongPath(queryParent, description)
	if err != nil {
		return "", err
	}
	canonicalParent = stripWindowsExtendedPathPrefix(filepath.Clean(canonicalParent))
	if !filepath.IsAbs(canonicalParent) {
		return "", fmt.Errorf("canonicalize %s parent path: result is not absolute", description)
	}
	canonicalParent, err = normalizeWindowsReplacementPath(canonicalParent)
	if err != nil {
		return "", fmt.Errorf("normalize canonical %s parent path: %w", description, err)
	}
	canonicalDestination := filepath.Join(canonicalParent, base)
	return normalizeWindowsReplacementPath(canonicalDestination)
}

func requireWindowsReplacementHandleFinalPath(
	handle windows.Handle,
	destination,
	description string,
) error {
	finalPath, err := inspectWindowsReplacementHandleFinalPath(handle, description)
	if err != nil {
		return err
	}
	actual, err := normalizeWindowsReplacementPath(finalPath)
	if err != nil {
		return fmt.Errorf("normalize %s final path: %w", description, err)
	}
	want, err := normalizeWindowsReplacementPath(destination)
	if err != nil {
		return fmt.Errorf("normalize %s destination: %w", description, err)
	}
	if !strings.EqualFold(actual, want) {
		return fmt.Errorf(
			"%s final path %q does not match intended destination %q",
			description,
			finalPath,
			destination,
		)
	}
	return nil
}

func renameExpectedWindowsReplacementHandle(
	source windows.Handle,
	destination string,
	sourceIdentity windowsFileIdentity,
	replace bool,
	testPhase,
	sourceDescription,
	destinationDescription string,
) error {
	if err := requireWindowsReplacementHandleIdentity(source, sourceIdentity, sourceDescription); err != nil {
		return err
	}
	canonicalDestination, err := canonicalizeWindowsReplacementDestination(
		destination,
		destinationDescription,
	)
	if err != nil {
		return err
	}
	if !replace {
		if err := requireWindowsReplacementPathAbsent(destination, destinationDescription); err != nil {
			return err
		}
	}
	if err := runWindowsReplacementTestHook(testPhase); err != nil {
		return err
	}
	if err := renameWindowsReplacementHandle(source, destination, replace); err != nil {
		return err
	}
	if err := requireWindowsReplacementHandleIdentity(source, sourceIdentity, destinationDescription); err != nil {
		return err
	}
	return requireWindowsReplacementHandleFinalPath(source, canonicalDestination, destinationDescription)
}

func rollbackWindowsReplacement(
	target string,
	security *windowsReplacementSecurityState,
	expectedDigest [sha256.Size]byte,
	expectedSecurity windowsSecurityBinding,
) error {
	if security == nil || security.target == windows.InvalidHandle {
		return fmt.Errorf("Windows rollback image handle is unavailable")
	}
	if err := requireWindowsReplacementHandleIdentity(
		security.target,
		security.targetIdentity,
		"Windows rollback image",
	); err != nil {
		return err
	}
	if err := requireWindowsReplacementHandleDigest(
		security.target,
		expectedDigest,
		"Windows rollback image",
	); err != nil {
		return err
	}
	if err := verifyWindowsRollbackSecurityBinding(
		security.target,
		expectedSecurity,
		"Windows rollback image",
	); err != nil {
		return err
	}
	currentHandle, openErr := openWindowsReplacementFile(target, 0)
	if openErr == nil {
		currentIdentity, inspectErr := inspectWindowsReplacementHandle(
			currentHandle,
			"failed installed Windows executable",
		)
		closeErr := windows.CloseHandle(currentHandle)
		if inspectErr != nil {
			return requireRecovery(inspectErr)
		}
		if closeErr != nil {
			return requireRecovery(fmt.Errorf("close failed installed Windows executable inspection handle: %w", closeErr))
		}
		if currentIdentity == security.targetIdentity {
			return nil
		}
	} else if !isWindowsPathNotFound(openErr) {
		return requireRecovery(openErr)
	}
	if err := security.closeStagedForRollback(); err != nil {
		return requireRecovery(fmt.Errorf("release failed installed Windows executable handles for rollback: %w", err))
	}
	if windowsRollbackAuthenticationTestHook != nil {
		if err := windowsRollbackAuthenticationTestHook(
			windowsReplacementBackup(target),
			security,
		); err != nil {
			return requireRecovery(fmt.Errorf("continue before restoring Windows executable: %w", err))
		}
	}
	if err := renameWindowsReplacementHandle(security.target, target, true); err != nil {
		return requireRecovery(err)
	}
	if err := requireWindowsReplacementHandleIdentity(
		security.target,
		security.targetIdentity,
		"restored Windows executable",
	); err != nil {
		return requireRecovery(err)
	}
	if err := requireWindowsReplacementPathIdentity(
		target,
		security.targetIdentity,
		"restored Windows executable",
	); err != nil {
		return requireRecovery(err)
	}
	if err := verifyWindowsRollbackSecurityBinding(
		security.target,
		expectedSecurity,
		"restored Windows executable",
	); err != nil {
		return retainWindowsRollbackAuthenticationEvidence(target, security, err)
	}
	if err := requireWindowsReplacementHandleDigest(
		security.target,
		expectedDigest,
		"restored Windows executable",
	); err != nil {
		return retainWindowsRollbackAuthenticationEvidence(target, security, err)
	}
	return nil
}

func retainWindowsRollbackAuthenticationEvidence(
	target string,
	security *windowsReplacementSecurityState,
	authenticationErr error,
) error {
	backup := windowsReplacementBackup(target)
	if err := requireWindowsReplacementPathAbsent(
		backup,
		"retained Windows rollback image",
	); err != nil {
		return blockOnRecoveryEvidence(errors.Join(
			authenticationErr,
			fmt.Errorf("retain unauthenticated Windows rollback evidence: %w", err),
		))
	}
	if err := renameWindowsReplacementHandle(security.target, backup, false); err != nil {
		return blockOnRecoveryEvidence(errors.Join(
			authenticationErr,
			fmt.Errorf("retain unauthenticated Windows rollback evidence: %w", err),
		))
	}
	if err := requireWindowsReplacementHandleIdentity(
		security.target,
		security.targetIdentity,
		"retained Windows rollback image",
	); err != nil {
		return blockOnRecoveryEvidence(errors.Join(authenticationErr, err))
	}
	if err := requireWindowsReplacementPathIdentity(
		backup,
		security.targetIdentity,
		"retained Windows rollback image",
	); err != nil {
		return blockOnRecoveryEvidence(errors.Join(authenticationErr, err))
	}
	return blockOnRecoveryEvidence(authenticationErr)
}

func verifyWindowsRollbackSecurityBinding(
	handle windows.Handle,
	binding windowsSecurityBinding,
	description string,
) (resultErr error) {
	verifier, err := newWindowsSecurityBindingVerifier(binding)
	if err != nil {
		return fmt.Errorf("prepare %s security descriptor verification: %w", description, err)
	}
	defer func() {
		if closeErr := verifier.close(); closeErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("release %s security descriptor verification: %w", description, closeErr),
			)
		}
	}()
	return verifier.verify(handle, description)
}

type windowsFileRenameInfo struct {
	flags          uint32
	rootDirectory  windows.Handle
	fileNameLength uint32
	fileName       [1]uint16
}

func renameWindowsFileHandle(handle windows.Handle, destination string, replace bool) error {
	name, err := windows.UTF16FromString(destination)
	if err != nil {
		return err
	}
	name = name[:len(name)-1]
	var layout windowsFileRenameInfo
	bufferSize := windowsVariableLengthFileInformationSize(
		int(unsafe.Sizeof(layout)),
		len(name)*2,
	)
	buffer := make([]byte, bufferSize)
	info := (*windowsFileRenameInfo)(unsafe.Pointer(&buffer[0]))
	if replace {
		info.flags = windows.FILE_RENAME_REPLACE_IF_EXISTS |
			windows.FILE_RENAME_POSIX_SEMANTICS |
			windows.FILE_RENAME_IGNORE_READONLY_ATTRIBUTE
	}
	info.fileNameLength = uint32(len(name) * 2)
	copy(
		unsafe.Slice(&info.fileName[0], len(name)),
		name,
	)
	return windows.SetFileInformationByHandle(
		handle,
		windows.FileRenameInfoEx,
		&buffer[0],
		uint32(len(buffer)),
	)
}

type windowsFileLinkInfo struct {
	flags          uint32
	rootDirectory  windows.Handle
	fileNameLength uint32
	fileName       [1]uint16
}

func linkWindowsFileHandle(handle windows.Handle, destination string) error {
	return linkWindowsFileHandleWithFlags(
		handle,
		destination,
		windows.FILE_LINK_REPLACE_IF_EXISTS|windows.FILE_LINK_POSIX_SEMANTICS,
	)
}

func linkWindowsFileHandleExclusive(handle windows.Handle, destination string) error {
	return linkWindowsFileHandleWithFlags(handle, destination, 0)
}

func linkWindowsFileHandleWithFlags(
	handle windows.Handle,
	destination string,
	flags uint32,
) error {
	// A nil RootDirectory makes this single-component name relative to the
	// held source link. Recovery uses only sibling names, so no pathname lookup
	// can substitute the held source object.
	name, err := windows.UTF16FromString(filepath.Base(destination))
	if err != nil {
		return err
	}
	name = name[:len(name)-1]
	var layout windowsFileLinkInfo
	headerSize := int(unsafe.Offsetof(layout.fileName))
	bufferSize := headerSize + len(name)*2
	if minimum := int(unsafe.Sizeof(layout)); bufferSize < minimum {
		bufferSize = minimum
	}
	buffer := make([]byte, bufferSize)
	info := (*windowsFileLinkInfo)(unsafe.Pointer(&buffer[0]))
	info.flags = flags
	info.fileNameLength = uint32(len(name) * 2)
	copy(
		unsafe.Slice(&info.fileName[0], len(name)),
		name,
	)
	var status windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(
		handle,
		&status,
		&buffer[0],
		uint32(len(buffer)),
		windows.FileLinkInformation,
	)
}

func restoreMappedWindowsReplacement(
	target string,
	targetHandle,
	backupHandle windows.Handle,
	targetIdentity windowsFileIdentity,
	targetLinks uint32,
) (cleanupDeferred bool, resultErr error) {
	targetOpen := true
	defer func() {
		if targetOpen {
			if closeErr := windows.CloseHandle(targetHandle); closeErr != nil {
				resultErr = errors.Join(
					resultErr,
					fmt.Errorf("close canonical Windows executable recovery guard: %w", closeErr),
				)
			}
		}
	}()

	mappedLink := windowsReplacementMappedLink(target)
	switch targetLinks {
	case 1:
		if err := requireWindowsReplacementPathAbsent(
			mappedLink,
			"mapped Windows executable recovery link",
		); err != nil {
			return false, err
		}
	case 2:
		if err := requireWindowsReplacementPathObjectIdentity(
			mappedLink,
			targetIdentity,
			2,
			"mapped Windows executable recovery link",
		); err != nil {
			return false, fmt.Errorf("resume mapped Windows executable recovery link: %w", err)
		}
		mappedHandle, err := openWindowsReplacementDeleteGuard(mappedLink)
		if err != nil {
			return false, fmt.Errorf("open mapped Windows executable recovery link: %w", err)
		}
		mappedOpen := true
		defer func() {
			if mappedOpen {
				if closeErr := windows.CloseHandle(mappedHandle); closeErr != nil {
					resultErr = errors.Join(
						resultErr,
						fmt.Errorf("close mapped Windows executable recovery link: %w", closeErr),
					)
				}
			}
		}()
		if err := requireWindowsReplacementHandleObjectIdentity(
			mappedHandle,
			targetIdentity,
			2,
			"mapped Windows executable recovery link",
		); err != nil {
			return false, err
		}
		// c1689fe could leave this exact two-link state. Disposition of
		// the reserved link succeeds, but immediately makes the canonical
		// name the sole live link. Close and remove only the reserved link;
		// the remaining mapped name must be renamed, not deleted.
		if err := unlinkWindowsMappedReplacementHandle(mappedHandle); err != nil {
			return false, fmt.Errorf("remove interrupted mapped Windows executable recovery link: %w", err)
		}
		if err := windows.CloseHandle(mappedHandle); err != nil {
			return false, fmt.Errorf("close removed mapped Windows executable recovery link: %w", err)
		}
		mappedOpen = false
		if err := requireWindowsReplacementPathAbsent(
			mappedLink,
			"removed mapped Windows executable recovery link",
		); err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("canonical Windows executable awaiting recovery has %d hard links", targetLinks)
	}
	if err := requireWindowsReplacementHandleObjectIdentity(
		targetHandle,
		targetIdentity,
		1,
		"guarded mapped Windows executable",
	); err != nil {
		return false, err
	}
	if err := requireWindowsReplacementPathObjectIdentity(
		target,
		targetIdentity,
		1,
		"canonical mapped Windows executable",
	); err != nil {
		return false, err
	}
	if err := renameWindowsReplacementHandle(targetHandle, mappedLink, false); err != nil {
		return false, fmt.Errorf("preserve displaced mapped Windows executable: %w", err)
	}
	if err := requireWindowsReplacementHandleObjectIdentity(
		targetHandle,
		targetIdentity,
		1,
		"displaced mapped Windows executable",
	); err != nil {
		return false, err
	}
	if err := requireWindowsReplacementPathObjectIdentity(
		mappedLink,
		targetIdentity,
		1,
		"displaced mapped Windows executable",
	); err != nil {
		return false, err
	}
	if err := requireWindowsReplacementPathAbsent(
		target,
		"vacated mapped canonical Windows executable",
	); err != nil {
		return false, err
	}
	if err := renameWindowsReplacementHandle(backupHandle, target, true); err != nil {
		return false, fmt.Errorf("restore Windows rollback image: %w", err)
	}
	if err := windows.CloseHandle(targetHandle); err != nil {
		return false, fmt.Errorf("close displaced mapped Windows executable: %w", err)
	}
	targetOpen = false
	return true, nil
}

func cleanupDisplacedMappedWindowsReplacement(
	target string,
	expectedIdentity windowsFileIdentity,
) (resultErr error) {
	mappedLink := windowsReplacementMappedLink(target)
	mappedHandle, err := openWindowsProtectedReplacementFile(mappedLink, windows.DELETE)
	if err != nil && isWindowsPathNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open displaced mapped Windows executable: %w", err)
	}
	mappedOpen := true
	defer func() {
		if mappedOpen {
			if closeErr := windows.CloseHandle(mappedHandle); closeErr != nil {
				resultErr = errors.Join(
					resultErr,
					fmt.Errorf("close displaced mapped Windows executable: %w", closeErr),
				)
			}
		}
	}()
	if err := requireWindowsReplacementHandleObjectIdentity(
		mappedHandle,
		expectedIdentity,
		1,
		"displaced mapped Windows executable",
	); err != nil {
		return err
	}
	if err := unlinkWindowsMappedReplacementHandle(mappedHandle); err != nil {
		return fmt.Errorf("remove displaced mapped Windows executable: %w", err)
	}
	if err := windows.CloseHandle(mappedHandle); err != nil {
		return fmt.Errorf("close removed displaced mapped Windows executable: %w", err)
	}
	mappedOpen = false
	return requireWindowsReplacementPathAbsent(
		mappedLink,
		"removed displaced mapped Windows executable",
	)
}

func unlinkWindowsMappedFileHandle(handle windows.Handle) error {
	// FileLinkInformationEx replacement still performs an image-section check
	// on the target. FileDispositionInfoEx without FORCE_IMAGE_SECTION_CHECK can
	// remove one held link while another link preserves the mapped image.
	flags := uint32(
		windows.FILE_DISPOSITION_DELETE |
			windows.FILE_DISPOSITION_POSIX_SEMANTICS,
	)
	return windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfoEx,
		(*byte)(unsafe.Pointer(&flags)),
		uint32(unsafe.Sizeof(flags)),
	)
}

type windowsReplacementLockState struct {
	handle     windows.Handle
	overlapped windows.Overlapped
	locked     bool
	policy     *windowsControlSecurityPolicy
}

func acquireWindowsReplacementLock(target string) (*windowsReplacementLockState, error) {
	policy, err := newWindowsControlSecurityPolicy()
	if err != nil {
		return nil, fmt.Errorf("prepare Windows executable update lock security policy: %w", err)
	}
	path := windowsReplacementLock(target)
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		policy.attributes(),
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, fmt.Errorf("another Windows executable update is active: %w", err)
		}
		return nil, fmt.Errorf("open Windows executable update lock: %w", err)
	}
	state := &windowsReplacementLockState{handle: handle, policy: policy}
	if _, err := inspectWindowsReplacementHandle(handle, "Windows executable update lock"); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if err := policy.validate(handle, "Windows executable update lock"); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if err := windows.LockFileEx(
		handle,
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&state.overlapped,
	); err != nil {
		_ = windows.CloseHandle(handle)
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
			errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, fmt.Errorf("another Windows executable update is active: %w", err)
		}
		return nil, fmt.Errorf("lock Windows executable update: %w", err)
	}
	state.locked = true
	return state, nil
}

func (state *windowsReplacementLockState) close() error {
	if state == nil || state.handle == windows.InvalidHandle {
		return nil
	}
	var errs []error
	if state.locked {
		errs = append(errs, windows.UnlockFileEx(state.handle, 0, 1, 0, &state.overlapped))
		state.locked = false
	}
	errs = append(errs, windows.CloseHandle(state.handle))
	state.handle = windows.InvalidHandle
	return errors.Join(errs...)
}

const (
	windowsReplacementRecordSize      = 136
	windowsReplacementRecordVersion   = uint32(3)
	windowsReplacementRecordPrepared  = uint32(1)
	windowsReplacementRecordCompleted = uint32(2)
)

// Version 3 is a fixed, bounded record:
// magic/version/state | original strong ID | installed strong ID |
// descriptor metadata | SHA-256 semantic descriptor binding |
// SHA-256 rollback executable digest | CRC32. The validated owner-only,
// protected state-file DACL authenticates the record; CRC32 only detects
// accidental corruption or torn writes.
var windowsReplacementRecordMagic = [8]byte{'S', 'S', 'M', 'O', 'L', 'D', '3', 0}

type windowsReplacementRecordData struct {
	state           uint32
	original        windowsFileIdentity
	installed       windowsFileIdentity
	rollbackDigest  [sha256.Size]byte
	securityBinding windowsSecurityBinding
}

type windowsReplacementRecordState struct {
	handle        windows.Handle
	deletePending bool
	data          windowsReplacementRecordData
}

func createWindowsReplacementRecord(
	target string,
	original,
	installed windowsFileIdentity,
	rollbackDigest [sha256.Size]byte,
	securityBinding windowsSecurityBinding,
	policy *windowsControlSecurityPolicy,
) (*windowsReplacementRecordState, error) {
	if err := validateWindowsSecurityBinding(securityBinding); err != nil {
		return nil, fmt.Errorf("validate Windows security descriptor binding: %w", err)
	}
	path := windowsReplacementRecord(target)
	if err := requireWindowsReplacementPathAbsent(path, "Windows rollback ownership record"); err != nil {
		return nil, err
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE,
		windows.FILE_SHARE_READ,
		policy.attributes(),
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	state := &windowsReplacementRecordState{
		handle: handle,
		data: windowsReplacementRecordData{
			state:           windowsReplacementRecordPrepared,
			original:        original,
			installed:       installed,
			rollbackDigest:  rollbackDigest,
			securityBinding: securityBinding,
		},
	}
	_, err = inspectWindowsReplacementHandle(
		handle,
		"Windows rollback ownership record",
	)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if err := policy.validate(handle, "Windows rollback ownership record"); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if err := state.write(); err != nil {
		if removeErr := state.remove(); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("remove failed Windows rollback ownership record: %w", removeErr))
		}
		if closeErr := state.close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close removed Windows rollback ownership record: %w", closeErr))
		}
		return nil, err
	}
	return state, nil
}

func (state *windowsReplacementRecordState) markCompleted() error {
	state.data.state = windowsReplacementRecordCompleted
	return state.write()
}

func (state *windowsReplacementRecordState) write() error {
	data := encodeWindowsReplacementRecord(state.data)
	if _, err := windows.SetFilePointer(state.handle, 0, nil, windows.FILE_BEGIN); err != nil {
		return err
	}
	var written uint32
	if err := windows.WriteFile(state.handle, data, &written, nil); err != nil {
		return err
	}
	if written != uint32(len(data)) {
		return fmt.Errorf("short Windows rollback ownership write: %d of %d", written, len(data))
	}
	if err := windows.SetEndOfFile(state.handle); err != nil {
		return err
	}
	return windows.FlushFileBuffers(state.handle)
}

func (state *windowsReplacementRecordState) remove() error {
	if state == nil || state.handle == windows.InvalidHandle {
		return fmt.Errorf("Windows rollback ownership record handle is unavailable")
	}
	if state.deletePending {
		return nil
	}
	deleteFile := byte(1)
	if err := windows.SetFileInformationByHandle(
		state.handle,
		windows.FileDispositionInfo,
		&deleteFile,
		uint32(unsafe.Sizeof(deleteFile)),
	); err != nil {
		return err
	}
	state.deletePending = true
	return nil
}

func (state *windowsReplacementRecordState) close() error {
	if state == nil || state.handle == windows.InvalidHandle {
		return nil
	}
	err := windows.CloseHandle(state.handle)
	state.handle = windows.InvalidHandle
	return err
}

func encodeWindowsReplacementRecord(record windowsReplacementRecordData) []byte {
	data := make([]byte, windowsReplacementRecordSize)
	copy(data[:8], windowsReplacementRecordMagic[:])
	binary.LittleEndian.PutUint32(data[8:12], windowsReplacementRecordVersion)
	binary.LittleEndian.PutUint32(data[12:16], record.state)
	putWindowsFileIdentity(data[16:40], record.original)
	putWindowsFileIdentity(data[40:64], record.installed)
	binary.LittleEndian.PutUint32(data[64:68], record.securityBinding.metadata)
	copy(data[68:100], record.securityBinding.digest[:])
	copy(data[100:132], record.rollbackDigest[:])
	binary.LittleEndian.PutUint32(data[132:136], crc32.ChecksumIEEE(data[:132]))
	return data
}

func decodeWindowsReplacementRecord(data []byte) (windowsReplacementRecordData, error) {
	if len(data) != windowsReplacementRecordSize {
		if len(data) >= 12 {
			version := binary.LittleEndian.Uint32(data[8:12])
			if version < windowsReplacementRecordVersion {
				return windowsReplacementRecordData{}, fmt.Errorf(
					"legacy Windows rollback ownership record version %d has no strong identity or executable digest",
					version,
				)
			}
		}
		return windowsReplacementRecordData{}, fmt.Errorf(
			"Windows rollback ownership record size is %d, want %d",
			len(data),
			windowsReplacementRecordSize,
		)
	}
	if string(data[:8]) != string(windowsReplacementRecordMagic[:]) {
		return windowsReplacementRecordData{}, fmt.Errorf("Windows rollback ownership record magic is invalid")
	}
	if version := binary.LittleEndian.Uint32(data[8:12]); version != windowsReplacementRecordVersion {
		return windowsReplacementRecordData{}, fmt.Errorf(
			"Windows rollback ownership record version is %d, want %d",
			version,
			windowsReplacementRecordVersion,
		)
	}
	if got, want := binary.LittleEndian.Uint32(data[132:136]), crc32.ChecksumIEEE(data[:132]); got != want {
		return windowsReplacementRecordData{}, fmt.Errorf("Windows rollback ownership record checksum is invalid")
	}
	state := binary.LittleEndian.Uint32(data[12:16])
	if state != windowsReplacementRecordPrepared && state != windowsReplacementRecordCompleted {
		return windowsReplacementRecordData{}, fmt.Errorf(
			"Windows rollback ownership record state %d is invalid",
			state,
		)
	}
	record := windowsReplacementRecordData{
		state:     state,
		original:  getWindowsFileIdentity(data[16:40]),
		installed: getWindowsFileIdentity(data[40:64]),
		securityBinding: windowsSecurityBinding{
			metadata: binary.LittleEndian.Uint32(data[64:68]),
		},
	}
	copy(record.securityBinding.digest[:], data[68:100])
	copy(record.rollbackDigest[:], data[100:132])
	if err := validateWindowsSecurityBinding(record.securityBinding); err != nil {
		return windowsReplacementRecordData{}, fmt.Errorf(
			"Windows rollback ownership record security descriptor binding is invalid: %w",
			err,
		)
	}
	return record, nil
}

func putWindowsFileIdentity(data []byte, identity windowsFileIdentity) {
	binary.LittleEndian.PutUint64(data[0:8], identity.volumeSerialNumber)
	copy(data[8:24], identity.fileID[:])
}

func getWindowsFileIdentity(data []byte) windowsFileIdentity {
	return windowsFileIdentity{
		volumeSerialNumber: binary.LittleEndian.Uint64(data[0:8]),
		fileID:             [16]byte(data[8:24]),
	}
}

func openWindowsReplacementRecord(
	target string,
	policy *windowsControlSecurityPolicy,
) (*windowsReplacementRecordState, error) {
	path := windowsReplacementRecord(target)
	handle, err := openWindowsReplacementFileWithShare(
		path,
		windows.GENERIC_READ|windows.DELETE,
		windows.FILE_SHARE_READ,
	)
	if err != nil {
		return nil, err
	}
	state := &windowsReplacementRecordState{handle: handle}
	if _, err := inspectWindowsReplacementHandle(
		handle,
		"Windows rollback ownership record",
	); err != nil {
		_ = state.close()
		return nil, err
	}
	if err := policy.validate(handle, "Windows rollback ownership record"); err != nil {
		_ = state.close()
		return nil, err
	}
	data := make([]byte, windowsReplacementRecordSize+1)
	var read uint32
	if err := windows.ReadFile(handle, data, &read, nil); err != nil {
		_ = state.close()
		return nil, err
	}
	state.data, err = decodeWindowsReplacementRecord(data[:read])
	if err != nil {
		_ = state.close()
		return nil, err
	}
	return state, nil
}

func cleanupPreviousExecutable(target string) (resultErr error) {
	defer func() {
		resultErr = blockOnRecoveryEvidence(resultErr)
	}()
	recoveryRequired, err := windowsReplacementRecoveryRequired(target)
	if err != nil {
		return err
	}
	if !recoveryRequired {
		return nil
	}
	updateLock, err := acquireWindowsReplacementLock(target)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := updateLock.close(); closeErr != nil && resultErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("release Windows executable update lock: %w", closeErr),
			)
		}
	}()
	return cleanupCompletedWindowsRollbackUnderLockWithPolicy(target, updateLock.policy)
}

func windowsReplacementRecoveryRequired(target string) (bool, error) {
	for _, evidence := range []struct {
		path        string
		description string
	}{
		{
			path:        windowsReplacementRecord(target),
			description: "Windows rollback ownership record",
		},
		{
			path:        windowsReplacementBackup(target),
			description: "Windows rollback image",
		},
	} {
		_, exists, err := inspectOptionalWindowsReplacementPath(
			evidence.path,
			evidence.description,
		)
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

func cleanupCompletedWindowsRollbackUnderLock(target string) error {
	policy, err := newWindowsControlSecurityPolicy()
	if err != nil {
		return err
	}
	return cleanupCompletedWindowsRollbackUnderLockWithPolicy(target, policy)
}

func cleanupCompletedWindowsRollbackUnderLockWithPolicy(
	target string,
	policy *windowsControlSecurityPolicy,
) (resultErr error) {
	backup := windowsReplacementBackup(target)
	recordPath := windowsReplacementRecord(target)
	_, recordExists, err := inspectOptionalWindowsReplacementPath(
		recordPath,
		"Windows rollback ownership record",
	)
	if err != nil {
		return err
	}
	if !recordExists {
		_, backupExists, backupErr := inspectOptionalWindowsReplacementPath(
			backup,
			"Windows rollback image",
		)
		if backupErr != nil {
			return backupErr
		}
		if backupExists {
			return fmt.Errorf("Windows rollback evidence has no ownership record")
		}
		return nil
	}

	record, err := openWindowsReplacementRecord(target, policy)
	if err != nil {
		return fmt.Errorf("read Windows rollback ownership record: %w", err)
	}
	defer func() {
		if closeErr := record.close(); closeErr != nil && resultErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("close Windows rollback ownership record: %w", closeErr),
			)
		}
	}()
	if record.data.state != windowsReplacementRecordCompleted {
		if err := recoverPreparedWindowsReplacement(target, backup, record); err != nil {
			return fmt.Errorf("recover incomplete Windows executable replacement: %w", err)
		}
		return nil
	}
	targetHandle, err := openWindowsProtectedReplacementFile(target, 0)
	if err != nil {
		if isWindowsPathNotFound(err) {
			return fmt.Errorf("completed Windows rollback record has no installed executable")
		}
		return err
	}
	defer func() {
		if targetHandle != windows.InvalidHandle {
			if closeErr := windows.CloseHandle(targetHandle); closeErr != nil && resultErr != nil {
				resultErr = errors.Join(
					resultErr,
					fmt.Errorf("close installed Windows executable: %w", closeErr),
				)
			}
		}
	}()
	targetIdentity, err := inspectWindowsReplacementHandle(
		targetHandle,
		"installed Windows executable",
	)
	if err != nil {
		return err
	}
	if targetIdentity != record.data.installed {
		return fmt.Errorf("completed Windows rollback record does not match the installed executable")
	}
	backupHandle, err := openWindowsReplacementFileWithShare(
		backup,
		windows.DELETE|windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
	)
	if err != nil && isWindowsPathNotFound(err) {
		if err := record.remove(); err != nil {
			return nil
		}
		return nil
	}
	if err != nil {
		return err
	}
	backupOpen := true
	defer func() {
		if backupOpen {
			if closeErr := windows.CloseHandle(backupHandle); closeErr != nil && resultErr != nil {
				resultErr = errors.Join(
					resultErr,
					fmt.Errorf("close Windows rollback image: %w", closeErr),
				)
			}
		}
	}()
	backupIdentity, err := inspectWindowsReplacementHandle(
		backupHandle,
		"Windows rollback image",
	)
	if err != nil {
		return err
	}
	if backupIdentity != record.data.original {
		return fmt.Errorf("completed Windows rollback record does not match the rollback image")
	}
	if err := requireWindowsReplacementHandleDigest(
		backupHandle,
		record.data.rollbackDigest,
		"Windows rollback image",
	); err != nil {
		return err
	}
	// From here the completed record, canonical executable, and rollback image
	// are authenticated. Cleanup failures retain that evidence for a later
	// launch and must not turn the already-committed update into update_failed.
	if err := deleteWindowsReplacementHandle(backupHandle); err != nil {
		return nil
	}
	if err := windows.CloseHandle(backupHandle); err != nil {
		return nil
	}
	backupOpen = false
	if err := record.remove(); err != nil {
		return nil
	}
	return nil
}

func recoverPreparedWindowsReplacement(
	target,
	backup string,
	record *windowsReplacementRecordState,
) (resultErr error) {
	mappedCleanupDeferred := false
	verifier, err := newWindowsSecurityBindingVerifier(record.data.securityBinding)
	if err != nil {
		return fmt.Errorf("prepare Windows rollback security descriptor verification: %w", err)
	}
	defer func() {
		if closeErr := verifier.close(); closeErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("release Windows rollback security descriptor verification: %w", closeErr),
			)
		}
	}()
	backupHandle, err := openWindowsProtectedReplacementFile(
		backup,
		windows.DELETE|windows.GENERIC_READ|verifier.access,
	)
	if err != nil && isWindowsPathNotFound(err) {
		return completePreparedWindowsRecoveryAtCanonical(target, record, verifier)
	}
	if err != nil {
		return fmt.Errorf("open Windows rollback image for recovery: %w", err)
	}
	defer func() {
		if backupHandle != windows.InvalidHandle {
			if closeErr := windows.CloseHandle(backupHandle); closeErr != nil {
				resultErr = errors.Join(
					resultErr,
					fmt.Errorf("close Windows rollback recovery image: %w", closeErr),
				)
			}
		}
	}()
	backupIdentity, backupLinks, err := inspectWindowsReplacementHandleObject(
		backupHandle,
		"Windows rollback recovery image",
	)
	if err != nil {
		return err
	}
	if backupIdentity != record.data.original {
		return fmt.Errorf("prepared Windows rollback record does not match the rollback image")
	}
	if backupLinks != 1 && backupLinks != 2 {
		return fmt.Errorf("Windows rollback recovery image has %d hard links", backupLinks)
	}
	if err := requireWindowsReplacementHandleDigest(
		backupHandle,
		record.data.rollbackDigest,
		"Windows rollback recovery image",
	); err != nil {
		return err
	}
	if err := verifier.verify(backupHandle, "Windows rollback recovery image"); err != nil {
		return err
	}
	completeLinkedRecovery := func() error {
		if err := unlinkWindowsMappedReplacementHandle(backupHandle); err != nil {
			return preserveCanonical(fmt.Errorf("remove linked Windows rollback image: %w", err))
		}
		if err := windows.CloseHandle(backupHandle); err != nil {
			return preserveCanonical(fmt.Errorf("close linked Windows rollback image: %w", err))
		}
		backupHandle = windows.InvalidHandle
		return completePreparedWindowsRecoveryAtCanonical(target, record, verifier)
	}
	if backupLinks == 2 {
		if err := requireWindowsReplacementPathObjectIdentity(
			target,
			record.data.original,
			2,
			"linked recovered Windows executable",
		); err != nil {
			if isWindowsPathNotFound(err) {
				return fmt.Errorf("Windows rollback recovery image has 2 hard links")
			}
			return err
		}
		return completeLinkedRecovery()
	}
	targetHandle, err := openWindowsReplacementDeleteGuard(target)
	if err != nil && isWindowsPathNotFound(err) {
		if err := renameWindowsReplacementHandle(backupHandle, target, true); err != nil {
			return requireRecovery(fmt.Errorf("restore Windows rollback image: %w", err))
		}
	} else {
		if err != nil {
			return requireRecovery(fmt.Errorf("restore Windows rollback image: %w", err))
		}
		targetIdentity, targetLinks, inspectErr := inspectWindowsReplacementHandleObject(
			targetHandle,
			"canonical Windows executable awaiting recovery",
		)
		if inspectErr != nil {
			_ = windows.CloseHandle(targetHandle)
			return requireRecovery(inspectErr)
		}
		mappedTarget, inspectErr := windowsReplacementHandleIsCurrentImage(targetHandle)
		if inspectErr != nil {
			_ = windows.CloseHandle(targetHandle)
			return requireRecovery(inspectErr)
		}
		if mappedTarget {
			mappedCleanupDeferred, err = restoreMappedWindowsReplacement(
				target,
				targetHandle,
				backupHandle,
				targetIdentity,
				targetLinks,
			)
			if err != nil {
				return requireRecovery(err)
			}
		} else {
			if targetLinks != 1 {
				_ = windows.CloseHandle(targetHandle)
				return requireRecovery(fmt.Errorf(
					"canonical Windows executable awaiting recovery has %d hard links",
					targetLinks,
				))
			}
			linkErr := linkWindowsReplacementHandle(backupHandle, target)
			closeErr := windows.CloseHandle(targetHandle)
			if linkErr != nil {
				if closeErr != nil {
					linkErr = errors.Join(
						linkErr,
						fmt.Errorf("close canonical Windows executable recovery guard: %w", closeErr),
					)
				}
				return requireRecovery(fmt.Errorf("restore Windows rollback image: %w", linkErr))
			}
			if closeErr != nil {
				return requireRecovery(fmt.Errorf("close replaced canonical Windows executable: %w", closeErr))
			}
			if err := requireWindowsReplacementHandleObjectIdentity(
				backupHandle,
				record.data.original,
				2,
				"linked recovered Windows executable",
			); err != nil {
				return requireRecovery(err)
			}
			if err := requireWindowsReplacementPathObjectIdentity(
				target,
				record.data.original,
				2,
				"linked recovered Windows executable",
			); err != nil {
				return requireRecovery(err)
			}
			return completeLinkedRecovery()
		}
	}
	if err := requireWindowsReplacementHandleIdentity(
		backupHandle,
		record.data.original,
		"recovered Windows executable",
	); err != nil {
		return requireRecovery(err)
	}
	if err := requireWindowsReplacementPathIdentity(
		target,
		record.data.original,
		"recovered Windows executable",
	); err != nil {
		return requireRecovery(err)
	}
	if err := verifier.verify(backupHandle, "recovered Windows executable"); err != nil {
		return requireRecovery(err)
	}
	if err := requireWindowsReplacementHandleDigest(
		backupHandle,
		record.data.rollbackDigest,
		"recovered Windows executable",
	); err != nil {
		return requireRecovery(err)
	}
	if mappedCleanupDeferred {
		// The authenticated original is canonical again, but this process is
		// still mapped from the displaced installed image. Retain the existing
		// prepared record so the next launch can authenticate and remove that
		// reserved image after this mapping is gone. Until then, the prepared
		// record is still live recovery state and startup must not dispatch.
		return requireRecovery(fmt.Errorf(
			"deferred mapped Windows executable cleanup remains pending",
		))
	}
	if err := cleanupDisplacedMappedWindowsReplacement(
		target,
		record.data.installed,
	); err != nil {
		return preserveCanonical(err)
	}
	if err := verifier.close(); err != nil {
		return preserveCanonical(fmt.Errorf("release Windows rollback security descriptor verification: %w", err))
	}
	if err := record.remove(); err != nil {
		return preserveCanonical(fmt.Errorf("remove recovered Windows rollback ownership record: %w", err))
	}
	if err := record.close(); err != nil {
		return preserveCanonical(fmt.Errorf("close recovered Windows rollback ownership record: %w", err))
	}
	return nil
}

func completePreparedWindowsRecoveryAtCanonical(
	target string,
	record *windowsReplacementRecordState,
	verifier *windowsSecurityBindingVerifier,
) (resultErr error) {
	targetHandle, err := openWindowsProtectedReplacementFile(
		target,
		windows.GENERIC_READ|verifier.access,
	)
	if err != nil {
		if isWindowsPathNotFound(err) {
			return fmt.Errorf("prepared Windows rollback record has no original executable")
		}
		return fmt.Errorf("open recovered Windows executable: %w", err)
	}
	defer func() {
		if targetHandle != windows.InvalidHandle {
			if closeErr := windows.CloseHandle(targetHandle); closeErr != nil {
				resultErr = errors.Join(
					resultErr,
					fmt.Errorf("close recovered Windows executable: %w", closeErr),
				)
			}
		}
	}()
	targetIdentity, err := inspectWindowsReplacementHandle(
		targetHandle,
		"recovered Windows executable",
	)
	if err != nil {
		return err
	}
	if targetIdentity != record.data.original {
		return fmt.Errorf("prepared Windows rollback record has no matching rollback image")
	}
	if err := requireWindowsReplacementHandleDigest(
		targetHandle,
		record.data.rollbackDigest,
		"recovered Windows executable",
	); err != nil {
		return err
	}
	if err := verifier.verify(targetHandle, "recovered Windows executable"); err != nil {
		return err
	}
	if err := cleanupDisplacedMappedWindowsReplacement(
		target,
		record.data.installed,
	); err != nil {
		return preserveCanonical(err)
	}
	if err := verifier.close(); err != nil {
		return preserveCanonical(fmt.Errorf("release Windows rollback security descriptor verification: %w", err))
	}
	if err := record.remove(); err != nil {
		return preserveCanonical(fmt.Errorf("remove recovered Windows rollback ownership record: %w", err))
	}
	if err := record.close(); err != nil {
		return preserveCanonical(fmt.Errorf("close recovered Windows rollback ownership record: %w", err))
	}
	return nil
}

func deleteWindowsReplacementHandle(handle windows.Handle) error {
	deleteFile := byte(1)
	return windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfo,
		&deleteFile,
		uint32(unsafe.Sizeof(deleteFile)),
	)
}

func windowsReplacementBackup(target string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".old")
}

func windowsReplacementRecord(target string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".old.state")
}

func windowsReplacementMappedLink(target string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".mapped")
}

func windowsReplacementLock(target string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".update.lock")
}
