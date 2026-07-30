//go:build windows

package update

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
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
)

var (
	renameWindowsReplacementHandle = renameWindowsFileHandle
	windowsReplacementTestHook     func(string) error
)

func replaceExecutable(staged, target string) (resultErr error) {
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
		if closeErr := updateLock.close(); closeErr != nil {
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
		return fmt.Errorf("clean previous Windows executable: %w", err)
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

	if err := runWindowsReplacementTestHook(windowsReplacementPhaseBeforeTargetMove); err != nil {
		return failBeforeRecord("continue before preserving Windows executable", err)
	}

	record, err := createWindowsReplacementRecord(
		target,
		targetIdentity,
		stageIdentity,
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
		rollbackErr := rollbackWindowsReplacement(target, security)
		if rollbackErr == nil {
			if removeErr := record.remove(); removeErr != nil {
				rollbackErr = fmt.Errorf("remove Windows rollback ownership record: %w", removeErr)
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
			return fmt.Errorf("%s: %w (rollback failed: %v)", operation, operationErr, rollbackErr)
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
	if err := record.markCompleted(); err != nil {
		return failAfterBackup("mark Windows replacement complete", err)
	}
	if err := record.close(); err != nil {
		return failAfterBackup("close completed Windows rollback ownership record", err)
	}
	if err := closeSecurity(); err != nil {
		return fmt.Errorf("release Windows security state after installing executable: %w", err)
	}
	return nil
}

func runWindowsReplacementTestHook(phase string) error {
	if windowsReplacementTestHook == nil {
		return nil
	}
	return windowsReplacementTestHook(phase)
}

type windowsFileIdentity struct {
	volumeSerialNumber uint32
	fileIndexHigh      uint32
	fileIndexLow       uint32
}

func inspectWindowsReplacementPath(path, description string) (windowsFileIdentity, error) {
	handle, err := openWindowsReplacementFile(path, 0)
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
	return windowsFileIdentity{
		volumeSerialNumber: info.VolumeSerialNumber,
		fileIndexHigh:      info.FileIndexHigh,
		fileIndexLow:       info.FileIndexLow,
	}, info.NumberOfLinks, nil
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
	return requireWindowsReplacementPathIdentity(
		destination,
		sourceIdentity,
		destinationDescription,
	)
}

func rollbackWindowsReplacement(
	target string,
	security *windowsReplacementSecurityState,
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
	currentHandle, openErr := openWindowsReplacementFile(target, 0)
	if openErr == nil {
		currentIdentity, inspectErr := inspectWindowsReplacementHandle(
			currentHandle,
			"failed installed Windows executable",
		)
		closeErr := windows.CloseHandle(currentHandle)
		if inspectErr != nil {
			return inspectErr
		}
		if closeErr != nil {
			return fmt.Errorf("close failed installed Windows executable inspection handle: %w", closeErr)
		}
		if currentIdentity == security.targetIdentity {
			return nil
		}
	} else if !isWindowsPathNotFound(openErr) {
		return openErr
	}
	if err := renameWindowsReplacementHandle(security.target, target, true); err != nil {
		return err
	}
	if err := requireWindowsReplacementHandleIdentity(
		security.target,
		security.targetIdentity,
		"restored Windows executable",
	); err != nil {
		return err
	}
	return requireWindowsReplacementPathIdentity(
		target,
		security.targetIdentity,
		"restored Windows executable",
	)
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
	headerSize := int(unsafe.Offsetof(layout.fileName))
	bufferSize := headerSize + len(name)*2
	if minimum := int(unsafe.Sizeof(layout)); bufferSize < minimum {
		bufferSize = minimum
	}
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
	windowsReplacementRecordSize      = 44
	windowsReplacementRecordVersion   = uint32(1)
	windowsReplacementRecordPrepared  = uint32(1)
	windowsReplacementRecordCompleted = uint32(2)
)

var windowsReplacementRecordMagic = [8]byte{'S', 'S', 'M', 'O', 'L', 'D', '1', 0}

type windowsReplacementRecordData struct {
	state     uint32
	original  windowsFileIdentity
	installed windowsFileIdentity
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
	policy *windowsControlSecurityPolicy,
) (*windowsReplacementRecordState, error) {
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
			state:     windowsReplacementRecordPrepared,
			original:  original,
			installed: installed,
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
	putWindowsFileIdentity(data[16:28], record.original)
	putWindowsFileIdentity(data[28:40], record.installed)
	binary.LittleEndian.PutUint32(data[40:44], crc32.ChecksumIEEE(data[:40]))
	return data
}

func decodeWindowsReplacementRecord(data []byte) (windowsReplacementRecordData, error) {
	if len(data) != windowsReplacementRecordSize {
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
	if got, want := binary.LittleEndian.Uint32(data[40:44]), crc32.ChecksumIEEE(data[:40]); got != want {
		return windowsReplacementRecordData{}, fmt.Errorf("Windows rollback ownership record checksum is invalid")
	}
	state := binary.LittleEndian.Uint32(data[12:16])
	if state != windowsReplacementRecordPrepared && state != windowsReplacementRecordCompleted {
		return windowsReplacementRecordData{}, fmt.Errorf(
			"Windows rollback ownership record state %d is invalid",
			state,
		)
	}
	return windowsReplacementRecordData{
		state:     state,
		original:  getWindowsFileIdentity(data[16:28]),
		installed: getWindowsFileIdentity(data[28:40]),
	}, nil
}

func putWindowsFileIdentity(data []byte, identity windowsFileIdentity) {
	binary.LittleEndian.PutUint32(data[0:4], identity.volumeSerialNumber)
	binary.LittleEndian.PutUint32(data[4:8], identity.fileIndexHigh)
	binary.LittleEndian.PutUint32(data[8:12], identity.fileIndexLow)
}

func getWindowsFileIdentity(data []byte) windowsFileIdentity {
	return windowsFileIdentity{
		volumeSerialNumber: binary.LittleEndian.Uint32(data[0:4]),
		fileIndexHigh:      binary.LittleEndian.Uint32(data[4:8]),
		fileIndexLow:       binary.LittleEndian.Uint32(data[8:12]),
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
	updateLock, err := acquireWindowsReplacementLock(target)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := updateLock.close(); closeErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("release Windows executable update lock: %w", closeErr),
			)
		}
	}()
	return cleanupCompletedWindowsRollbackUnderLockWithPolicy(target, updateLock.policy)
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
		if closeErr := record.close(); closeErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("close Windows rollback ownership record: %w", closeErr),
			)
		}
	}()
	if record.data.state != windowsReplacementRecordCompleted {
		return fmt.Errorf("incomplete Windows executable replacement requires recovery")
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
			if closeErr := windows.CloseHandle(targetHandle); closeErr != nil {
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
		windows.DELETE,
		windows.FILE_SHARE_READ,
	)
	if err != nil && isWindowsPathNotFound(err) {
		if err := record.remove(); err != nil {
			return fmt.Errorf("remove completed Windows rollback ownership record: %w", err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	backupOpen := true
	defer func() {
		if backupOpen {
			if closeErr := windows.CloseHandle(backupHandle); closeErr != nil {
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
	if err := deleteWindowsReplacementHandle(backupHandle); err != nil {
		return fmt.Errorf("remove completed Windows rollback image: %w", err)
	}
	if err := windows.CloseHandle(backupHandle); err != nil {
		backupOpen = false
		return fmt.Errorf("close removed Windows rollback image: %w", err)
	}
	backupOpen = false
	if err := record.remove(); err != nil {
		return fmt.Errorf("remove completed Windows rollback ownership record: %w", err)
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

func windowsReplacementLock(target string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".update.lock")
}
