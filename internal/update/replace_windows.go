//go:build windows

package update

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	windowsReplacementPhaseAfterLock        = "after_lock"
	windowsReplacementPhaseBeforeTargetMove = "before_target_move"
	windowsReplacementPhaseAfterBackup      = "after_backup"
	windowsReplacementPhaseBeforeStageMove  = "before_stage_move"
)

var (
	moveWindowsReplacementFile = moveWindowsFile
	windowsReplacementTestHook func(string) error
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
	if err := cleanupCompletedWindowsRollbackUnderLock(target); err != nil {
		return fmt.Errorf("clean previous Windows executable: %w", err)
	}

	targetIdentity, err := inspectWindowsReplacementPath(target, "current Windows executable")
	if err != nil {
		return err
	}
	stageIdentity, err := inspectWindowsReplacementPath(staged, "verified Windows replacement")
	if err != nil {
		return err
	}
	if targetIdentity == stageIdentity {
		return fmt.Errorf("verified Windows replacement aliases the current executable")
	}

	security, err := prepareWindowsReplacementSecurity(
		staged,
		target,
		targetIdentity,
		stageIdentity,
	)
	if err != nil {
		return fmt.Errorf("preserve Windows executable security descriptor: %w", err)
	}
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
		return failBeforeRecord("revalidate Windows replacement before preserving executable", err)
	}
	if err := requireWindowsReplacementPathIdentity(
		target,
		targetIdentity,
		"current Windows executable",
	); err != nil {
		return failBeforeRecord("revalidate Windows replacement before preserving executable", err)
	}
	if err := requireWindowsReplacementPathIdentity(
		staged,
		stageIdentity,
		"verified Windows replacement",
	); err != nil {
		return failBeforeRecord("revalidate Windows replacement before preserving executable", err)
	}

	record, err := createWindowsReplacementRecord(target, targetIdentity, stageIdentity)
	if err != nil {
		return failBeforeRecord("record Windows rollback ownership", err)
	}
	failBeforeBackup := func(operation string, operationErr error) error {
		if closeErr := closeSecurity(); closeErr != nil {
			operationErr = errors.Join(
				operationErr,
				fmt.Errorf("release Windows security state: %w", closeErr),
			)
		}
		if closeErr := record.close(); closeErr != nil {
			operationErr = errors.Join(
				operationErr,
				fmt.Errorf("close Windows rollback ownership record: %w", closeErr),
			)
		}
		if removeErr := removeWindowsReplacementPath(
			windowsReplacementRecord(target),
			record.identity,
			"Windows rollback ownership record",
		); removeErr != nil {
			operationErr = errors.Join(
				operationErr,
				fmt.Errorf("remove Windows rollback ownership record: %w", removeErr),
			)
		}
		return fmt.Errorf("%s: %w", operation, operationErr)
	}
	failAfterBackup := func(operation string, operationErr error) error {
		if closeErr := closeSecurity(); closeErr != nil {
			operationErr = errors.Join(
				operationErr,
				fmt.Errorf("release Windows security state: %w", closeErr),
			)
		}
		if closeErr := record.close(); closeErr != nil {
			operationErr = errors.Join(
				operationErr,
				fmt.Errorf("close Windows rollback ownership record: %w", closeErr),
			)
		}
		if rollbackErr := rollbackWindowsReplacement(
			target,
			targetIdentity,
			stageIdentity,
			record.identity,
		); rollbackErr != nil {
			return fmt.Errorf("%s: %w (rollback failed: %v)", operation, operationErr, rollbackErr)
		}
		return fmt.Errorf("%s: %w", operation, operationErr)
	}

	backup := windowsReplacementBackup(target)
	if err := moveExpectedWindowsReplacementPath(
		target,
		backup,
		targetIdentity,
		nil,
		false,
		"current Windows executable",
		"Windows rollback image",
	); err != nil {
		backupIdentity, exists, inspectErr := inspectOptionalWindowsReplacementPath(
			backup,
			"Windows rollback image",
		)
		switch {
		case inspectErr != nil:
			return failAfterBackup(
				"preserve running Windows executable",
				errors.Join(err, inspectErr),
			)
		case exists && backupIdentity == targetIdentity:
			return failAfterBackup("preserve running Windows executable", err)
		default:
			return failBeforeBackup("preserve running Windows executable", err)
		}
	}
	if err := runWindowsReplacementTestHook(windowsReplacementPhaseAfterBackup); err != nil {
		return failAfterBackup("continue after preserving running Windows executable", err)
	}
	if err := runWindowsReplacementTestHook(windowsReplacementPhaseBeforeStageMove); err != nil {
		return failAfterBackup("revalidate verified Windows replacement before install", err)
	}
	if err := moveExpectedWindowsReplacementPath(
		staged,
		target,
		stageIdentity,
		nil,
		false,
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
	if err := closeSecurity(); err != nil {
		return failAfterBackup("release Windows security state", err)
	}
	if err := record.markCompleted(); err != nil {
		return failAfterBackup("mark Windows replacement complete", err)
	}
	if err := record.close(); err != nil {
		return failAfterBackup("close completed Windows rollback ownership record", err)
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
	fileType, err := windows.GetFileType(handle)
	if err != nil {
		return windowsFileIdentity{}, fmt.Errorf("inspect %s file type: %w", description, err)
	}
	if fileType != windows.FILE_TYPE_DISK {
		return windowsFileIdentity{}, fmt.Errorf("%s is not a disk file", description)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return windowsFileIdentity{}, fmt.Errorf("inspect %s identity: %w", description, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return windowsFileIdentity{}, fmt.Errorf("%s is a reparse point", description)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return windowsFileIdentity{}, fmt.Errorf("%s is a directory", description)
	}
	if info.NumberOfLinks != 1 {
		return windowsFileIdentity{}, fmt.Errorf("%s has %d hard links", description, info.NumberOfLinks)
	}
	return windowsFileIdentity{
		volumeSerialNumber: info.VolumeSerialNumber,
		fileIndexHigh:      info.FileIndexHigh,
		fileIndexLow:       info.FileIndexLow,
	}, nil
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
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(
		pathPointer,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|
			windows.FILE_FLAG_BACKUP_SEMANTICS|
			windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

func moveExpectedWindowsReplacementPath(
	source,
	destination string,
	sourceIdentity windowsFileIdentity,
	destinationIdentity *windowsFileIdentity,
	replace bool,
	sourceDescription,
	destinationDescription string,
) error {
	if err := requireWindowsReplacementPathIdentity(source, sourceIdentity, sourceDescription); err != nil {
		return err
	}
	if destinationIdentity == nil {
		if err := requireWindowsReplacementPathAbsent(destination, destinationDescription); err != nil {
			return err
		}
	} else if err := requireWindowsReplacementPathIdentity(
		destination,
		*destinationIdentity,
		destinationDescription,
	); err != nil {
		return err
	}
	if err := moveWindowsReplacementFile(source, destination, replace); err != nil {
		return err
	}
	if err := requireWindowsReplacementPathIdentity(
		destination,
		sourceIdentity,
		destinationDescription,
	); err != nil {
		return err
	}
	return requireWindowsReplacementPathAbsent(source, sourceDescription)
}

func rollbackWindowsReplacement(
	target string,
	targetIdentity,
	stageIdentity,
	recordIdentity windowsFileIdentity,
) error {
	backup := windowsReplacementBackup(target)
	if err := requireWindowsReplacementPathIdentity(
		backup,
		targetIdentity,
		"Windows rollback image",
	); err != nil {
		return err
	}
	currentIdentity, targetExists, err := inspectOptionalWindowsReplacementPath(
		target,
		"failed installed Windows executable",
	)
	if err != nil {
		return err
	}
	var destinationIdentity *windowsFileIdentity
	if targetExists {
		if currentIdentity != stageIdentity {
			return fmt.Errorf("canonical Windows executable changed before rollback")
		}
		destinationIdentity = &stageIdentity
	}
	if err := moveExpectedWindowsReplacementPath(
		backup,
		target,
		targetIdentity,
		destinationIdentity,
		targetExists,
		"Windows rollback image",
		"restored Windows executable",
	); err != nil {
		return err
	}
	return removeWindowsReplacementPath(
		windowsReplacementRecord(target),
		recordIdentity,
		"Windows rollback ownership record",
	)
}

type windowsReplacementLockState struct {
	handle     windows.Handle
	overlapped windows.Overlapped
	locked     bool
}

func acquireWindowsReplacementLock(target string) (*windowsReplacementLockState, error) {
	path := windowsReplacementLock(target)
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
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
	state := &windowsReplacementLockState{handle: handle}
	if _, err := inspectWindowsReplacementHandle(handle, "Windows executable update lock"); err != nil {
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
	handle   windows.Handle
	identity windowsFileIdentity
	data     windowsReplacementRecordData
}

func createWindowsReplacementRecord(
	target string,
	original,
	installed windowsFileIdentity,
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
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ,
		nil,
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
	state.identity, err = inspectWindowsReplacementHandle(
		handle,
		"Windows rollback ownership record",
	)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if err := state.write(); err != nil {
		if closeErr := state.close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close failed Windows rollback ownership record: %w", closeErr))
		}
		if removeErr := removeWindowsReplacementPath(
			path,
			state.identity,
			"failed Windows rollback ownership record",
		); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("remove failed Windows rollback ownership record: %w", removeErr))
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

func readWindowsReplacementRecord(
	target string,
) (windowsReplacementRecordData, windowsFileIdentity, error) {
	path := windowsReplacementRecord(target)
	handle, err := openWindowsReplacementFile(path, windows.GENERIC_READ)
	if err != nil {
		return windowsReplacementRecordData{}, windowsFileIdentity{}, err
	}
	identity, inspectErr := inspectWindowsReplacementHandle(
		handle,
		"Windows rollback ownership record",
	)
	if inspectErr != nil {
		_ = windows.CloseHandle(handle)
		return windowsReplacementRecordData{}, windowsFileIdentity{}, inspectErr
	}
	data := make([]byte, windowsReplacementRecordSize+1)
	var read uint32
	readErr := windows.ReadFile(handle, data, &read, nil)
	closeErr := windows.CloseHandle(handle)
	if readErr != nil {
		return windowsReplacementRecordData{}, windowsFileIdentity{}, readErr
	}
	if closeErr != nil {
		return windowsReplacementRecordData{}, windowsFileIdentity{}, closeErr
	}
	record, err := decodeWindowsReplacementRecord(data[:read])
	return record, identity, err
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
	return cleanupCompletedWindowsRollbackUnderLock(target)
}

func cleanupCompletedWindowsRollbackUnderLock(target string) error {
	backup := windowsReplacementBackup(target)
	recordPath := windowsReplacementRecord(target)
	backupIdentity, backupExists, err := inspectOptionalWindowsReplacementPath(
		backup,
		"Windows rollback image",
	)
	if err != nil {
		return err
	}
	_, recordExists, err := inspectOptionalWindowsReplacementPath(
		recordPath,
		"Windows rollback ownership record",
	)
	if err != nil {
		return err
	}
	if !backupExists && !recordExists {
		return nil
	}
	if backupExists && !recordExists {
		return fmt.Errorf("Windows rollback evidence has no ownership record")
	}

	record, recordIdentity, err := readWindowsReplacementRecord(target)
	if err != nil {
		return fmt.Errorf("read Windows rollback ownership record: %w", err)
	}
	if record.state != windowsReplacementRecordCompleted {
		return fmt.Errorf("incomplete Windows executable replacement requires recovery")
	}
	targetIdentity, targetExists, err := inspectOptionalWindowsReplacementPath(
		target,
		"installed Windows executable",
	)
	if err != nil {
		return err
	}
	if !targetExists || targetIdentity != record.installed {
		return fmt.Errorf("completed Windows rollback record does not match the installed executable")
	}
	if !backupExists {
		return removeWindowsReplacementPath(
			recordPath,
			recordIdentity,
			"completed Windows rollback ownership record",
		)
	}
	if backupIdentity != record.original {
		return fmt.Errorf("completed Windows rollback record does not match the rollback image")
	}
	if err := removeWindowsReplacementPath(
		backup,
		backupIdentity,
		"completed Windows rollback image",
	); err != nil {
		return err
	}
	return removeWindowsReplacementPath(
		recordPath,
		recordIdentity,
		"completed Windows rollback ownership record",
	)
}

func removeWindowsReplacementPath(
	path string,
	expected windowsFileIdentity,
	description string,
) error {
	if err := requireWindowsReplacementPathIdentity(path, expected, description); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return requireWindowsReplacementPathAbsent(path, description)
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

func moveWindowsFile(source, destination string, replace bool) error {
	sourcePath, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPath, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(sourcePath, destinationPath, flags)
}
