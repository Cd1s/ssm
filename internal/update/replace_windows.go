//go:build windows

package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	getWindowsSecurityInfo = windows.GetSecurityInfo
	setWindowsSecurityInfo = windows.SetSecurityInfo
)

func replaceExecutable(staged, target string) error {
	if !strings.EqualFold(filepath.Clean(filepath.Dir(staged)), filepath.Clean(filepath.Dir(target))) {
		return fmt.Errorf("Windows replacement staging is not on the executable filesystem")
	}
	if err := requireRegularWindowsReplacementFile(target, "current Windows executable"); err != nil {
		return err
	}
	if err := requireRegularWindowsReplacementFile(staged, "verified Windows replacement"); err != nil {
		return err
	}

	security, err := prepareWindowsReplacementSecurity(staged, target)
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
	failBeforeRename := func(operation string, operationErr error) error {
		if closeErr := closeSecurity(); closeErr != nil {
			operationErr = errors.Join(operationErr, fmt.Errorf("release Windows security privileges: %w", closeErr))
		}
		return fmt.Errorf("%s: %w", operation, operationErr)
	}
	failAfterBackup := func(operation string, operationErr error) error {
		if closeErr := closeSecurity(); closeErr != nil {
			operationErr = errors.Join(operationErr, fmt.Errorf("release Windows security privileges: %w", closeErr))
		}
		backup := windowsReplacementBackup(target)
		if rollbackErr := moveWindowsFile(backup, target, true); rollbackErr != nil {
			return fmt.Errorf("%s: %w (rollback failed: %v)", operation, operationErr, rollbackErr)
		}
		return fmt.Errorf("%s: %w", operation, operationErr)
	}

	if err := cleanupPreviousExecutable(target); err != nil {
		return failBeforeRename("clean previous Windows executable", err)
	}

	backup := windowsReplacementBackup(target)
	if err := moveWindowsFile(target, backup, false); err != nil {
		return failBeforeRename("preserve running Windows executable", err)
	}
	if err := moveWindowsFile(staged, target, false); err != nil {
		return failAfterBackup("install verified Windows executable", err)
	}
	if err := security.apply(); err != nil {
		return failAfterBackup("apply preserved Windows security descriptor", err)
	}
	if err := security.verify(); err != nil {
		return failAfterBackup("verify preserved Windows security descriptor", err)
	}
	if err := closeSecurity(); err != nil {
		if rollbackErr := moveWindowsFile(backup, target, true); rollbackErr != nil {
			return fmt.Errorf("release Windows security privileges: %w (rollback failed: %v)", err, rollbackErr)
		}
		return fmt.Errorf("release Windows security privileges: %w", err)
	}
	return nil
}

func requireRegularWindowsReplacementFile(path, description string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", description, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", description)
	}
	return nil
}

type windowsReplacementSecurityState struct {
	scope      *windowsReplacementPrivilegeScope
	target     windows.Handle
	staged     windows.Handle
	descriptor *windows.SECURITY_DESCRIPTOR
}

func prepareWindowsReplacementSecurity(staged, target string) (*windowsReplacementSecurityState, error) {
	scope, err := beginWindowsReplacementPrivileges()
	if err != nil {
		return nil, err
	}
	state := &windowsReplacementSecurityState{
		scope:  scope,
		target: windows.InvalidHandle,
		staged: windows.InvalidHandle,
	}
	fail := func(err error) (*windowsReplacementSecurityState, error) {
		if closeErr := state.close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, err
	}

	state.target, err = openWindowsReplacementFile(
		target,
		windows.READ_CONTROL|windows.ACCESS_SYSTEM_SECURITY,
	)
	if err != nil {
		return fail(fmt.Errorf("open current executable security descriptor: %w", err))
	}
	targetIdentity, err := inspectWindowsReplacementHandle(state.target, false)
	if err != nil {
		return fail(fmt.Errorf("inspect current executable handle: %w", err))
	}
	state.staged, err = openWindowsReplacementFile(
		staged,
		windows.READ_CONTROL|
			windows.WRITE_DAC|
			windows.WRITE_OWNER|
			windows.ACCESS_SYSTEM_SECURITY,
	)
	if err != nil {
		return fail(fmt.Errorf("open verified replacement security descriptor: %w", err))
	}
	stageIdentity, err := inspectWindowsReplacementHandle(state.staged, true)
	if err != nil {
		return fail(fmt.Errorf("inspect verified replacement handle: %w", err))
	}
	if targetIdentity == stageIdentity {
		return fail(fmt.Errorf("verified Windows replacement aliases the current executable"))
	}

	state.descriptor, err = getWindowsSecurityInfo(
		state.target,
		windows.SE_FILE_OBJECT,
		windows.BACKUP_SECURITY_INFORMATION,
	)
	if err != nil {
		return fail(fmt.Errorf("capture current executable security descriptor: %w", err))
	}
	if err := validateWindowsSecurityDescriptor(state.descriptor); err != nil {
		return fail(fmt.Errorf("capture current executable security descriptor: %w", err))
	}
	if err := state.apply(); err != nil {
		return fail(fmt.Errorf("apply current security descriptor to verified replacement: %w", err))
	}
	if err := state.verify(); err != nil {
		return fail(fmt.Errorf("verify current security descriptor on verified replacement: %w", err))
	}
	return state, nil
}

type windowsFileIdentity struct {
	volumeSerialNumber uint32
	fileIndexHigh      uint32
	fileIndexLow       uint32
}

func inspectWindowsReplacementHandle(handle windows.Handle, requireSingleLink bool) (windowsFileIdentity, error) {
	fileType, err := windows.GetFileType(handle)
	if err != nil {
		return windowsFileIdentity{}, err
	}
	if fileType != windows.FILE_TYPE_DISK {
		return windowsFileIdentity{}, fmt.Errorf("replacement path is not a disk file")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return windowsFileIdentity{}, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return windowsFileIdentity{}, fmt.Errorf("replacement path is a reparse point")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return windowsFileIdentity{}, fmt.Errorf("replacement path is a directory")
	}
	if requireSingleLink && info.NumberOfLinks != 1 {
		return windowsFileIdentity{}, fmt.Errorf("verified Windows replacement has %d hard links", info.NumberOfLinks)
	}
	return windowsFileIdentity{
		volumeSerialNumber: info.VolumeSerialNumber,
		fileIndexHigh:      info.FileIndexHigh,
		fileIndexLow:       info.FileIndexLow,
	}, nil
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

func (state *windowsReplacementSecurityState) apply() error {
	owner, _, err := state.descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read owner: %w", err)
	}
	if owner == nil {
		return fmt.Errorf("security descriptor owner is absent")
	}
	group, _, err := state.descriptor.Group()
	if err != nil {
		return fmt.Errorf("read primary group: %w", err)
	}
	if group == nil {
		return fmt.Errorf("security descriptor primary group is absent")
	}
	dacl, _, err := state.descriptor.DACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return fmt.Errorf("read DACL: %w", err)
	}
	sacl, _, err := state.descriptor.SACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return fmt.Errorf("read SACL: %w", err)
	}
	control, _, err := state.descriptor.Control()
	if err != nil {
		return fmt.Errorf("read descriptor control: %w", err)
	}
	securityInformation := windows.SECURITY_INFORMATION(
		windows.BACKUP_SECURITY_INFORMATION |
			windows.OWNER_SECURITY_INFORMATION |
			windows.GROUP_SECURITY_INFORMATION |
			windows.DACL_SECURITY_INFORMATION |
			windows.SACL_SECURITY_INFORMATION |
			windows.LABEL_SECURITY_INFORMATION |
			windows.ATTRIBUTE_SECURITY_INFORMATION |
			windows.SCOPE_SECURITY_INFORMATION,
	)
	if control&windows.SE_DACL_PROTECTED != 0 {
		securityInformation |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		securityInformation |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if control&windows.SE_SACL_PROTECTED != 0 {
		securityInformation |= windows.PROTECTED_SACL_SECURITY_INFORMATION
	} else {
		securityInformation |= windows.UNPROTECTED_SACL_SECURITY_INFORMATION
	}
	if err := setWindowsSecurityInfo(
		state.staged,
		windows.SE_FILE_OBJECT,
		securityInformation,
		owner,
		group,
		dacl,
		sacl,
	); err != nil {
		return err
	}
	return nil
}

func (state *windowsReplacementSecurityState) verify() error {
	descriptor, err := getWindowsSecurityInfo(
		state.staged,
		windows.SE_FILE_OBJECT,
		windows.BACKUP_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	if err := validateWindowsSecurityDescriptor(descriptor); err != nil {
		return err
	}
	return compareWindowsSecurityDescriptors(state.descriptor, descriptor)
}

func validateWindowsSecurityDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	if descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("security descriptor is absent or invalid")
	}
	if descriptor.String() == "" {
		return fmt.Errorf("security descriptor cannot be represented")
	}
	return nil
}

func compareWindowsSecurityDescriptors(want, got *windows.SECURITY_DESCRIPTOR) error {
	if want.String() != got.String() {
		return fmt.Errorf("security descriptor owner, group, DACL, or SACL changed")
	}
	wantControl, _, err := want.Control()
	if err != nil {
		return fmt.Errorf("read source descriptor control: %w", err)
	}
	gotControl, _, err := got.Control()
	if err != nil {
		return fmt.Errorf("read replacement descriptor control: %w", err)
	}
	const relevantControl = windows.SE_OWNER_DEFAULTED |
		windows.SE_GROUP_DEFAULTED |
		windows.SE_DACL_PRESENT |
		windows.SE_DACL_DEFAULTED |
		windows.SE_SACL_PRESENT |
		windows.SE_SACL_DEFAULTED |
		windows.SE_DACL_AUTO_INHERIT_REQ |
		windows.SE_SACL_AUTO_INHERIT_REQ |
		windows.SE_DACL_AUTO_INHERITED |
		windows.SE_SACL_AUTO_INHERITED |
		windows.SE_DACL_PROTECTED |
		windows.SE_SACL_PROTECTED |
		windows.SE_RM_CONTROL_VALID
	if wantControl&relevantControl != gotControl&relevantControl {
		return fmt.Errorf("security descriptor inheritance or defaulting state changed")
	}
	return nil
}

func (state *windowsReplacementSecurityState) close() error {
	var errs []error
	if state.target != windows.InvalidHandle {
		errs = append(errs, windows.CloseHandle(state.target))
		state.target = windows.InvalidHandle
	}
	if state.staged != windows.InvalidHandle {
		errs = append(errs, windows.CloseHandle(state.staged))
		state.staged = windows.InvalidHandle
	}
	if state.scope != nil {
		errs = append(errs, state.scope.close())
		state.scope = nil
	}
	return errors.Join(errs...)
}

type windowsReplacementPrivilegeScope struct {
	token    windows.Token
	previous []windows.Tokenprivileges
	active   bool
}

func beginWindowsReplacementPrivileges() (*windowsReplacementPrivilegeScope, error) {
	runtime.LockOSThread()
	scope := &windowsReplacementPrivilegeScope{active: true}
	fail := func(err error) (*windowsReplacementPrivilegeScope, error) {
		if closeErr := scope.close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, err
	}
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		return fail(fmt.Errorf("impersonate current process for scoped privileges: %w", err))
	}
	if err := windows.OpenThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES,
		true,
		&scope.token,
	); err != nil {
		return fail(fmt.Errorf("open scoped replacement token: %w", err))
	}
	for _, privilege := range []string{
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeSecurityPrivilege",
	} {
		previous, err := enableWindowsReplacementPrivilege(scope.token, privilege)
		if err != nil {
			return fail(fmt.Errorf("enable %s: %w", privilege, err))
		}
		scope.previous = append(scope.previous, previous)
	}
	return scope, nil
}

func enableWindowsReplacementPrivilege(token windows.Token, name string) (windows.Tokenprivileges, error) {
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return windows.Tokenprivileges{}, err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePointer, &luid); err != nil {
		return windows.Tokenprivileges{}, err
	}
	state := windows.Tokenprivileges{PrivilegeCount: 1}
	state.Privileges[0] = windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}
	var previous windows.Tokenprivileges
	var previousLength uint32
	if err := windows.AdjustTokenPrivileges(
		token,
		false,
		&state,
		uint32(unsafe.Sizeof(previous)),
		&previous,
		&previousLength,
	); err != nil {
		return windows.Tokenprivileges{}, err
	}
	if lastErr := windows.GetLastError(); lastErr != nil {
		return windows.Tokenprivileges{}, lastErr
	}
	return previous, nil
}

func (scope *windowsReplacementPrivilegeScope) close() error {
	if !scope.active {
		return nil
	}
	var errs []error
	for i := len(scope.previous) - 1; i >= 0; i-- {
		previous := scope.previous[i]
		if err := windows.AdjustTokenPrivileges(
			scope.token,
			false,
			&previous,
			0,
			nil,
			nil,
		); err != nil {
			errs = append(errs, fmt.Errorf("restore replacement privilege: %w", err))
		} else if lastErr := windows.GetLastError(); lastErr != nil {
			errs = append(errs, fmt.Errorf("restore replacement privilege: %w", lastErr))
		}
	}
	if scope.token != 0 {
		errs = append(errs, scope.token.Close())
		scope.token = 0
	}
	errs = append(errs, windows.RevertToSelf())
	scope.active = false
	runtime.UnlockOSThread()
	return errors.Join(errs...)
}

func cleanupPreviousExecutable(target string) error {
	backup := windowsReplacementBackup(target)
	info, err := os.Lstat(backup)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", backup)
	}
	return os.Remove(backup)
}

func windowsReplacementBackup(target string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".old")
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
