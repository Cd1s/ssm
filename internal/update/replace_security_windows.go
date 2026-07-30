//go:build windows

package update

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsOrdinarySecurityInformation windows.SECURITY_INFORMATION = windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION
	windowsFullSecurityInformation windows.SECURITY_INFORMATION = windows.BACKUP_SECURITY_INFORMATION
)

var (
	getWindowsSecurityInfoProcedure    = windows.NewLazySystemDLL("advapi32.dll").NewProc("GetSecurityInfo")
	localFreeWindowsSecurityDescriptor = windows.LocalFree
	setWindowsSecurityInfo             = windows.SetSecurityInfo
)

type ownedWindowsSecurityDescriptor struct {
	descriptor *windows.SECURITY_DESCRIPTOR
}

func captureWindowsSecurityDescriptor(
	handle windows.Handle,
	information windows.SECURITY_INFORMATION,
) (*ownedWindowsSecurityDescriptor, error) {
	var descriptor *windows.SECURITY_DESCRIPTOR
	result, _, _ := getWindowsSecurityInfoProcedure.Call(
		uintptr(handle),
		uintptr(windows.SE_FILE_OBJECT),
		uintptr(information),
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&descriptor)),
	)
	if result != 0 {
		err := error(syscall.Errno(result))
		if descriptor != nil {
			if _, freeErr := localFreeWindowsSecurityDescriptor(
				windows.Handle(unsafe.Pointer(descriptor)),
			); freeErr != nil {
				err = errors.Join(err, fmt.Errorf("free failed security descriptor: %w", freeErr))
			}
		}
		return nil, err
	}
	if descriptor == nil {
		return nil, fmt.Errorf("GetSecurityInfo returned an absent security descriptor")
	}
	return &ownedWindowsSecurityDescriptor{descriptor: descriptor}, nil
}

func (descriptor *ownedWindowsSecurityDescriptor) close() error {
	if descriptor == nil || descriptor.descriptor == nil {
		return nil
	}
	memory := windows.Handle(unsafe.Pointer(descriptor.descriptor))
	descriptor.descriptor = nil
	_, err := localFreeWindowsSecurityDescriptor(memory)
	return err
}

type windowsSecurityTier struct {
	name         string
	full         bool
	information  windows.SECURITY_INFORMATION
	targetAccess uint32
	stageAccess  uint32
}

var (
	windowsOrdinarySecurityTier = windowsSecurityTier{
		name:         "ordinary owner/group/DACL",
		information:  windowsOrdinarySecurityInformation,
		targetAccess: windows.READ_CONTROL,
		stageAccess:  windows.READ_CONTROL | windows.WRITE_DAC,
	}
	windowsFullSecurityTier = windowsSecurityTier{
		name:         "privileged complete descriptor",
		full:         true,
		information:  windowsFullSecurityInformation,
		targetAccess: windows.READ_CONTROL | windows.ACCESS_SYSTEM_SECURITY,
		stageAccess: windows.READ_CONTROL |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.ACCESS_SYSTEM_SECURITY,
	}
)

type windowsReplacementSecurityState struct {
	tier             windowsSecurityTier
	scope            *windowsReplacementPrivilegeScope
	target           windows.Handle
	staged           windows.Handle
	stagedOwner      windows.Handle
	targetIdentity   windowsFileIdentity
	stageIdentity    windowsFileIdentity
	sourceDescriptor *ownedWindowsSecurityDescriptor
	applyOwner       bool
	applyGroup       bool
}

func prepareWindowsReplacementSecurity(
	staged,
	target string,
) (*windowsReplacementSecurityState, error) {
	scope, full, err := beginWindowsReplacementPrivileges()
	if err != nil {
		return nil, err
	}
	tier := windowsOrdinarySecurityTier
	if full {
		tier = windowsFullSecurityTier
	}
	state := &windowsReplacementSecurityState{
		tier:        tier,
		scope:       scope,
		target:      windows.InvalidHandle,
		staged:      windows.InvalidHandle,
		stagedOwner: windows.InvalidHandle,
	}
	fail := func(operationErr error) (*windowsReplacementSecurityState, error) {
		if closeErr := state.close(); closeErr != nil {
			operationErr = errors.Join(operationErr, closeErr)
		}
		return nil, operationErr
	}

	state.target, err = openWindowsProtectedReplacementFile(
		target,
		tier.targetAccess|windows.DELETE,
	)
	if err != nil {
		return fail(fmt.Errorf("open current executable %s: %w", tier.name, err))
	}
	state.targetIdentity, err = inspectWindowsReplacementHandle(
		state.target,
		"current Windows executable",
	)
	if err != nil {
		return fail(err)
	}
	state.staged, err = openWindowsProtectedReplacementFile(
		staged,
		tier.stageAccess|windows.DELETE,
	)
	if err != nil {
		return fail(fmt.Errorf("open verified replacement %s: %w", tier.name, err))
	}
	state.stageIdentity, err = inspectWindowsReplacementHandle(
		state.staged,
		"verified Windows replacement",
	)
	if err != nil {
		return fail(err)
	}
	if state.targetIdentity == state.stageIdentity {
		return fail(fmt.Errorf("verified Windows replacement aliases the current executable"))
	}

	state.sourceDescriptor, err = captureWindowsSecurityDescriptor(state.target, tier.information)
	if err != nil {
		return fail(fmt.Errorf("capture current executable %s: %w", tier.name, err))
	}
	if err := validateWindowsSecurityDescriptor(state.sourceDescriptor.descriptor); err != nil {
		return fail(fmt.Errorf("capture current executable %s: %w", tier.name, err))
	}
	if !tier.full {
		if err := state.prepareOrdinaryOwnerAndGroup(staged); err != nil {
			return fail(err)
		}
	} else {
		state.applyOwner = true
		state.applyGroup = true
	}
	if err := state.apply(); err != nil {
		return fail(fmt.Errorf("apply current %s to verified replacement: %w", tier.name, err))
	}
	if err := state.verify(); err != nil {
		return fail(fmt.Errorf("verify current %s on verified replacement: %w", tier.name, err))
	}
	return state, nil
}

func (state *windowsReplacementSecurityState) prepareOrdinaryOwnerAndGroup(
	staged string,
) (err error) {
	current, err := captureWindowsSecurityDescriptor(state.staged, windowsOrdinarySecurityInformation)
	if err != nil {
		return fmt.Errorf("capture verified replacement owner/group: %w", err)
	}
	defer func() {
		if closeErr := current.close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("free verified replacement security descriptor: %w", closeErr))
		}
	}()
	sourceOwner, _, err := state.sourceDescriptor.descriptor.Owner()
	if err != nil || sourceOwner == nil {
		return fmt.Errorf("read current executable owner: %w", descriptorComponentError(err))
	}
	currentOwner, _, err := current.descriptor.Owner()
	if err != nil || currentOwner == nil {
		return fmt.Errorf("read verified replacement owner: %w", descriptorComponentError(err))
	}
	sourceGroup, _, err := state.sourceDescriptor.descriptor.Group()
	if err != nil || sourceGroup == nil {
		return fmt.Errorf("read current executable primary group: %w", descriptorComponentError(err))
	}
	currentGroup, _, err := current.descriptor.Group()
	if err != nil || currentGroup == nil {
		return fmt.Errorf("read verified replacement primary group: %w", descriptorComponentError(err))
	}
	state.applyOwner = !windows.EqualSid(sourceOwner, currentOwner)
	state.applyGroup = !windows.EqualSid(sourceGroup, currentGroup)
	if !state.applyOwner && !state.applyGroup {
		return nil
	}

	state.stagedOwner, err = openWindowsReplacementFileWithShare(
		staged,
		state.tier.stageAccess|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
	)
	if err != nil {
		return fmt.Errorf(
			"current permissions cannot preserve the Windows executable owner/primary group: %w",
			err,
		)
	}
	return requireWindowsReplacementHandleIdentity(
		state.stagedOwner,
		state.stageIdentity,
		"verified Windows replacement",
	)
}

func descriptorComponentError(err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("component is absent")
}

func (state *windowsReplacementSecurityState) apply() error {
	descriptor := state.sourceDescriptor.descriptor
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("read owner: %w", descriptorComponentError(err))
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil {
		return fmt.Errorf("read primary group: %w", descriptorComponentError(err))
	}
	dacl, _, err := descriptor.DACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return fmt.Errorf("read DACL: %w", err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read descriptor control: %w", err)
	}

	information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if state.applyOwner {
		information |= windows.OWNER_SECURITY_INFORMATION
	} else {
		owner = nil
	}
	if state.applyGroup {
		information |= windows.GROUP_SECURITY_INFORMATION
	} else {
		group = nil
	}
	if control&windows.SE_DACL_PROTECTED != 0 {
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		information |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}

	var sacl *windows.ACL
	if state.tier.full {
		sacl, _, err = descriptor.SACL()
		if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			return fmt.Errorf("read SACL: %w", err)
		}
		information |= windows.BACKUP_SECURITY_INFORMATION |
			windows.OWNER_SECURITY_INFORMATION |
			windows.GROUP_SECURITY_INFORMATION |
			windows.SACL_SECURITY_INFORMATION |
			windows.LABEL_SECURITY_INFORMATION |
			windows.ATTRIBUTE_SECURITY_INFORMATION |
			windows.SCOPE_SECURITY_INFORMATION
		owner, _, _ = descriptor.Owner()
		group, _, _ = descriptor.Group()
		if control&windows.SE_SACL_PROTECTED != 0 {
			information |= windows.PROTECTED_SACL_SECURITY_INFORMATION
		} else {
			information |= windows.UNPROTECTED_SACL_SECURITY_INFORMATION
		}
	}
	return setWindowsSecurityInfo(
		state.stagedSecurityHandle(),
		windows.SE_FILE_OBJECT,
		information,
		owner,
		group,
		dacl,
		sacl,
	)
}

func (state *windowsReplacementSecurityState) verify() (err error) {
	descriptor, err := captureWindowsSecurityDescriptor(state.stagedSecurityHandle(), state.tier.information)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := descriptor.close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("free verification security descriptor: %w", closeErr))
		}
	}()
	if err := validateWindowsSecurityDescriptor(descriptor.descriptor); err != nil {
		return err
	}
	return compareWindowsSecurityDescriptors(
		state.sourceDescriptor.descriptor,
		descriptor.descriptor,
		state.tier.full,
	)
}

func (state *windowsReplacementSecurityState) stagedSecurityHandle() windows.Handle {
	if state.stagedOwner != windows.InvalidHandle {
		return state.stagedOwner
	}
	return state.staged
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

func compareWindowsSecurityDescriptors(want, got *windows.SECURITY_DESCRIPTOR, full bool) error {
	if want.String() != got.String() {
		if full {
			return fmt.Errorf("complete security descriptor changed")
		}
		return fmt.Errorf("security descriptor owner, primary group, or DACL changed")
	}
	wantControl, _, err := want.Control()
	if err != nil {
		return fmt.Errorf("read source descriptor control: %w", err)
	}
	gotControl, _, err := got.Control()
	if err != nil {
		return fmt.Errorf("read replacement descriptor control: %w", err)
	}
	relevantControl := windows.SECURITY_DESCRIPTOR_CONTROL(
		windows.SE_OWNER_DEFAULTED |
			windows.SE_GROUP_DEFAULTED |
			windows.SE_DACL_PRESENT |
			windows.SE_DACL_DEFAULTED |
			windows.SE_DACL_AUTO_INHERIT_REQ |
			windows.SE_DACL_AUTO_INHERITED |
			windows.SE_DACL_PROTECTED,
	)
	if full {
		relevantControl |= windows.SE_SACL_PRESENT |
			windows.SE_SACL_DEFAULTED |
			windows.SE_SACL_AUTO_INHERIT_REQ |
			windows.SE_SACL_AUTO_INHERITED |
			windows.SE_SACL_PROTECTED |
			windows.SE_RM_CONTROL_VALID
	}
	if wantControl&relevantControl != gotControl&relevantControl {
		return fmt.Errorf("%s inheritance or defaulting state changed", stateDescriptorScope(full))
	}
	return nil
}

func stateDescriptorScope(full bool) string {
	if full {
		return "complete security descriptor"
	}
	return "owner/group/DACL"
}

func (state *windowsReplacementSecurityState) close() error {
	var errs []error
	if state.sourceDescriptor != nil {
		errs = append(errs, state.sourceDescriptor.close())
		state.sourceDescriptor = nil
	}
	if state.target != windows.InvalidHandle {
		errs = append(errs, windows.CloseHandle(state.target))
		state.target = windows.InvalidHandle
	}
	if state.staged != windows.InvalidHandle {
		errs = append(errs, windows.CloseHandle(state.staged))
		state.staged = windows.InvalidHandle
	}
	if state.stagedOwner != windows.InvalidHandle {
		errs = append(errs, windows.CloseHandle(state.stagedOwner))
		state.stagedOwner = windows.InvalidHandle
	}
	if state.scope != nil {
		errs = append(errs, state.scope.close())
		state.scope = nil
	}
	return errors.Join(errs...)
}

type windowsReplacementPrivilegeScope struct {
	token         windows.Token
	processToken  windows.Token
	previousToken windows.Token
	hadPrevious   bool
	installed     bool
	active        bool
}

func beginWindowsReplacementPrivileges() (*windowsReplacementPrivilegeScope, bool, error) {
	runtime.LockOSThread()
	scope := &windowsReplacementPrivilegeScope{active: true}
	fallback := func() (*windowsReplacementPrivilegeScope, bool, error) {
		if err := scope.close(); err != nil {
			return nil, false, fmt.Errorf("restore optional Windows security privilege scope: %w", err)
		}
		return nil, false, nil
	}
	var source windows.Token
	if err := windows.OpenThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE,
		true,
		&scope.previousToken,
	); err == nil {
		scope.hadPrevious = true
		source = scope.previousToken
	} else if errors.Is(err, windows.ERROR_NO_TOKEN) {
		if err := windows.OpenProcessToken(
			windows.CurrentProcess(),
			windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE,
			&scope.processToken,
		); err != nil {
			return fallback()
		}
		source = scope.processToken
	} else {
		return fallback()
	}

	if err := windows.DuplicateTokenEx(
		source,
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_IMPERSONATE,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&scope.token,
	); err != nil {
		return fallback()
	}
	if err := windows.SetThreadToken(nil, scope.token); err != nil {
		return fallback()
	}
	scope.installed = true
	for _, privilege := range []string{
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeSecurityPrivilege",
	} {
		if err := enableWindowsReplacementPrivilege(scope.token, privilege); err != nil {
			return fallback()
		}
	}
	return scope, true, nil
}

func enableWindowsReplacementPrivilege(token windows.Token, name string) error {
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePointer, &luid); err != nil {
		return err
	}
	state := windows.Tokenprivileges{PrivilegeCount: 1}
	state.Privileges[0] = windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}
	if err := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); err != nil {
		return err
	}
	return windows.GetLastError()
}

func (scope *windowsReplacementPrivilegeScope) close() error {
	if scope == nil || !scope.active {
		return nil
	}
	var errs []error
	if scope.installed {
		if scope.hadPrevious {
			errs = append(errs, windows.SetThreadToken(nil, scope.previousToken))
		} else {
			errs = append(errs, windows.RevertToSelf())
		}
		scope.installed = false
	}
	if scope.token != 0 {
		errs = append(errs, scope.token.Close())
		scope.token = 0
	}
	if scope.processToken != 0 {
		errs = append(errs, scope.processToken.Close())
		scope.processToken = 0
	}
	if scope.previousToken != 0 {
		errs = append(errs, scope.previousToken.Close())
		scope.previousToken = 0
	}
	scope.active = false
	runtime.UnlockOSThread()
	return errors.Join(errs...)
}
