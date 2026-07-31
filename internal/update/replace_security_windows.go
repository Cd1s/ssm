//go:build windows

package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
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
	getWindowsSecurityInfoProcedure           = windows.NewLazySystemDLL("advapi32.dll").NewProc("GetSecurityInfo")
	localFreeWindowsSecurityDescriptor        = windows.LocalFree
	setWindowsSecurityInfo                    = windows.SetSecurityInfo
	beginWindowsReplacementSecurityPrivileges = beginWindowsReplacementPrivileges
	captureWindowsReplacementDescriptor       = captureWindowsSecurityDescriptor
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

const (
	windowsSecurityBindingOrdinary                  = uint32(1)
	windowsSecurityBindingFull                      = uint32(2)
	windowsSecurityBindingTierMask                  = uint32(0xff)
	windowsSecurityBindingDACLAutoInheritedRequired = uint32(1 << 8)
	windowsSecurityContractMaxACLBytes              = 64 << 10
	windowsSecurityContractMaxSIDBytes              = 256
)

type windowsSecurityBinding struct {
	metadata uint32
	digest   [sha256.Size]byte
}

type windowsSecurityBindingVerifier struct {
	binding     windowsSecurityBinding
	information windows.SECURITY_INFORMATION
	access      uint32
	scope       *windowsReplacementPrivilegeScope
}

func bindWindowsSecurityDescriptor(
	descriptor *windows.SECURITY_DESCRIPTOR,
	full bool,
) (windowsSecurityBinding, error) {
	if err := validateWindowsSecurityDescriptor(descriptor); err != nil {
		return windowsSecurityBinding{}, err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return windowsSecurityBinding{}, fmt.Errorf("read security descriptor control: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return windowsSecurityBinding{}, fmt.Errorf(
			"read security descriptor owner: %w",
			descriptorComponentError(err),
		)
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil || !group.IsValid() {
		return windowsSecurityBinding{}, fmt.Errorf(
			"read security descriptor primary group: %w",
			descriptorComponentError(err),
		)
	}
	dacl, err := readWindowsDACLContract(descriptor, "security descriptor")
	if err != nil {
		return windowsSecurityBinding{}, err
	}

	binding := windowsSecurityBinding{metadata: windowsSecurityBindingOrdinary}
	digest := sha256.New()
	_, _ = digest.Write([]byte("SSM-WINDOWS-SECURITY-CONTRACT-V1\x00"))
	writeWindowsSecurityContractUint32(digest, windowsSecurityBindingOrdinary)
	if err := writeWindowsSecurityContractSID(digest, owner, "owner"); err != nil {
		return windowsSecurityBinding{}, err
	}
	if err := writeWindowsSecurityContractSID(digest, group, "primary group"); err != nil {
		return windowsSecurityBinding{}, err
	}
	writeWindowsSecurityContractACL(digest, dacl)
	writeWindowsSecurityContractUint32(
		digest,
		uint32(control&windows.SE_DACL_PROTECTED),
	)

	if full {
		binding.metadata = windowsSecurityBindingFull
		sacl, err := readWindowsSACLContract(descriptor, "security descriptor")
		if err != nil {
			return windowsSecurityBinding{}, err
		}
		writeWindowsSecurityContractUint32(digest, windowsSecurityBindingFull)
		writeWindowsSecurityContractACL(digest, sacl)
		writeWindowsSecurityContractUint32(
			digest,
			uint32(control&windowsSecurityBindingFullControlMask()),
		)
		rmControlPresent := control&windows.SE_RM_CONTROL_VALID != 0
		var rmControl byte
		if rmControlPresent {
			rmControl, err = descriptor.RMControl()
			if err != nil {
				return windowsSecurityBinding{},
					fmt.Errorf("read security descriptor resource manager control: %w", err)
			}
		}
		writeWindowsSecurityContractRMControl(digest, rmControlPresent, rmControl)
	} else if control&windows.SE_DACL_AUTO_INHERITED != 0 {
		binding.metadata |= windowsSecurityBindingDACLAutoInheritedRequired
	}
	copy(binding.digest[:], digest.Sum(nil))
	return binding, nil
}

func validateWindowsSecurityBinding(binding windowsSecurityBinding) error {
	switch binding.metadata & windowsSecurityBindingTierMask {
	case windowsSecurityBindingOrdinary:
		if binding.metadata & ^(windowsSecurityBindingTierMask|
			windowsSecurityBindingDACLAutoInheritedRequired) != 0 {
			return fmt.Errorf("ordinary Windows security descriptor binding flags are invalid")
		}
	case windowsSecurityBindingFull:
		if binding.metadata != windowsSecurityBindingFull {
			return fmt.Errorf("complete Windows security descriptor binding flags are invalid")
		}
	default:
		return fmt.Errorf("Windows security descriptor binding tier is invalid")
	}
	return nil
}

func newWindowsSecurityBindingVerifier(
	binding windowsSecurityBinding,
) (*windowsSecurityBindingVerifier, error) {
	if err := validateWindowsSecurityBinding(binding); err != nil {
		return nil, err
	}
	verifier := &windowsSecurityBindingVerifier{
		binding:     binding,
		information: windowsOrdinarySecurityInformation,
		access:      windows.READ_CONTROL,
	}
	if binding.metadata&windowsSecurityBindingTierMask != windowsSecurityBindingFull {
		return verifier, nil
	}
	scope, available, err := beginWindowsReplacementSecurityPrivileges()
	if err != nil {
		return nil, fmt.Errorf("enable complete Windows descriptor recovery privileges: %w", err)
	}
	if !available {
		return nil, fmt.Errorf("complete Windows descriptor recovery privileges are unavailable")
	}
	verifier.scope = scope
	verifier.information = windowsFullSecurityInformation
	verifier.access |= windows.ACCESS_SYSTEM_SECURITY
	return verifier, nil
}

func (verifier *windowsSecurityBindingVerifier) verify(
	handle windows.Handle,
	description string,
) (resultErr error) {
	descriptor, err := captureWindowsReplacementDescriptor(handle, verifier.information)
	if err != nil {
		return fmt.Errorf("capture %s security descriptor: %w", description, err)
	}
	defer func() {
		if closeErr := descriptor.close(); closeErr != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("free %s security descriptor: %w", description, closeErr),
			)
		}
	}()
	got, err := bindWindowsSecurityDescriptor(
		descriptor.descriptor,
		verifier.binding.metadata&windowsSecurityBindingTierMask == windowsSecurityBindingFull,
	)
	if err != nil {
		return fmt.Errorf("bind %s security descriptor: %w", description, err)
	}
	if err := compareWindowsSecurityBindings(verifier.binding, got); err != nil {
		return fmt.Errorf("%s security descriptor contract changed", description)
	}
	return nil
}

func compareWindowsSecurityBindings(want, got windowsSecurityBinding) error {
	if err := validateWindowsSecurityBinding(want); err != nil {
		return fmt.Errorf("wanted Windows security descriptor binding is invalid: %w", err)
	}
	if err := validateWindowsSecurityBinding(got); err != nil {
		return fmt.Errorf("captured Windows security descriptor binding is invalid: %w", err)
	}
	if want.metadata&windowsSecurityBindingTierMask !=
		got.metadata&windowsSecurityBindingTierMask {
		return fmt.Errorf("Windows security descriptor binding tier changed")
	}
	if got.digest != want.digest {
		return fmt.Errorf("Windows security descriptor binding digest changed")
	}
	if want.metadata&windowsSecurityBindingDACLAutoInheritedRequired != 0 &&
		got.metadata&windowsSecurityBindingDACLAutoInheritedRequired == 0 {
		return fmt.Errorf("Windows security descriptor auto-inherited state regressed")
	}
	return nil
}

func (verifier *windowsSecurityBindingVerifier) close() error {
	if verifier == nil || verifier.scope == nil {
		return nil
	}
	err := verifier.scope.close()
	verifier.scope = nil
	return err
}

func writeWindowsSecurityContractSID(
	digest hash.Hash,
	sid *windows.SID,
	description string,
) error {
	size := sid.Len()
	if size <= 0 || size > windowsSecurityContractMaxSIDBytes {
		return fmt.Errorf("%s SID size %d is invalid", description, size)
	}
	writeWindowsSecurityContractUint32(digest, uint32(size))
	_, _ = digest.Write(unsafe.Slice((*byte)(unsafe.Pointer(sid)), size))
	return nil
}

func writeWindowsSecurityContractACL(digest hash.Hash, contract windowsDACLContract) {
	writeWindowsSecurityContractUint32(digest, uint32(contract.state))
	writeWindowsSecurityContractUint32(digest, uint32(contract.revision))
	writeWindowsSecurityContractUint32(digest, uint32(len(contract.aces)))
	for _, ace := range contract.aces {
		writeWindowsSecurityContractUint32(digest, uint32(len(ace)))
		_, _ = digest.Write(ace)
	}
}

func writeWindowsSecurityContractUint32(digest hash.Hash, value uint32) {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}

func windowsSecurityBindingFullControlMask() windows.SECURITY_DESCRIPTOR_CONTROL {
	return windows.SE_OWNER_DEFAULTED |
		windows.SE_GROUP_DEFAULTED |
		windows.SE_DACL_PRESENT |
		windows.SE_DACL_DEFAULTED |
		windows.SE_DACL_AUTO_INHERIT_REQ |
		windows.SE_DACL_AUTO_INHERITED |
		windows.SE_DACL_PROTECTED |
		windows.SE_SACL_PRESENT |
		windows.SE_SACL_DEFAULTED |
		windows.SE_SACL_AUTO_INHERIT_REQ |
		windows.SE_SACL_AUTO_INHERITED |
		windows.SE_SACL_PROTECTED |
		windows.SE_RM_CONTROL_VALID
}

func prepareWindowsReplacementSecurity(
	staged,
	target string,
) (*windowsReplacementSecurityState, error) {
	scope, full, err := beginWindowsReplacementSecurityPrivileges()
	if err != nil {
		return nil, err
	}
	tier := windowsOrdinarySecurityTier
	if full {
		tier = windowsFullSecurityTier
	}
	state, unavailable, err := prepareWindowsReplacementSecurityTier(
		staged,
		target,
		tier,
		scope,
	)
	if !unavailable {
		return state, err
	}
	return prepareWindowsReplacementOrdinarySecurity(staged, target)
}

func prepareWindowsReplacementOrdinarySecurity(
	staged,
	target string,
) (*windowsReplacementSecurityState, error) {
	state, _, err := prepareWindowsReplacementSecurityTier(
		staged,
		target,
		windowsOrdinarySecurityTier,
		nil,
	)
	return state, err
}

func prepareWindowsReplacementSecurityTier(
	staged,
	target string,
	tier windowsSecurityTier,
	scope *windowsReplacementPrivilegeScope,
) (*windowsReplacementSecurityState, bool, error) {
	state := &windowsReplacementSecurityState{
		tier:        tier,
		scope:       scope,
		target:      windows.InvalidHandle,
		staged:      windows.InvalidHandle,
		stagedOwner: windows.InvalidHandle,
	}
	fail := func(operationErr error) (*windowsReplacementSecurityState, bool, error) {
		unavailable := tier.full && isWindowsCompleteSecurityUnavailable(operationErr)
		if closeErr := state.close(); closeErr != nil {
			operationErr = errors.Join(operationErr, closeErr)
			unavailable = false
		}
		return nil, unavailable, operationErr
	}

	var err error
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

	state.sourceDescriptor, err = captureWindowsReplacementDescriptor(state.target, tier.information)
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
	return state, false, nil
}

func isWindowsCompleteSecurityUnavailable(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) ||
		errors.Is(err, windows.ERROR_NOT_SUPPORTED)
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
	descriptor, err := captureWindowsReplacementDescriptor(
		state.stagedSecurityHandle(),
		state.tier.information,
	)
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

func (state *windowsReplacementSecurityState) closeStagedForRollback() error {
	var errs []error
	if state.stagedOwner != windows.InvalidHandle {
		errs = append(errs, windows.CloseHandle(state.stagedOwner))
		state.stagedOwner = windows.InvalidHandle
	}
	if state.staged != windows.InvalidHandle {
		errs = append(errs, windows.CloseHandle(state.staged))
		state.staged = windows.InvalidHandle
	}
	return errors.Join(errs...)
}

func validateWindowsSecurityDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	if descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("security descriptor is absent or invalid")
	}
	return nil
}

func compareWindowsSecurityDescriptors(want, got *windows.SECURITY_DESCRIPTOR, full bool) error {
	if !full {
		return compareWindowsOrdinarySecurityDescriptors(want, got)
	}
	wantString := want.String()
	gotString := got.String()
	if wantString == "" || gotString == "" {
		return fmt.Errorf("complete security descriptor cannot be represented")
	}
	if wantString != gotString {
		return fmt.Errorf("complete security descriptor changed")
	}
	wantControl, _, err := want.Control()
	if err != nil {
		return fmt.Errorf("read source descriptor control: %w", err)
	}
	gotControl, _, err := got.Control()
	if err != nil {
		return fmt.Errorf("read replacement descriptor control: %w", err)
	}
	relevantControl := windowsSecurityBindingFullControlMask()
	if wantControl&relevantControl != gotControl&relevantControl {
		return fmt.Errorf("complete security descriptor inheritance or defaulting state changed")
	}
	if wantControl&windows.SE_RM_CONTROL_VALID != 0 {
		wantRMControl, err := want.RMControl()
		if err != nil {
			return fmt.Errorf("read source descriptor resource manager control: %w", err)
		}
		gotRMControl, err := got.RMControl()
		if err != nil {
			return fmt.Errorf("read replacement descriptor resource manager control: %w", err)
		}
		if wantRMControl != gotRMControl {
			return fmt.Errorf(
				"complete security descriptor resource manager control changed: got %d, want %d",
				gotRMControl,
				wantRMControl,
			)
		}
	}
	return nil
}

type windowsDACLState uint8

const (
	windowsDACLAbsent windowsDACLState = iota
	windowsDACLNull
	windowsDACLPresent
)

type windowsDACLContract struct {
	state    windowsDACLState
	revision byte
	aces     [][]byte
}

func compareWindowsOrdinarySecurityDescriptors(
	want,
	got *windows.SECURITY_DESCRIPTOR,
) error {
	wantOwner, _, err := want.Owner()
	if err != nil || wantOwner == nil || !wantOwner.IsValid() {
		return fmt.Errorf("read source owner SID: %w", descriptorComponentError(err))
	}
	gotOwner, _, err := got.Owner()
	if err != nil || gotOwner == nil || !gotOwner.IsValid() {
		return fmt.Errorf("read replacement owner SID: %w", descriptorComponentError(err))
	}
	if !windows.EqualSid(wantOwner, gotOwner) {
		return fmt.Errorf(
			"owner SID changed: got %s, want %s",
			gotOwner.String(),
			wantOwner.String(),
		)
	}

	wantGroup, _, err := want.Group()
	if err != nil || wantGroup == nil || !wantGroup.IsValid() {
		return fmt.Errorf("read source primary group SID: %w", descriptorComponentError(err))
	}
	gotGroup, _, err := got.Group()
	if err != nil || gotGroup == nil || !gotGroup.IsValid() {
		return fmt.Errorf("read replacement primary group SID: %w", descriptorComponentError(err))
	}
	if !windows.EqualSid(wantGroup, gotGroup) {
		return fmt.Errorf(
			"primary group SID changed: got %s, want %s",
			gotGroup.String(),
			wantGroup.String(),
		)
	}

	wantDACL, err := readWindowsDACLContract(want, "source")
	if err != nil {
		return err
	}
	gotDACL, err := readWindowsDACLContract(got, "replacement")
	if err != nil {
		return err
	}
	if wantDACL.state != gotDACL.state {
		return fmt.Errorf(
			"DACL state changed: got %s, want %s",
			gotDACL.state,
			wantDACL.state,
		)
	}
	if wantDACL.revision != gotDACL.revision {
		return fmt.Errorf(
			"DACL revision changed: got %d, want %d",
			gotDACL.revision,
			wantDACL.revision,
		)
	}
	if len(wantDACL.aces) != len(gotDACL.aces) {
		return fmt.Errorf(
			"DACL ACE count changed: got %d, want %d",
			len(gotDACL.aces),
			len(wantDACL.aces),
		)
	}
	for index := range wantDACL.aces {
		if !bytes.Equal(wantDACL.aces[index], gotDACL.aces[index]) {
			return fmt.Errorf(
				"DACL ACE %d changed: got %s, want %s",
				index,
				describeWindowsACE(gotDACL.aces[index]),
				describeWindowsACE(wantDACL.aces[index]),
			)
		}
	}

	wantControl, _, err := want.Control()
	if err != nil {
		return fmt.Errorf("read source descriptor control: %w", err)
	}
	gotControl, _, err := got.Control()
	if err != nil {
		return fmt.Errorf("read replacement descriptor control: %w", err)
	}
	wantProtected := wantControl&windows.SE_DACL_PROTECTED != 0
	gotProtected := gotControl&windows.SE_DACL_PROTECTED != 0
	if wantProtected != gotProtected {
		return fmt.Errorf(
			"DACL protection changed: got protected=%t, want protected=%t",
			gotProtected,
			wantProtected,
		)
	}
	wantAutoInherited := wantControl&windows.SE_DACL_AUTO_INHERITED != 0
	gotAutoInherited := gotControl&windows.SE_DACL_AUTO_INHERITED != 0
	if wantAutoInherited && !gotAutoInherited {
		return fmt.Errorf(
			"DACL auto-inherited state changed: got auto-inherited=false, want auto-inherited=true",
		)
	}
	// SetSecurityInfo can impose Windows' current inheritance model and add
	// SE_DACL_AUTO_INHERITED. That one-way normalization is not an access
	// change when protection and every ordered ACE, including INHERITED_ACE,
	// remain identical.
	return nil
}

func readWindowsDACLContract(
	descriptor *windows.SECURITY_DESCRIPTOR,
	description string,
) (windowsDACLContract, error) {
	dacl, _, err := descriptor.DACL()
	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND):
		return windowsDACLContract{state: windowsDACLAbsent}, nil
	case err != nil:
		return windowsDACLContract{}, fmt.Errorf("read %s DACL: %w", description, err)
	case dacl == nil:
		return windowsDACLContract{state: windowsDACLNull}, nil
	}

	contract := windowsDACLContract{
		state:    windowsDACLPresent,
		revision: *(*byte)(unsafe.Pointer(dacl)),
		aces:     make([][]byte, 0, dacl.AceCount),
	}
	totalBytes := 0
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return windowsDACLContract{}, fmt.Errorf(
				"read %s DACL ACE %d: %w",
				description,
				index,
				err,
			)
		}
		if ace == nil || ace.Header.AceSize < uint16(unsafe.Sizeof(windows.ACE_HEADER{})) {
			return windowsDACLContract{}, fmt.Errorf(
				"%s DACL ACE %d is absent or truncated",
				description,
				index,
			)
		}
		totalBytes += int(ace.Header.AceSize)
		if totalBytes > windowsSecurityContractMaxACLBytes {
			return windowsDACLContract{}, fmt.Errorf(
				"%s DACL exceeds the %d-byte security contract limit",
				description,
				windowsSecurityContractMaxACLBytes,
			)
		}
		raw := unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize))
		contract.aces = append(contract.aces, append([]byte(nil), raw...))
	}
	return contract, nil
}

func readWindowsSACLContract(
	descriptor *windows.SECURITY_DESCRIPTOR,
	description string,
) (windowsDACLContract, error) {
	sacl, _, err := descriptor.SACL()
	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND):
		return windowsDACLContract{state: windowsDACLAbsent}, nil
	case err != nil:
		return windowsDACLContract{}, fmt.Errorf("read %s SACL: %w", description, err)
	case sacl == nil:
		return windowsDACLContract{state: windowsDACLNull}, nil
	}

	contract := windowsDACLContract{
		state:    windowsDACLPresent,
		revision: *(*byte)(unsafe.Pointer(sacl)),
		aces:     make([][]byte, 0, sacl.AceCount),
	}
	totalBytes := 0
	for index := uint32(0); index < uint32(sacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(sacl, index, &ace); err != nil {
			return windowsDACLContract{}, fmt.Errorf(
				"read %s SACL ACE %d: %w",
				description,
				index,
				err,
			)
		}
		if ace == nil || ace.Header.AceSize < uint16(unsafe.Sizeof(windows.ACE_HEADER{})) {
			return windowsDACLContract{}, fmt.Errorf(
				"%s SACL ACE %d is absent or truncated",
				description,
				index,
			)
		}
		totalBytes += int(ace.Header.AceSize)
		if totalBytes > windowsSecurityContractMaxACLBytes {
			return windowsDACLContract{}, fmt.Errorf(
				"%s SACL exceeds the %d-byte security contract limit",
				description,
				windowsSecurityContractMaxACLBytes,
			)
		}
		raw := unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize))
		contract.aces = append(contract.aces, append([]byte(nil), raw...))
	}
	return contract, nil
}

func (state windowsDACLState) String() string {
	switch state {
	case windowsDACLAbsent:
		return "absent"
	case windowsDACLNull:
		return "null"
	case windowsDACLPresent:
		return "present"
	default:
		return fmt.Sprintf("unknown(%d)", state)
	}
}

func describeWindowsACE(ace []byte) string {
	if len(ace) < int(unsafe.Sizeof(windows.ACE_HEADER{})) {
		return fmt.Sprintf("truncated bytes=%x", ace)
	}
	header := (*windows.ACE_HEADER)(unsafe.Pointer(&ace[0]))
	return fmt.Sprintf(
		"type=%d flags=0x%02x size=%d bytes=%x",
		header.AceType,
		header.AceFlags,
		header.AceSize,
		ace,
	)
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
	closeToken    windowsCloseTokenFunc
	hadPrevious   bool
	installed     bool
	active        bool
}

func beginWindowsReplacementPrivileges() (*windowsReplacementPrivilegeScope, bool, error) {
	return beginWindowsReplacementPrivilegesWithTokenOpen(
		windows.OpenThreadToken,
		windows.OpenProcessToken,
	)
}

type windowsOpenThreadTokenFunc func(
	thread windows.Handle,
	access uint32,
	openAsSelf bool,
	token *windows.Token,
) error

type windowsOpenProcessTokenFunc func(
	process windows.Handle,
	access uint32,
	token *windows.Token,
) error

type windowsCloseTokenFunc func(token windows.Token) error

func beginWindowsReplacementPrivilegesWithTokenOpen(
	openThreadToken windowsOpenThreadTokenFunc,
	openProcessToken windowsOpenProcessTokenFunc,
) (*windowsReplacementPrivilegeScope, bool, error) {
	return beginWindowsReplacementPrivilegesWithTokenOpenAndClose(
		openThreadToken,
		openProcessToken,
		func(token windows.Token) error {
			return token.Close()
		},
	)
}

func beginWindowsReplacementPrivilegesWithTokenOpenAndClose(
	openThreadToken windowsOpenThreadTokenFunc,
	openProcessToken windowsOpenProcessTokenFunc,
	closeToken windowsCloseTokenFunc,
) (*windowsReplacementPrivilegeScope, bool, error) {
	runtime.LockOSThread()
	scope := &windowsReplacementPrivilegeScope{
		closeToken: closeToken,
		active:     true,
	}
	fallback := func() (*windowsReplacementPrivilegeScope, bool, error) {
		if err := scope.close(); err != nil {
			return nil, false, fmt.Errorf("restore optional Windows security privilege scope: %w", err)
		}
		return nil, false, nil
	}
	var source windows.Token
	if err := openThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE,
		false,
		&scope.previousToken,
	); err == nil {
		scope.hadPrevious = true
		source = scope.previousToken
	} else if errors.Is(err, windows.ERROR_NO_TOKEN) {
		if err := openProcessToken(
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
	enabled, err := windowsTokenPrivilegeEnabled(token, luid)
	if err != nil {
		return err
	}
	if !enabled {
		return windows.ERROR_NOT_ALL_ASSIGNED
	}
	return nil
}

func windowsTokenPrivilegeEnabled(token windows.Token, want windows.LUID) (bool, error) {
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return false, fmt.Errorf("size adjusted token privileges: %w", err)
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(
		token,
		windows.TokenPrivileges,
		&buffer[0],
		uint32(len(buffer)),
		&size,
	); err != nil {
		return false, fmt.Errorf("read adjusted token privileges: %w", err)
	}
	for _, privilege := range (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0])).AllPrivileges() {
		if privilege.Luid == want {
			return privilege.Attributes&windows.SE_PRIVILEGE_ENABLED != 0, nil
		}
	}
	return false, nil
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
		errs = append(errs, scope.closeToken(scope.token))
		scope.token = 0
	}
	if scope.processToken != 0 {
		errs = append(errs, scope.closeToken(scope.processToken))
		scope.processToken = 0
	}
	if scope.previousToken != 0 {
		errs = append(errs, scope.closeToken(scope.previousToken))
		scope.previousToken = 0
	}
	scope.active = false
	runtime.UnlockOSThread()
	return errors.Join(errs...)
}
