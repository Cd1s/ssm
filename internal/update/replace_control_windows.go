//go:build windows

package update

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsControlFileFullAccess = windows.STANDARD_RIGHTS_REQUIRED |
	windows.SYNCHRONIZE |
	0x1ff

type windowsControlSecurityPolicy struct {
	owner      *windows.SID
	group      *windows.SID
	descriptor *windows.SECURITY_DESCRIPTOR
}

func newWindowsControlSecurityPolicy() (*windowsControlSecurityPolicy, error) {
	token := windows.GetCurrentThreadEffectiveToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read Windows updater identity: %w", err)
	}
	primaryGroup, err := token.GetTokenPrimaryGroup()
	if err != nil {
		return nil, fmt.Errorf("read Windows updater primary group: %w", err)
	}
	owner, err := user.User.Sid.Copy()
	if err != nil {
		return nil, fmt.Errorf("copy Windows updater identity: %w", err)
	}
	group, err := primaryGroup.PrimaryGroup.Copy()
	if err != nil {
		return nil, fmt.Errorf("copy Windows updater primary group: %w", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + owner.String() +
			"G:" + group.String() +
			"D:P(A;;FA;;;" + owner.String() + ")",
	)
	if err != nil {
		return nil, fmt.Errorf("build owner-only Windows control-file security descriptor: %w", err)
	}
	return &windowsControlSecurityPolicy{
		owner:      owner,
		group:      group,
		descriptor: descriptor,
	}, nil
}

func (policy *windowsControlSecurityPolicy) attributes() *windows.SecurityAttributes {
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: policy.descriptor,
	}
}

func (policy *windowsControlSecurityPolicy) validate(
	handle windows.Handle,
	description string,
) error {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read %s security policy: %w", description, err)
	}
	if descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("%s security policy descriptor is absent or invalid", description)
	}
	owner, ownerDefaulted, err := descriptor.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s security policy owner is absent or invalid: %w", description, descriptorComponentError(err))
	}
	if ownerDefaulted || !windows.EqualSid(owner, policy.owner) {
		return fmt.Errorf("%s security policy owner is not the current updater identity", description)
	}
	group, groupDefaulted, err := descriptor.Group()
	if err != nil || group == nil {
		return fmt.Errorf("%s security policy primary group is absent or invalid: %w", description, descriptorComponentError(err))
	}
	if groupDefaulted || !windows.EqualSid(group, policy.group) {
		return fmt.Errorf("%s security policy primary group is unexpected", description)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read %s security policy control: %w", description, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s security policy DACL is inherited or unprotected", description)
	}
	if control&(windows.SE_DACL_DEFAULTED|
		windows.SE_DACL_AUTO_INHERIT_REQ|
		windows.SE_DACL_AUTO_INHERITED) != 0 {
		return fmt.Errorf("%s security policy DACL has inherited or defaulted control", description)
	}
	dacl, daclDefaulted, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s security policy DACL is absent or invalid: %w", description, descriptorComponentError(err))
	}
	if daclDefaulted || dacl.AceCount != 1 {
		return fmt.Errorf("%s security policy DACL is not owner-only", description)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return fmt.Errorf("read %s security policy ACE: %w", description, err)
	}
	if ace == nil ||
		ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Header.AceFlags != 0 ||
		ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart))+8 ||
		ace.Mask != windowsControlFileFullAccess {
		return fmt.Errorf("%s security policy ACE is not owner-only full access", description)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.IsValid() || !windows.EqualSid(aceSID, policy.owner) {
		return fmt.Errorf("%s security policy ACE trustee is not the current updater identity", description)
	}
	runtime.KeepAlive(policy)
	return nil
}
