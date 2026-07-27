//go:build windows

package privatepath

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsFileAllAccess = windows.ACCESS_MASK(
	windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff,
)

func RestrictDirectory(path string) error {
	if err := requirePathType(path, true); err != nil {
		return err
	}
	if err := setCurrentUserOnlyDACL(path, true); err != nil {
		return fmt.Errorf("restrict private directory DACL: %w", err)
	}
	return VerifyDirectory(path)
}

func VerifyDirectory(path string) error {
	if err := requirePathType(path, true); err != nil {
		return err
	}
	if err := verifyCurrentUserOnlyDACL(path, true); err != nil {
		return fmt.Errorf("verify private directory DACL: %w", err)
	}
	return nil
}

func RestrictFile(path string) error {
	if err := requirePathType(path, false); err != nil {
		return err
	}
	if err := setCurrentUserOnlyDACL(path, false); err != nil {
		return fmt.Errorf("restrict private file DACL: %w", err)
	}
	return VerifyFile(path)
}

func VerifyFile(path string) error {
	if err := requirePathType(path, false); err != nil {
		return err
	}
	if err := verifyCurrentUserOnlyDACL(path, false); err != nil {
		return fmt.Errorf("verify private file DACL: %w", err)
	}
	return nil
}

func setCurrentUserOnlyDACL(path string, directory bool) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("open current process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current token user: %w", err)
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windowsFileAllAccess,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
			},
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("build current-user DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("set current-user DACL: %w", err)
	}
	return nil
}

func verifyCurrentUserOnlyDACL(path string, directory bool) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("open current process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current token user: %w", err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}
	if descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("DACL security descriptor is absent or invalid")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read DACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("DACL is not protected from inherited access")
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read DACL entries: %w", err)
	}
	if acl == nil {
		return fmt.Errorf("DACL is nil")
	}
	if acl.AceCount != 1 {
		return fmt.Errorf("DACL has %d access entries, need exactly one", acl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		return fmt.Errorf("read DACL access entry: %w", err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return fmt.Errorf("DACL entry is not access-allowed")
	}
	if ace.Mask&windowsFileAllAccess != windowsFileAllAccess {
		return fmt.Errorf("DACL entry does not grant current-user full access")
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !sid.Equals(user.User.Sid) {
		return fmt.Errorf("DACL entry does not belong to the current user")
	}
	wantFlags := uint8(windows.NO_INHERITANCE)
	if directory {
		wantFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	if ace.Header.AceFlags != wantFlags {
		return fmt.Errorf("DACL inheritance flags are %x, need %x", ace.Header.AceFlags, wantFlags)
	}
	return nil
}

func requirePathType(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private path is a reparse link")
	}
	if directory && !info.IsDir() {
		return fmt.Errorf("private path is not a directory")
	}
	if !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("private path is not a regular file")
	}
	return nil
}
