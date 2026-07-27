//go:build windows

package privatepath

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func assertPlatformPrivacy(t *testing.T, directory, file string) {
	t.Helper()
	assertCurrentUserOnlyDACL(t, directory, true)
	assertCurrentUserOnlyDACL(t, file, false)
}

func assertCurrentUserOnlyDACL(t *testing.T, path string, directory bool) {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("open current process token: %v", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("read current token user: %v", err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("read DACL: %v", err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("read DACL control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("DACL inherits access from a parent")
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("read DACL entries: %v", err)
	}
	if acl == nil {
		t.Fatal("DACL is nil")
	}
	if acl.AceCount != 1 {
		t.Fatalf("DACL ACE count = %d, want exactly one", acl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		t.Fatalf("read DACL ACE: %v", err)
	}
	const wantFullAccess = windows.ACCESS_MASK(
		windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff,
	)
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
		ace.Mask&wantFullAccess != wantFullAccess {
		t.Fatalf("DACL ACE type/mask = %d/%x, want current-user full access", ace.Header.AceType, ace.Mask)
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !sid.Equals(user.User.Sid) {
		t.Fatalf("DACL SID = %s, want current user %s", sid, user.User.Sid)
	}
	wantFlags := uint8(0)
	if directory {
		wantFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	if ace.Header.AceFlags != wantFlags {
		t.Fatalf("DACL ACE flags = %x, want %x", ace.Header.AceFlags, wantFlags)
	}
}
