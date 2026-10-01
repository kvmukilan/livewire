package recording

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

func TestPrivateWindowsACL(t *testing.T) {
	dir := t.TempDir()
	if err := restrictDirectory(dir); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := RestrictFile(f); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, f.Name()} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		control, _, err := sd.Control()
		if err != nil {
			t.Fatal(err)
		}
		acl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 || acl == nil || acl.AceCount != 1 {
			t.Fatalf("secret ACL is not protected and owner-only: %s", sd.String())
		}
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, 0, &ace); err != nil {
			t.Fatal(err)
		}
		// SDDL may abbreviate a well-known SID (e.g. LA for the local admin).
		// Compare the actual ACE identity, not its formatted representation.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
			t.Fatalf("secret ACL grants another principal: %s", sd.String())
		}
	}
}
