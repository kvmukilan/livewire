package recording

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		if control&windows.SE_DACL_PROTECTED == 0 || acl == nil || acl.AceCount != 1 || !strings.Contains(sd.String(), user.User.Sid.String()) {
			t.Fatalf("secret ACL is not protected and owner-only: %s", sd.String())
		}
	}
}
