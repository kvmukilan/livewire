package recording

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func ownerACL(inherit bool) (*windows.ACL, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	flags := ""
	if inherit {
		flags = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;" + flags + ";FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	acl, _, err := sd.DACL()
	return acl, err
}

// RestrictFile applies a protected owner-only DACL; Windows chmod alone does
// not prevent other local accounts from reading TLS session secrets.
func RestrictFile(f *os.File) error {
	acl, err := ownerACL(false)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return err
	}
	// os.OpenFile does not request WRITE_DAC. Open a security handle and bind it
	// to the already-open file identity before changing permissions.
	handle, err := windows.CreateFile(name, windows.WRITE_DAC|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("open TLS artifact security handle: %w", err)
	}
	defer windows.CloseHandle(handle)
	var original, security windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &original); err != nil {
		return fmt.Errorf("read original TLS artifact identity: %w", err)
	}
	if err := windows.GetFileInformationByHandle(handle, &security); err != nil {
		return fmt.Errorf("read security handle identity: %w", err)
	}
	if original.VolumeSerialNumber != security.VolumeSerialNumber || original.FileIndexHigh != security.FileIndexHigh || original.FileIndexLow != security.FileIndexLow || security.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("TLS artifact changed while protecting it")
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("set TLS artifact owner-only ACL: %w", err)
	}
	return nil
}

func restrictDirectory(path string) error {
	acl, err := ownerACL(true)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
