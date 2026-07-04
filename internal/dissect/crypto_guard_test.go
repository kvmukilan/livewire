package dissect

import "testing"

func TestDetectSSH(t *testing.T) {
	if !DetectSSH([]byte("SSH-2.0-OpenSSH_9.6\r\n")) {
		t.Fatal("failed to detect SSH-2.0 banner")
	}
	if !DetectSSH([]byte("SSH-1.99-Cisco-1.25\r\n")) {
		t.Fatal("failed to detect SSH-1.99 banner")
	}
	if DetectSSH([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("HTTP misdetected as SSH")
	}
	sec := AppSecurity{SSH: true}
	if sec.Recoverable() {
		t.Fatal("SSH flow should be non-recoverable")
	}
	if sec.Reason() == "" {
		t.Fatal("SSH should give a reason")
	}
}

func TestDNP3SecureAuthDetection(t *testing.T) {
	// A normal READ (function 0x01) with a group-1 object is recoverable.
	normal := buildDNP3(0x44, 0x0004, 0x0001, 1, 1, 0x01, []byte{0x01, 0x00, 0x00})
	d, _, err := ParseDNP3(normal)
	if err != nil {
		t.Fatal(err)
	}
	if d.UsesSecureAuth() {
		t.Fatal("plain READ misflagged as Secure Auth")
	}

	// An application payload whose first object group is 120 is Secure Auth.
	// UserData layout: transport(1) appctrl(1) func(1) then object group(1)...
	saObjects := []byte{dnp3ObjectGroup120, 0x01, 0x00} // g120 v1 (challenge)
	sa := buildDNP3(0x44, 0x0004, 0x0001, 2, 2, 0x83, saObjects)
	d2, _, err := ParseDNP3(sa)
	if err != nil {
		t.Fatal(err)
	}
	if !d2.UsesSecureAuth() {
		t.Fatalf("g120 object not detected as Secure Auth (UserData=% x)", d2.UserData)
	}
	sec := AppSecurity{DNP3SecureAuth: true}
	if sec.Recoverable() || sec.Reason() == "" {
		t.Fatal("DNP3-SA flow should be non-recoverable with a reason")
	}
}
