package dissect

import "bytes"

// Flows whose payload can't be reproduced by TCP-faithful replay alone, so the
// tool can flag them instead of shipping bytes a live device will reject:
//
//   - SSH: fresh keys every session, so captured ciphertext never passes a new
//     handshake, and there's no TLS-style key-log format. Re-terminate with
//     credentials (build -tags ssh).
//   - DNP3 Secure Authentication (IEEE 1815 g120): challenge/response HMACs bind
//     to live nonces, so a replayed reply hits the wrong challenge and is rejected.

// AppSecurity classifies a flow's recoverability.
type AppSecurity struct {
	SSH            bool
	DNP3SecureAuth bool
}

// Recoverable reports whether replay can reproduce this flow without extra
// material (keys / credentials).
func (a AppSecurity) Recoverable() bool { return !a.SSH && !a.DNP3SecureAuth }

// Reason explains why a non-recoverable flow can't be replayed, for the CLI.
func (a AppSecurity) Reason() string {
	switch {
	case a.SSH:
		return "SSH: session-encrypted; captured ciphertext cannot pass a fresh handshake. " +
			"Re-terminate with credentials (build -tags ssh); no key-log recovery like TLS."
	case a.DNP3SecureAuth:
		return "DNP3 Secure Authentication (g120): challenge/response HMACs bind to live " +
			"nonces; a replayed reply authenticates against the wrong challenge and is rejected."
	default:
		return ""
	}
}

// DetectSSH reports whether a payload starts an SSH connection. Both peers open
// with a cleartext "SSH-<protoversion>-<softwareversion>" banner (RFC 4253 §4.2).
func DetectSSH(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte("SSH-2.0-")) || bytes.HasPrefix(payload, []byte("SSH-1.99-"))
}

// dnp3ObjectGroup120 is the IEEE 1815 Secure Authentication object group.
const dnp3ObjectGroup120 = 120

// UsesSecureAuth reports whether a DNP3 frame carries Secure Authentication
// objects (group 120). Objects begin after the transport octet and the 2-byte
// app header, so the first object's group byte is at UserData[3].
func (d DNP3) UsesSecureAuth() bool {
	if !d.HasApp || len(d.UserData) < 4 {
		return false
	}
	return d.UserData[3] == dnp3ObjectGroup120
}
