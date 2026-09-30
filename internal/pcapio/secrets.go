package pcapio

import (
	"bytes"
	"fmt"
)

// MaxTLSKeyLogBytes bounds the total sensitive metadata retained from all
// PCAPNG TLS Decryption Secrets Blocks. It is independent of packet bounds.
const MaxTLSKeyLogBytes = 1 << 20

const ngSecretsTLS = 0x544c534b // TLSK, PCAPNG Decryption Secrets Block type

// TLSKeyLog returns a private copy of the TLS secrets explicitly embedded in
// this capture. Classic PCAP has no such metadata. Callers must not log, report,
// or publish these bytes; packet writers intentionally do not preserve them.
// This accessor does not imply that any secret matches a selected TLS session.
func (c Capture) TLSKeyLog() []byte { return bytes.Clone(c.tlsKeyLog) }

// String and GoString keep ordinary diagnostic formatting from exposing the
// sensitive unexported metadata (fmt otherwise traverses unexported fields).
func (c Capture) String() string {
	return fmt.Sprintf("pcapio.Capture{Records:%d, PCAPNG:%t, TLSSecrets:%t}", len(c.Records), c.PCAPNG, len(c.tlsKeyLog) > 0)
}

func (c Capture) GoString() string { return c.String() }

// TLSKeyLog returns a private copy of embedded TLS secrets read so far. A
// streaming caller must reach EOF to include blocks after the last packet.
func (nr *NgReader) TLSKeyLog() []byte { return bytes.Clone(nr.tlsKeyLog) }

func (nr *NgReader) String() string {
	if nr == nil {
		return "pcapio.NgReader(nil)"
	}
	return fmt.Sprintf("pcapio.NgReader{Interfaces:%d, TLSSecrets:%t}", len(nr.ifaces), len(nr.tlsKeyLog) > 0)
}

func (nr *NgReader) GoString() string { return nr.String() }

func (nr *NgReader) addSecrets(body []byte) error {
	if len(body) < 8 {
		return fmt.Errorf("%w: truncated decryption secrets block", ErrInvalid)
	}
	kind, size := nr.bo.Uint32(body[:4]), uint64(nr.bo.Uint32(body[4:8]))
	padded := (size + 3) &^ uint64(3)
	if padded > uint64(len(body)-8) {
		return fmt.Errorf("%w: invalid decryption secrets length", ErrInvalid)
	}
	// Options contain arbitrary user comments; validate structure without
	// retaining or including their contents in diagnostics.
	if err := nr.checkSecretsOptions(body[8+int(padded):]); err != nil {
		return err
	}
	if kind != ngSecretsTLS {
		return nil
	}
	if size > uint64(MaxTLSKeyLogBytes-len(nr.tlsKeyLog)) || int64(size)+int64(len(nr.tlsKeyLog)) > nr.limits.MaxCaptureData {
		return fmt.Errorf("%w: embedded TLS secrets exceed capture metadata budget", ErrLimit)
	}
	data := body[8 : 8+int(size)]
	// The PCAPNG TLSK format requires a terminated key-log line. Reject a
	// partial final line rather than joining it to the next block's first line.
	if len(data) > 0 && (data[len(data)-1] != '\n' || bytes.IndexByte(data, 0) >= 0) {
		return fmt.Errorf("%w: embedded TLS key log is not complete text", ErrInvalid)
	}
	nr.tlsKeyLog = append(nr.tlsKeyLog, data...)
	return nil
}

func (nr *NgReader) checkSecretsOptions(options []byte) error {
	for len(options) > 0 {
		if len(options) < 4 {
			return fmt.Errorf("%w: truncated decryption secrets option", ErrInvalid)
		}
		code, size := nr.bo.Uint16(options[:2]), int(nr.bo.Uint16(options[2:4]))
		if code == 0 {
			if size != 0 {
				return fmt.Errorf("%w: invalid decryption secrets end option", ErrInvalid)
			}
			for _, b := range options[4:] {
				if b != 0 {
					return fmt.Errorf("%w: data follows decryption secrets end option", ErrInvalid)
				}
			}
			return nil
		}
		padded := (size + 3) &^ 3
		if padded > len(options)-4 {
			return fmt.Errorf("%w: invalid decryption secrets option length", ErrInvalid)
		}
		options = options[4+padded:]
	}
	return nil
}
