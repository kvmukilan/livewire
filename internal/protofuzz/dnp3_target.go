package protofuzz

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/kvmukilan/livewire/internal/dissect"
)

// DNP3MockTarget is a deliberately conforming DNP3 outstation with optional
// defects. It is not a device simulator -- it answers reads with an empty
// response rather than real point data -- but it enforces the framing rules a
// receiver is required to enforce, which is what tells a classifier that reports
// real deviations from one that reports noise.
type DNP3MockTarget struct {
	ln      net.Listener
	addr    uint16
	defects Defects

	mu       sync.Mutex
	requests int
}

// ServeDNP3Mock starts a mock outstation on addr (port 0 for an ephemeral port),
// answering as outstation address station. The caller closes it.
func ServeDNP3Mock(addr string, station uint16, d Defects) (*DNP3MockTarget, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	m := &DNP3MockTarget{ln: ln, addr: station, defects: d}
	go m.serve()
	return m, nil
}

// Addr is the address the target is listening on, with the port resolved.
func (m *DNP3MockTarget) Addr() string { return m.ln.Addr().String() }

// Close stops the target.
func (m *DNP3MockTarget) Close() error { return m.ln.Close() }

func (m *DNP3MockTarget) serve() {
	for {
		c, err := m.ln.Accept()
		if err != nil {
			return
		}
		go m.handleConn(c)
	}
}

func (m *DNP3MockTarget) handleConn(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 2048)
	for {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Read(buf)
		if n == 0 || err != nil {
			return
		}
		m.mu.Lock()
		m.requests++
		wedged := m.defects.WedgeAfter > 0 && m.requests > m.defects.WedgeAfter
		m.mu.Unlock()
		if wedged {
			continue
		}
		if reply := m.reply(buf[:n]); reply != nil {
			c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Write(reply); err != nil {
				return
			}
		}
	}
}

// reply builds the answer to one frame, or nil to discard it. IEEE 1815 requires a
// receiver to drop a frame whose start octets, LEN or CRCs do not hold up, and
// silence is the correct response, so that is what this does unless a defect says
// otherwise.
func (m *DNP3MockTarget) reply(f []byte) []byte {
	d, _, err := dissect.ParseDNP3(f)
	if err != nil {
		// Work out whether a defect means we answer anyway. ParseDNP3 reports CRC
		// failures and LEN problems distinctly, so each maps to its own knob.
		switch {
		case m.defects.TrustBadCRC &&
			(errorsIsAny(err, dissect.ErrDNP3HdrCRC, dissect.ErrDNP3BlockCRC)):
			// Fall through to a canned response: we cannot trust the parse, so
			// answer with sequence zero rather than echoing anything.
			return m.response(0, 0)
		case m.defects.TrustLengthField &&
			errorsIsAny(err, dissect.ErrDNP3LenField, dissect.ErrDNP3Truncated):
			return m.response(0, 0)
		}
		return nil
	}

	// A well-formed frame that is not addressed to us is not ours to answer.
	if d.Dest != m.addr {
		return nil
	}
	// PRM clear marks a secondary frame; an outstation should not treat it as a
	// request. Dropping it is correct and must not be reported as a fault.
	if d.Control&0x40 == 0 {
		return nil
	}
	if !d.HasApp {
		return nil // a transport continuation with nothing to act on yet
	}
	// A request carrying the unsolicited bit is malformed; refuse it silently.
	if d.AppUNS {
		return nil
	}

	seq := d.AppSeq
	if m.defects.DontEchoAppSeq() {
		seq = (seq + 1) & 0x0F
	}
	return m.response(seq, m.indications(d))
}

// indications reports what IEEE 1815 calls the internal indications for this
// request. An outstation does not refuse an unimplemented function with silence --
// it answers and sets IIN2.0 -- and reporting that faithfully is what gives the
// fuzzer's state feedback something to distinguish, since DNP3 otherwise has a
// single response function code for everything.
func (m *DNP3MockTarget) indications(d dissect.DNP3) uint16 {
	const (
		iin2FuncNotImplemented = 0x01
		iin2ObjectUnknown      = 0x02
	)
	var iin2 uint16
	switch d.AppFunc {
	case 0x00, 0x01, 0x14, 0x15, 0x17: // confirm, read, enable/disable unsolicited, delay measure
	default:
		iin2 |= iin2FuncNotImplemented
	}
	// The object group is the first octet after the function code.
	if len(d.UserData) >= 4 {
		switch d.UserData[3] {
		case 1, 30, 60: // binary input, analogue input, class data
		default:
			iin2 |= iin2ObjectUnknown
		}
	}
	return iin2
}

// DontEchoAppSeq reports whether the shared DontEchoTxID knob applies here; DNP3's
// equivalent of the Modbus transaction id is the application sequence.
func (d Defects) DontEchoAppSeq() bool { return d.DontEchoTxID }

// response builds a minimal DNP3 response: function 0x81 carrying the internal
// indication octets and no object data.
func (m *DNP3MockTarget) response(seq uint8, iin uint16) []byte {
	appCtl := byte(0xC0) | (seq & 0x0F) // FIR | FIN | sequence
	user := []byte{
		dnp3SingleFragment, // transport: FIR | FIN, sequence 0
		appCtl,
		0x81,                             // response
		byte(iin >> 8), byte(iin & 0xff), // internal indications
	}
	out := dissect.DNP3{
		Control:      0x44, // PRM | unconfirmed user data, DIR clear (outstation)
		Dest:         1,    // back to the master
		Source:       m.addr,
		UserData:     user,
		HasTransport: true,
		TransportFIN: true,
		TransportFIR: true,
		HasApp:       true,
		AppControl:   appCtl,
		AppFIR:       true,
		AppFIN:       true,
		AppSeq:       seq & 0x0F,
		AppFunc:      0x81,
	}
	return out.Encode()
}

// errorsIsAny reports whether err matches any of the targets. The dissector
// returns sentinel errors, so a wrapped comparison is what is wanted.
func errorsIsAny(err error, targets ...error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}
