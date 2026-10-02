package protofuzz

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// Defects are misbehaviours a MockTarget can be asked to exhibit. They exist for
// two jobs: letting the test suite prove the engine catches a specific fault, and
// giving somebody a target to point 'livewire fuzz' at before they have a device
// to test. Every one of them is a real pattern seen in Modbus stacks.
type Defects struct {
	// TrustLengthField serves a frame whose MBAP length disagrees with the bytes
	// that actually arrived, instead of discarding it.
	TrustLengthField bool
	// SkipQuantityCheck serves a read whose quantity is over the spec ceiling.
	SkipQuantityCheck bool
	// DontEchoTxID replies with a transaction id the client never sent.
	DontEchoTxID bool
	// BadProtocolID replies with a nonzero protocol id.
	BadProtocolID bool
	// WedgeAfter stops answering anything once this many requests have arrived,
	// standing in for a device that has fallen over.
	WedgeAfter int

	// TrustBadCRC answers a DNP3 frame whose link-header or data-block CRC does
	// not hold up, instead of discarding it. DNP3 only.
	TrustBadCRC bool
}

// For a DNP3 target the shared fields carry the nearest equivalent meaning:
// TrustLengthField answers a frame whose LEN octet disagrees with what arrived,
// DontEchoTxID replies with the wrong application sequence, and WedgeAfter behaves
// identically. SkipQuantityCheck and BadProtocolID are Modbus-only.

// DefectByName maps the -demo-defect flag onto a Defects value. "none" is a
// conforming server, which is the more useful demo of the two: it shows the
// classifier staying quiet when there is nothing to report.
func DefectByName(name string) (Defects, error) {
	switch name {
	case "none", "":
		return Defects{}, nil
	case "trust-length":
		return Defects{TrustLengthField: true}, nil
	case "skip-quantity-check":
		return Defects{SkipQuantityCheck: true}, nil
	case "no-txid-echo":
		return Defects{DontEchoTxID: true}, nil
	case "bad-protocol-id":
		return Defects{BadProtocolID: true}, nil
	case "wedge":
		return Defects{WedgeAfter: 40}, nil
	case "trust-bad-crc":
		return Defects{TrustBadCRC: true}, nil
	}
	return Defects{}, fmt.Errorf("unknown defect %q (try none, trust-length, "+
		"skip-quantity-check, no-txid-echo, bad-protocol-id, wedge, trust-bad-crc)", name)
}

// MockTarget is a deliberately conforming Modbus/TCP server with optional
// defects. It is not a device simulator: it serves a 256-register data model and
// the function codes the seed corpus exercises, which is enough to tell a
// classifier that reports real faults from one that reports noise.
type MockTarget struct {
	ln      net.Listener
	defects Defects

	mu       sync.Mutex
	requests int
	regs     [256]uint16
}

// ServeMock starts a mock target on addr, which may use port 0 for an ephemeral
// port. The caller closes it.
func ServeMock(addr string, d Defects) (*MockTarget, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	m := &MockTarget{ln: ln, defects: d}
	for i := range m.regs {
		m.regs[i] = uint16(i)
	}
	go m.serve()
	return m, nil
}

// Addr is the address the target is listening on, with the port resolved.
func (m *MockTarget) Addr() string { return m.ln.Addr().String() }

// Close stops the target.
func (m *MockTarget) Close() error { return m.ln.Close() }

func (m *MockTarget) serve() {
	for {
		c, err := m.ln.Accept()
		if err != nil {
			return
		}
		go m.handleConn(c)
	}
}

func (m *MockTarget) handleConn(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 2048)
	for {
		// A real device would block waiting for the rest of a frame whose length
		// field over-claims. The deadline stands in for the watchdog that
		// eventually gives up, so nothing can hang on one frame forever.
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
			continue // connection stays open, nothing comes back
		}
		if reply := m.reply(buf[:n]); reply != nil {
			c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Write(reply); err != nil {
				return
			}
		}
	}
}

// reply builds the answer to one frame, or nil to discard it. Discarding is the
// correct response to framing the spec lets a device reject, and the target takes
// that option unless a defect says otherwise.
func (m *MockTarget) reply(f []byte) []byte {
	if len(f) < mbapHeaderLen+1 {
		return nil // too short to be an ADU
	}
	txid := binary.BigEndian.Uint16(f[0:2])
	pid := binary.BigEndian.Uint16(f[2:4])
	declared := binary.BigEndian.Uint16(f[4:6])
	unit := f[6]
	fn := f[7]
	data := f[mbapHeaderLen+1:]

	if pid != 0 {
		return nil // not Modbus/TCP
	}
	if int(declared) != len(f)-6 && !m.defects.TrustLengthField {
		return nil
	}
	if len(f) > maxADU && !m.defects.TrustLengthField {
		return nil
	}

	if m.defects.DontEchoTxID {
		txid ^= 0xffff
	}
	outPID := uint16(0)
	if m.defects.BadProtocolID {
		outPID = 0x1234
	}

	build := func(payload []byte) []byte {
		out := make([]byte, mbapHeaderLen+1+len(payload))
		binary.BigEndian.PutUint16(out[0:2], txid)
		binary.BigEndian.PutUint16(out[2:4], outPID)
		binary.BigEndian.PutUint16(out[4:6], uint16(len(payload)+2))
		out[6] = unit
		out[7] = fn
		copy(out[8:], payload)
		return out
	}
	exception := func(code byte) []byte {
		out := make([]byte, mbapHeaderLen+2)
		binary.BigEndian.PutUint16(out[0:2], txid)
		binary.BigEndian.PutUint16(out[2:4], outPID)
		binary.BigEndian.PutUint16(out[4:6], 3)
		out[6] = unit
		out[7] = fn | 0x80
		out[8] = code
		return out
	}

	switch fn {
	case 0x01, 0x02: // read coils / discrete inputs
		if len(data) < 4 {
			return exception(0x03)
		}
		start := binary.BigEndian.Uint16(data[0:2])
		qty := binary.BigEndian.Uint16(data[2:4])
		if qty < 1 || (qty > quantityCeiling[fn] && !m.defects.SkipQuantityCheck) {
			return exception(0x03)
		}
		if int(start)+int(qty) > len(m.regs) {
			return exception(0x02)
		}
		nb := int(qty+7) / 8
		return build(append([]byte{byte(nb)}, make([]byte, nb)...))

	case 0x03, 0x04: // read holding / input registers
		if len(data) < 4 {
			return exception(0x03)
		}
		start := binary.BigEndian.Uint16(data[0:2])
		qty := binary.BigEndian.Uint16(data[2:4])
		if qty < 1 || (qty > quantityCeiling[fn] && !m.defects.SkipQuantityCheck) {
			return exception(0x03)
		}
		if int(start)+int(qty) > len(m.regs) {
			return exception(0x02)
		}
		payload := []byte{byte(qty * 2)}
		m.mu.Lock()
		for i := 0; i < int(qty); i++ {
			payload = append(payload, be16(m.regs[int(start)+i])...)
		}
		m.mu.Unlock()
		return build(payload)

	case 0x05, 0x06: // write single coil / register
		if len(data) < 4 {
			return exception(0x03)
		}
		addr := binary.BigEndian.Uint16(data[0:2])
		if int(addr) >= len(m.regs) {
			return exception(0x02)
		}
		if fn == 0x06 {
			m.mu.Lock()
			m.regs[addr] = binary.BigEndian.Uint16(data[2:4])
			m.mu.Unlock()
		}
		return build(data[:4])

	case 0x0f, 0x10: // write multiple coils / registers
		if len(data) < 5 {
			return exception(0x03)
		}
		start := binary.BigEndian.Uint16(data[0:2])
		qty := binary.BigEndian.Uint16(data[2:4])
		bc := int(data[4])
		if qty < 1 || (qty > quantityCeiling[fn] && !m.defects.SkipQuantityCheck) {
			return exception(0x03)
		}
		// The byte count is redundant with the quantity; disagreement is an
		// illegal data value, and the payload must actually be that long.
		want := int(qty) * 2
		if fn == 0x0f {
			want = (int(qty) + 7) / 8
		}
		if bc != want || len(data)-5 < bc {
			return exception(0x03)
		}
		if int(start)+int(qty) > len(m.regs) {
			return exception(0x02)
		}
		return build(data[:4])

	case 0x07: // read exception status
		return build([]byte{0x00})

	case 0x11: // report server id
		id := []byte("livewire-mock")
		return build(append([]byte{byte(len(id) + 1)}, append(id, 0xff)...))
	}
	return exception(0x01) // illegal function
}
