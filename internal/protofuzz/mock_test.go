package protofuzz

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// mockDefects turns individual misbehaviours on. They are opt-in so a test can
// assert both halves of the contract: that the engine notices the defect it was
// given, and that it stays quiet about a server that has none.
type mockDefects struct {
	// trustLengthField serves a frame whose MBAP length disagrees with the bytes
	// that actually arrived, instead of discarding it.
	trustLengthField bool
	// skipQuantityCheck serves a read whose quantity is over the spec ceiling.
	skipQuantityCheck bool
	// dontEchoTxID replies with a transaction id the client never sent.
	dontEchoTxID bool
	// badProtocolID replies with a nonzero protocol id.
	badProtocolID bool
	// wedgeAfter stops answering anything once this many requests have arrived,
	// standing in for a device that has fallen over.
	wedgeAfter int
}

// mockServer is a deliberately conforming Modbus/TCP server with optional
// defects, used as a target in tests. It is not a full device: it serves a
// 256-register data model and the function codes the seed corpus exercises.
type mockServer struct {
	ln      net.Listener
	defects mockDefects

	mu       sync.Mutex
	requests int
	regs     [256]uint16
}

func newMockServer(t *testing.T, d mockDefects) *mockServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := &mockServer{ln: ln, defects: d}
	for i := range m.regs {
		m.regs[i] = uint16(i)
	}
	go m.serve()
	t.Cleanup(func() { ln.Close() })
	return m
}

func (m *mockServer) addr() string { return m.ln.Addr().String() }

func (m *mockServer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests
}

func (m *mockServer) serve() {
	for {
		c, err := m.ln.Accept()
		if err != nil {
			return
		}
		go m.handleConn(c)
	}
}

func (m *mockServer) handleConn(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 2048)
	for {
		// A real device would block waiting for the rest of a frame whose length
		// field over-claims. The deadline stands in for the watchdog that
		// eventually gives up, so a test cannot hang on one.
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Read(buf)
		if n == 0 || err != nil {
			return
		}
		m.mu.Lock()
		m.requests++
		wedged := m.defects.wedgeAfter > 0 && m.requests > m.defects.wedgeAfter
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
// correct response to framing the spec lets a device reject, and the mock takes
// that option unless a defect says otherwise.
func (m *mockServer) reply(f []byte) []byte {
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
	if int(declared) != len(f)-6 && !m.defects.trustLengthField {
		return nil
	}
	if len(f) > maxADU && !m.defects.trustLengthField {
		return nil
	}

	if m.defects.dontEchoTxID {
		txid ^= 0xffff
	}
	outPID := uint16(0)
	if m.defects.badProtocolID {
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
		if qty < 1 || (qty > quantityCeiling[fn] && !m.defects.skipQuantityCheck) {
			return exception(0x03)
		}
		if int(start)+int(qty) > len(m.regs) {
			return exception(0x02)
		}
		nb := int(qty+7) / 8
		payload := append([]byte{byte(nb)}, make([]byte, nb)...)
		return build(payload)

	case 0x03, 0x04: // read holding / input registers
		if len(data) < 4 {
			return exception(0x03)
		}
		start := binary.BigEndian.Uint16(data[0:2])
		qty := binary.BigEndian.Uint16(data[2:4])
		if qty < 1 || (qty > quantityCeiling[fn] && !m.defects.skipQuantityCheck) {
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
		if qty < 1 || (qty > quantityCeiling[fn] && !m.defects.skipQuantityCheck) {
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
		id := []byte("mock")
		return build(append([]byte{byte(len(id) + 1)}, append(id, 0xff)...))
	}
	return exception(0x01) // illegal function
}
