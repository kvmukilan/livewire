package tlsreplay

import (
	"encoding/binary"
	"strings"
	"testing"
)

func tlsRecordForTest(typ byte, body []byte) []byte {
	out := []byte{typ, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(out[3:5], uint16(len(body)))
	return append(out, body...)
}

func TestFirstHandshakeReassemblesAcrossRecords(t *testing.T) {
	body := make([]byte, 34)
	body[0], body[1] = 3, 3
	for i := 2; i < len(body); i++ {
		body[i] = byte(i)
	}
	message := append([]byte{1, 0, 0, byte(len(body))}, body...)
	stream := append(tlsRecordForTest(22, message[:11]), tlsRecordForTest(22, message[11:])...)
	got, err := firstHandshake(stream, 1)
	if err != nil || string(got) != string(body) {
		t.Fatalf("reassembled handshake=%x err=%v", got, err)
	}
}

func TestFirstHandshakeRejectsTruncatedMessage(t *testing.T) {
	stream := tlsRecordForTest(22, []byte{1, 0, 0, 10, 1, 2})
	if _, err := firstHandshake(stream, 1); err == nil || !strings.Contains(err.Error(), "truncated handshake body") {
		t.Fatalf("truncated handshake error=%v", err)
	}
}

func TestServerHelloRejectsMalformedExtensions(t *testing.T) {
	body := make([]byte, 2+32+1+2+1+2)
	body[0], body[1] = 3, 3
	p := 2 + 32
	body[p] = 0
	p++
	binary.BigEndian.PutUint16(body[p:p+2], 0x1301)
	p += 2
	body[p] = 0
	p++
	binary.BigEndian.PutUint16(body[p:p+2], 4) // claims bytes not present
	message := append([]byte{2, 0, 0, byte(len(body))}, body...)
	if _, _, err := serverHelloParams(tlsRecordForTest(22, message)); err == nil || !strings.Contains(err.Error(), "extension block") {
		t.Fatalf("malformed extensions error=%v", err)
	}
}
