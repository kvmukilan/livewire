package tlsreplay

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func helloExtension(kind uint16, data []byte) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], kind)
	binary.BigEndian.PutUint16(b[2:], uint16(len(data)))
	return append(b, data...)
}

func helloSNI(name string) []byte {
	b := make([]byte, 5)
	binary.BigEndian.PutUint16(b[:2], uint16(3+len(name)))
	binary.BigEndian.PutUint16(b[3:5], uint16(len(name)))
	return helloExtension(0, append(b, name...))
}

func helloBody(extensions ...[]byte) []byte {
	b := []byte{3, 3}
	b = append(b, bytes.Repeat([]byte{0x91}, 32)...)
	b = append(b, 0, 0, 2, 0x13, 1, 1, 0) // no session ID, one cipher, null compression
	var exts []byte
	for _, extension := range extensions {
		exts = append(exts, extension...)
	}
	b = append(b, byte(len(exts)>>8), byte(len(exts)))
	return append(b, exts...)
}

func helloStream(body []byte, cuts ...int) []byte {
	message := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	var out []byte
	start := 0
	for _, end := range append(cuts, len(message)) {
		out = append(out, tlsRecordForTest(22, message[start:end])...)
		start = end
	}
	return out
}

func TestParseClientHelloSplitRecordsAndPublicMetadata(t *testing.T) {
	body := helloBody(helloSNI("capture.example"),
		helloExtension(16, []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}),
		helloExtension(43, []byte{6, 0x1a, 0x1a, 3, 4, 3, 3}),
		helloExtension(35, []byte("captured-session-ticket-must-not-escape")))
	unsplit, err := ParseClientHello(helloStream(body))
	if err != nil {
		t.Fatal(err)
	}
	for _, cuts := range [][]int{{1, 3, 4, 5}, {38, 42}, {len(body) + 3}} {
		got, err := ParseClientHello(helloStream(body, cuts...))
		if err != nil || !reflect.DeepEqual(got, unsplit) {
			t.Fatalf("split %v changed public negotiation metadata: got=%+v err=%v", cuts, got, err)
		}
	}
	if unsplit.ServerName != "capture.example" || !reflect.DeepEqual(unsplit.ALPN, []string{"h2", "http/1.1"}) ||
		!reflect.DeepEqual(unsplit.OfferedVersions, []uint16{0x1a1a, tls.VersionTLS13, tls.VersionTLS12}) ||
		!reflect.DeepEqual(unsplit.UsedVersions, []uint16{tls.VersionTLS13, tls.VersionTLS12}) ||
		unsplit.SHA256 != publicHash(body) || unsplit.RandomSHA256 != publicHash(body[2:34]) {
		t.Fatalf("incorrect public metadata: %+v", unsplit)
	}
	encoded, err := json.Marshal(unsplit)
	if err != nil || bytes.Contains(encoded, []byte("captured-session-ticket")) || bytes.Contains(encoded, bytes.Repeat([]byte("91"), 32)) {
		t.Fatal("metadata exposed session ticket or raw client random")
	}
}

func TestParseClientHelloRejectsMalformedNegotiation(t *testing.T) {
	valid := helloBody(helloSNI("capture.example"))
	mutate := func(at int, value byte) []byte { b := bytes.Clone(valid); b[at] = value; return b }
	for _, test := range []struct {
		name string
		body []byte
	}{
		{"short body", valid[:37]},
		{"oversized session ID", mutate(34, 33)},
		{"invalid legacy version", mutate(0, 5)},
		{"empty ciphers", mutate(36, 0)},
		{"odd ciphers", mutate(36, 3)},
		{"empty compression", mutate(39, 0)},
		{"no null compression", mutate(40, 1)},
		{"truncated extensions", valid[:len(valid)-1]},
		{"extension trailing byte", append(bytes.Clone(valid), 0)},
		{"duplicate SNI", helloBody(helloSNI("one.example"), helloSNI("two.example"))},
		{"duplicate unknown extension", helloBody(helloExtension(123, nil), helloExtension(123, nil))},
		{"truncated SNI", helloBody(helloExtension(0, []byte{0, 2, 0, 0}))},
		{"SNI IP", helloBody(helloSNI("127.0.0.1"))},
		{"SNI terminal control", helloBody(helloSNI("bad\n.example"))},
		{"SNI trailing dot", helloBody(helloSNI("example."))},
		{"SNI empty label", helloBody(helloSNI("a..example"))},
		{"SNI oversized label", helloBody(helloSNI(strings.Repeat("x", 64) + ".example"))},
		{"empty ALPN", helloBody(helloExtension(16, []byte{0, 0}))},
		{"ALPN length mismatch", helloBody(helloExtension(16, []byte{0, 3, 1, 'x'}))},
		{"empty ALPN protocol", helloBody(helloExtension(16, []byte{0, 1, 0}))},
		{"truncated ALPN protocol", helloBody(helloExtension(16, []byte{0, 2, 2, 'x'}))},
		{"oversized ALPN", helloBody(helloExtension(16, bytes.Repeat([]byte{1}, 4097)))},
		{"odd supported versions", helloBody(helloExtension(43, []byte{1, 3}))},
		{"truncated supported versions", helloBody(helloExtension(43, []byte{4, 3, 4}))},
		{"duplicate supported version", helloBody(helloExtension(43, []byte{4, 3, 4, 3, 4}))},
		{"only obsolete versions", helloBody(helloExtension(43, []byte{2, 3, 2}))},
		{"ECH hidden identity", helloBody(helloExtension(0xfe0d, []byte{0}))},
		{"TLS 1.3 incorrect legacy version", func() []byte {
			b := helloBody(helloExtension(43, []byte{2, 3, 4}))
			b[1] = 2
			return b
		}()},
		{"TLS 1.3 multiple compression methods", func() []byte {
			b := helloBody(helloExtension(43, []byte{2, 3, 4}))
			b[39] = 2
			return append(append(bytes.Clone(b[:41]), 1), b[41:]...)
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseClientHello(helloStream(test.body))
			if err == nil || got != nil {
				t.Fatalf("malformed negotiation accepted: %+v, %v", got, err)
			}
		})
	}
	stream := helloStream(valid, 2)
	for n := 0; n < len(stream); n++ {
		if got, err := ParseClientHello(stream[:n]); err == nil || got != nil {
			t.Fatalf("accepted truncated record prefix %d", n)
		}
	}
}

func TestParseClientHelloBoundsOpeningAndIgnoresCiphertextTail(t *testing.T) {
	hello := helloStream(helloBody(helloSNI("capture.example")))
	want, err := ParseClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	// The handshake-only path must not build a record index for unrelated
	// ciphertext. A large tail, even one that is not a complete record, cannot
	// alter the public negotiation inputs extracted from the complete hello.
	tail := bytes.Repeat([]byte{0, 0, 0, 0, 0}, 1<<18)
	tail = append(tail, 0)
	got, err := ParseClientHello(append(bytes.Clone(hello), tail...))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("later ciphertext affected opening hello: %+v, %v", got, err)
	}
	for _, stream := range [][]byte{
		bytes.Repeat(tlsRecordForTest(22, nil), maxClientHelloBytes/5+1),
		tlsRecordForTest(22, bytes.Repeat([]byte{1}, 16385)),
		tlsRecordForTest(22, []byte{1, 0xff, 0xff, 0xff}),
		tlsRecordForTest(22, []byte{2, 0, 0, 0}),
		tlsRecordForTest(23, []byte{1, 0, 0, 0}),
	} {
		if got, err := ParseClientHello(stream); err == nil || got != nil {
			t.Fatal("unbounded or invalid opening records were accepted")
		}
	}
}

func TestParseClientHelloTLS12LegacyAndTLS13Only(t *testing.T) {
	legacy := helloBody()
	legacy = legacy[:len(legacy)-2] // TLS 1.2 permits absent extensions
	got, err := ParseClientHello(helloStream(legacy))
	if err != nil || !reflect.DeepEqual(got.UsedVersions, []uint16{tls.VersionTLS12}) || got.ServerName != "" || len(got.ALPN) != 0 {
		t.Fatalf("legacy TLS 1.2 negotiation: %+v, %v", got, err)
	}
	got, err = ParseClientHello(helloStream(helloBody(helloExtension(43, []byte{2, 3, 4}))))
	if err != nil || !reflect.DeepEqual(got.UsedVersions, []uint16{tls.VersionTLS13}) {
		t.Fatalf("TLS 1.3-only offer broadened: %+v, %v", got, err)
	}
}
