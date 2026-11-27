package tlsreplay

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecryptTLS12_ChaCha20Poly1305(t *testing.T) {
	decryptRoundTrip(t, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256})
}

func TestDecryptTLS12_CBC(t *testing.T) {
	for name, suite := range map[string]uint16{
		"AES128-SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		"AES256-SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		"AES128-SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	} {
		t.Run(name, func(t *testing.T) { decryptRoundTrip(t, tls.VersionTLS12, []uint16{suite}) })
	}
}

type recordedSession struct {
	c2s, s2c []byte
	keys     *KeyLog
}

func loadRecordedSession(t *testing.T, name string) recordedSession {
	t.Helper()
	read := func(suffix string) []byte {
		data, err := os.ReadFile(filepath.Join("testdata", name+suffix))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	keys, err := ParseKeyLog(bytes.NewReader(read(".keylog")))
	if err != nil || keys.Count() != 1 {
		t.Fatalf("key log for %s: %v", name, err)
	}
	return recordedSession{c2s: read(".c2s.bin"), s2c: read(".s2c.bin"), keys: keys}
}

func plaintextByRole(messages []AppMessage) (client, server string) {
	for _, m := range messages {
		if m.Role == FromClient {
			client += string(m.Data)
		} else {
			server += string(m.Data)
		}
	}
	return client, server
}

// Sessions recorded from OpenSSL cover what crypto/tls cannot negotiate: DHE
// key exchange, CBC with HMAC-SHA384, and encrypt-then-MAC.
func TestDecryptRecordedOpenSSLSessions(t *testing.T) {
	for name, wantSuite := range map[string]uint16{
		"dhe-gcm": 0x009F, "dhe-chacha": 0xCCAA, "dhe-cbc-sha": 0x0033, "cbc384-mte": 0xC028, "cbc384-etm": 0xC028,
	} {
		t.Run(name, func(t *testing.T) {
			session := loadRecordedSession(t, name)
			suite, isTLS13, err := serverHelloParams(session.s2c)
			if err != nil || isTLS13 || suite != wantSuite {
				t.Fatalf("recording negotiated 0x%04x tls13=%v err=%v", suite, isTLS13, err)
			}
			hello, err := firstHandshake(session.s2c, 2)
			if err != nil {
				t.Fatal(err)
			}
			if got := serverHelloHasExtension(hello, extEncryptThenMAC); got != (name == "cbc384-etm") {
				t.Fatalf("encrypt-then-MAC negotiated = %v", got)
			}
			messages, err := NewDecryptor(session.keys).DecryptFlow(session.c2s, session.s2c)
			if err != nil {
				t.Fatal(err)
			}
			if client, server := plaintextByRole(messages); client != "hello-device\n" || server != "ecived-olleh\n" {
				t.Fatalf("client %q server %q", client, server)
			}
		})
	}
}

// A CBC record whose ciphertext, MAC or padding was altered must be refused in
// both layouts, never returned as plaintext.
func TestDecryptCBCRejectsTamperedRecords(t *testing.T) {
	for _, name := range []string{"cbc384-mte", "cbc384-etm", "dhe-cbc-sha"} {
		session := loadRecordedSession(t, name)
		records, err := parseRecords(session.c2s)
		if err != nil {
			t.Fatal(err)
		}
		last := records[len(records)-1]
		for _, offset := range []int{last.start + 5, last.start + 5 + 16, last.end - 1} {
			tampered := append([]byte(nil), session.c2s...)
			tampered[offset] ^= 0x01
			if _, err := NewDecryptor(session.keys).DecryptFlow(tampered, session.s2c); err == nil || !strings.Contains(err.Error(), "auth failed") {
				t.Errorf("%s: altered byte %d: %v", name, offset-last.start, err)
			}
		}
	}
}

// After a KeyUpdate each direction continues under the next generation of its
// traffic secret; without following it, everything after the update is lost.
func TestDecryptTLS13FollowsKeyUpdate(t *testing.T) {
	session := loadRecordedSession(t, "keyupdate")
	messages, err := NewDecryptor(session.keys).DecryptFlow(session.c2s, session.s2c)
	if err != nil {
		t.Fatal(err)
	}
	client, server := plaintextByRole(messages)
	if client != "before-update\nafter-update\n" || server != "etadpu-erofeb\netadpu-retfa\n" {
		t.Fatalf("client %q server %q", client, server)
	}
}

func TestDecryptRejectsOlderProtocolVersions(t *testing.T) {
	session := loadRecordedSession(t, "dhe-cbc-sha")
	// Rewrite the ServerHello version to TLS 1.1: record header(5) + handshake header(4).
	downgraded := append([]byte(nil), session.s2c...)
	downgraded[9], downgraded[10] = 0x03, 0x02
	if _, err := NewDecryptor(session.keys).DecryptFlow(session.c2s, downgraded); err == nil || !strings.Contains(err.Error(), "only TLS 1.2 and 1.3") {
		t.Fatalf("error = %v", err)
	}
}

func TestStrictKeyLogSkipsUnknownLabels(t *testing.T) {
	random := strings.Repeat("ab", 32)
	known := "CLIENT_RANDOM " + random + " " + strings.Repeat("cd", 48) + "\n"
	extra := "ECH_SECRET " + random + " " + strings.Repeat("ef", 32) + "\nCLIENT_TRAFFIC_SECRET_1 " + random + " " + strings.Repeat("01", 32) + "\n"
	keys, err := ParseKeyLogStrict([]byte(extra + known))
	if err != nil || keys.Count() != 1 {
		t.Fatalf("known entry beside unknown labels: %v", err)
	}
	if _, ok := keys.Secret(random, "CLIENT_RANDOM"); !ok {
		t.Fatal("known entry was dropped")
	}
	if _, err := ParseKeyLogStrict([]byte(extra)); err == nil || !strings.Contains(err.Error(), "no usable NSS entries") {
		t.Fatalf("only unknown labels: %v", err)
	}
	for _, bad := range []string{"lowercase_label " + random + " " + strings.Repeat("ef", 32), "ECH_SECRET " + random + " zz", "CLIENT_RANDOM " + random + " " + strings.Repeat("cd", 32)} {
		if _, err := ParseKeyLogStrict([]byte(bad + "\n" + known)); err == nil {
			t.Errorf("accepted malformed entry %q", strings.Fields(bad)[0])
		}
	}
}
