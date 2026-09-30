package qualification

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLabCommandContractKeepsHistoricalGates(t *testing.T) {
	for version, count := range map[string]int{"1.0.0": 6, "1.0.1": 7, "1.0.1-rc.1": 7, "1.1.0": 5, "v1.1.0-rc.1": 5, "2.0.0": 5} {
		t.Run(version, func(t *testing.T) {
			keys := requiredLabRuns(version)
			if len(keys) != count {
				t.Fatalf("required runs: %v", keys)
			}
			modern := UsesStatelessReproduce(version)
			for _, suite := range []string{"application", "packet"} {
				if !labCommandAllowed(version, suite, "live") || labCommandAllowed(version, suite, "reproduce") == modern || labCommandAllowed(version, suite, "replay") {
					t.Fatalf("incorrect %s command contract", suite)
				}
			}
			if !labCommandAllowed(version, "stateless", "replay") || labCommandAllowed(version, "stateless", "reproduce") != modern || labCommandAllowed(version, "stateless", "live") {
				t.Fatal("incorrect stateless command contract")
			}
		})
	}
	for _, version := range []string{"1.0.0", "1.0.1", "1.1.0"} {
		t.Run("complete-"+version, func(t *testing.T) {
			doc, options := labValidatorFixtureVersion(t, version)
			if errs := Validate(doc, options); len(errs) != 0 {
				t.Fatal(errs)
			}
			for i, ref := range doc.SoftwareLab.Runs {
				missing := doc
				copyLab := *doc.SoftwareLab
				copyLab.Runs = append(append([]Evidence{}, doc.SoftwareLab.Runs[:i]...), doc.SoftwareLab.Runs[i+1:]...)
				missing.SoftwareLab = &copyLab
				if errs := Validate(missing, options); len(errs) == 0 {
					t.Fatalf("missing required run accepted: %s", ref.Path)
				}
			}
		})
	}
}

// Independent frame construction for the validator, not release evidence.
func protocolStatelessTestFrames() [][]byte {
	var frames [][]byte
	frame := func(version, proto byte, port uint16, payload []byte) {
		body := append([]byte{}, payload...)
		if proto == 6 || proto == 17 {
			size := 20
			if proto == 17 {
				size = 8
			}
			body = make([]byte, size+len(payload))
			binary.BigEndian.PutUint16(body, 40000)
			binary.BigEndian.PutUint16(body[2:], port)
			if proto == 6 {
				body[12] = 0x50
			} else {
				binary.BigEndian.PutUint16(body[4:], uint16(len(body)))
			}
			copy(body[size:], payload)
		}
		header := 20
		if version == 6 {
			header = 40
		}
		b := make([]byte, 14+header+len(body))
		copy(b, []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2})
		if len(frames)%2 != 0 {
			b[5], b[11] = 2, 1
		}
		if version == 4 {
			b[12], b[14], b[23] = 8, 0x45, proto
			binary.BigEndian.PutUint16(b[16:], uint16(header+len(body)))
		} else {
			b[12], b[13], b[14], b[20] = 0x86, 0xdd, 0x60, proto
			binary.BigEndian.PutUint16(b[18:], uint16(len(body)))
		}
		copy(b[14+header:], body)
		for len(b) < 60 {
			b = append(b, 0)
		}
		frames = append(frames, b)
	}
	frame(4, 6, 80, []byte("GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n"))
	dns := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	frame(4, 17, 53, dns)
	frame(4, 6, 53, append([]byte{0, byte(len(dns))}, dns...))
	for _, level := range []byte{4, 5} {
		frame(4, 6, 1883, []byte{0x10, 10, 0, 4, 'M', 'Q', 'T', 'T', level, 2, 0, 60})
	}
	frame(4, 6, 502, []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1})
	frame(4, 6, 20000, []byte{5, 0x64, 8, 0xc4, 1, 0, 0, 4, 0, 0, 0xc0, 0xc0, 1, 0, 0})
	frame(4, 6, 21, []byte("220 synthetic\r\n"))
	frame(4, 6, 20, []byte("file bytes"))
	frame(4, 6, 21, []byte("AUTH TLS\r\n"))
	for _, port := range []uint16{443, 21, 990} {
		frame(4, 6, port, []byte{23, 3, 3, 0, 3, 1, 2, 3})
	}
	frame(4, 6, 22, []byte("SSH-2.0-Synthetic\r\n"))
	frame(4, 6, 22, bytes.Repeat([]byte{0xa5}, 32))
	frame(6, 6, 19001, []byte("IPv6 TCP"))
	frame(6, 17, 19000, []byte("IPv6 UDP"))
	frame(4, 1, 0, make([]byte, 8))
	frame(6, 58, 0, make([]byte, 8))
	unknown := make([]byte, 60)
	unknown[12], unknown[13] = 0x88, 0xb5
	frames = append(frames, unknown)
	return frames
}

func TestCorrectedStatelessContractRequiresProtocolBytesAndCommand(t *testing.T) {
	for _, command := range []string{"reproduce", "replay"} {
		t.Run(command, func(t *testing.T) {
			run, base, write := statelessValidatorFixtureVersion(t, "1.1.0", command, protocolStatelessTestFrames())
			if err := validateLabTranscript(run, base); err != nil {
				t.Fatal(err)
			}
			// Rehashing a report cannot hide invocation of the other front door.
			path := filepath.Join(base, "report.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var report map[string]any
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			report["command"] = "live"
			data, _ = json.Marshal(report)
			changed := write("report.json", data)
			for i, ref := range run.Evidence {
				if ref.Path == changed.Path {
					run.Evidence[i] = changed
				}
			}
			data, err = os.ReadFile(filepath.Join(base, "events.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(data, []byte{'\n'})
			var event statelessLabEvent
			if err := json.Unmarshal(lines[0], &event); err != nil {
				t.Fatal(err)
			}
			event.ReportSHA256 = changed.SHA256
			lines[0], _ = json.Marshal(event)
			changed = write("events.jsonl", bytes.Join(lines, []byte{'\n'}))
			for i, ref := range run.Evidence {
				if ref.Path == changed.Path {
					run.Evidence[i] = changed
				}
			}
			if err := validateLabTranscript(run, base); err == nil || !strings.Contains(err.Error(), "CLI command differs") {
				t.Fatalf("changed CLI command accepted or wrong rejection: %v", err)
			}
		})
	}
	if err := validateStatelessProtocolCoverage(encodeStatelessTestCapture(t, statelessTestFrames())); err == nil {
		t.Fatal("historical mixed bytes substituted for expanded protocol coverage")
	}
	for _, missing := range []string{"http1", "dns-tcp", "dns-udp", "mqtt311", "mqtt5", "modbus", "dnp3", "ftp-control", "ftp-data", "ftp-auth-tls", "ftps-explicit", "ftps-implicit", "ssh-banner", "ssh-opaque", "tcp6", "udp6", "icmp4", "icmp6", "unknown-ether-type"} {
		t.Run("missing-"+missing, func(t *testing.T) {
			var remaining [][]byte
			for _, frame := range protocolStatelessTestFrames() {
				forms := map[string]bool{}
				statelessFrameForms(frame, forms)
				if !forms[missing] {
					remaining = append(remaining, frame)
				}
			}
			if err := validateStatelessProtocolCoverage(encodeStatelessTestCapture(t, remaining)); err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("missing protocol accepted or wrong rejection: %v", err)
			}
		})
	}
}
