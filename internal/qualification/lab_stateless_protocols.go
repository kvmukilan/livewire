package qualification

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/kvmukilan/livewire/internal/pcapio"
)

// These are representative captured byte forms, not application transactions.
// Opaque TLS/SSH bytes do not prove authentication or decrypted inner protocols.
var statelessProtocolForms = []string{
	"http1", "dns-tcp", "dns-udp", "mqtt311", "mqtt5", "modbus", "dnp3",
	"ftp-control", "ftp-data", "ftp-auth-tls", "ftps-explicit", "ftps-implicit",
	"ssh-banner", "ssh-opaque", "tls-bytes", "tcp4", "udp4", "tcp6", "udp6",
	"icmp4", "icmp6", "unknown-ether-type",
}

func validateStatelessProtocolCoverage(fixture []byte) error {
	capture, err := pcapio.Load(bytes.NewReader(fixture), pcapio.Limits{MaxRecords: 100000, MaxCaptureData: 64 << 20})
	if err != nil {
		return err
	}
	kinds := map[string]bool{}
	for _, record := range capture.Records {
		statelessFrameForms(record.Data, kinds)
	}
	for _, name := range statelessProtocolForms {
		if !kinds[name] {
			return fmt.Errorf("stateless fixture lacks representative %s bytes", name)
		}
	}
	return nil
}

// This deliberately inspects frame bytes independently of the Python producer
// and application replay adapters. Full equality/order is checked separately.
func statelessFrameForms(frame []byte, kinds map[string]bool) {
	if len(frame) < 14 {
		return
	}
	var version, proto byte
	var body []byte
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0800:
		if len(frame) < 34 || frame[14]>>4 != 4 {
			return
		}
		header, total := int(frame[14]&15)*4, int(binary.BigEndian.Uint16(frame[16:18]))
		if header < 20 || total < header || 14+total > len(frame) {
			return
		}
		version, proto, body = 4, frame[23], frame[14+header:14+total]
	case 0x86dd:
		if len(frame) < 54 || frame[14]>>4 != 6 {
			return
		}
		total := int(binary.BigEndian.Uint16(frame[18:20]))
		if 54+total > len(frame) {
			return
		}
		version, proto, body = 6, frame[20], frame[54:54+total]
	case 0x88b5: // deliberate experimental EtherType in the synthetic fixture
		kinds["unknown-ether-type"] = true
		return
	default:
		return
	}
	if version == 4 && proto == 1 && len(body) >= 8 {
		kinds["icmp4"] = true
	}
	if version == 6 && proto == 58 && len(body) >= 8 {
		kinds["icmp6"] = true
	}
	var payload []byte
	switch proto {
	case 6:
		if len(body) < 20 {
			return
		}
		header := int(body[12]>>4) * 4
		if header < 20 || header > len(body) {
			return
		}
		payload = body[header:]
		kinds[fmt.Sprintf("tcp%d", version)] = true
	case 17:
		if len(body) < 8 || int(binary.BigEndian.Uint16(body[4:6])) != len(body) {
			return
		}
		payload = body[8:]
		kinds[fmt.Sprintf("udp%d", version)] = true
	default:
		return
	}
	port := func(want uint16) bool {
		return binary.BigEndian.Uint16(body[:2]) == want || binary.BigEndian.Uint16(body[2:4]) == want
	}
	dns := func(p []byte) bool { return len(p) >= 12 && binary.BigEndian.Uint16(p[4:6]) == 1 }
	if proto == 17 {
		if port(53) && dns(payload) {
			kinds["dns-udp"] = true
		}
		return
	}
	if port(80) && bytes.HasPrefix(payload, []byte("GET /")) && bytes.Contains(payload, []byte(" HTTP/1.1\r\n")) {
		kinds["http1"] = true
	}
	if port(53) && len(payload) >= 14 && int(binary.BigEndian.Uint16(payload[:2])) == len(payload)-2 && dns(payload[2:]) {
		kinds["dns-tcp"] = true
	}
	if (port(1883) || port(1884)) && len(payload) >= 12 && payload[0] == 0x10 && int(payload[1]) == len(payload)-2 && bytes.Equal(payload[2:8], []byte{0, 4, 'M', 'Q', 'T', 'T'}) {
		if payload[8] == 4 {
			kinds["mqtt311"] = true
		} else if payload[8] == 5 {
			kinds["mqtt5"] = true
		}
	}
	if port(502) && len(payload) >= 8 && binary.BigEndian.Uint16(payload[2:4]) == 0 && int(binary.BigEndian.Uint16(payload[4:6])) == len(payload)-6 && payload[7] == 3 {
		kinds["modbus"] = true
	}
	if port(20000) && len(payload) >= 15 && payload[0] == 5 && payload[1] == 0x64 && payload[2] >= 8 {
		kinds["dnp3"] = true
	}
	if port(21) {
		if bytes.HasPrefix(payload, []byte("USER ")) || bytes.HasPrefix(payload, []byte("220 ")) {
			kinds["ftp-control"] = true
		}
		if bytes.Equal(payload, []byte("AUTH TLS\r\n")) {
			kinds["ftp-auth-tls"] = true
		}
	}
	if port(20) && len(payload) > 0 {
		kinds["ftp-data"] = true
	}
	if port(22) {
		if bytes.HasPrefix(payload, []byte("SSH-2.0-")) {
			kinds["ssh-banner"] = true
		} else if len(payload) >= 16 {
			kinds["ssh-opaque"] = true
		}
	}
	if len(payload) >= 6 && (payload[0] == 22 || payload[0] == 23) && payload[1] == 3 && payload[2] <= 4 && int(binary.BigEndian.Uint16(payload[3:5])) == len(payload)-5 {
		kinds["tls-bytes"] = true
		if port(21) {
			kinds["ftps-explicit"] = true
		}
		if port(990) {
			kinds["ftps-implicit"] = true
		}
	}
}
