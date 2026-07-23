package adapters

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/replay"
)

func TestHTTPPipeliningAndSubstitution(t *testing.T) {
	raw := []byte("GET /one HTTP/1.1\r\nHost: old\r\nContent-Length: 0\r\n\r\nGET /two HTTP/1.1\r\nHost: old\r\n\r\n")
	msgs, err := (HTTP{}).Decode(replay.ClientToServer, raw)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("decode: messages=%d err=%v", len(msgs), err)
	}
	got, err := (HTTP{}).Prepare(replay.ClientToServer, msgs[0], &replay.RuntimeState{Variables: map[string]string{"http.host": "new.example", "http.header.X-Test": "yes"}})
	if err != nil || !bytes.Contains(got, []byte("Host: new.example\r\n")) || !bytes.Contains(got, []byte("X-Test: yes\r\n")) {
		t.Fatalf("prepared request: %q err=%v", got, err)
	}
}

func TestHTTPBodySubstitutionRepairsFraming(t *testing.T) {
	a := HTTP{}
	msgs, err := a.Decode(replay.ClientToServer, []byte("POST /set HTTP/1.1\r\nHost: old\r\nContent-Length: 3\r\n\r\nold"))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := a.Prepare(replay.ClientToServer, msgs[0], &replay.RuntimeState{Variables: map[string]string{"http.body": "new-value"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(prepared, []byte("Content-Length: 9\r\n")) || !bytes.HasSuffix(prepared, []byte("new-value")) {
		t.Fatalf("fixed-length body framing=%q", prepared)
	}
	chunked, err := a.Decode(replay.ClientToServer, []byte("POST /set HTTP/1.1\r\nHost: old\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nold\r\n0\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = a.Prepare(replay.ClientToServer, chunked[0], &replay.RuntimeState{Variables: map[string]string{"http.body": "changed"}})
	if err != nil || !bytes.HasSuffix(prepared, []byte("7\r\nchanged\r\n0\r\n\r\n")) {
		t.Fatalf("chunked body framing=%q err=%v", prepared, err)
	}
}

func TestHTTPChunkedBodyWithTrailers(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nDigest: sha-256=x\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n")
	msgs, err := (HTTP{}).Decode(replay.ServerToClient, raw)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("decode chunked trailers: messages=%d err=%v", len(msgs), err)
	}
	if !bytes.HasSuffix(msgs[0].Raw, []byte("Digest: sha-256=x\r\n\r\n")) {
		t.Fatalf("first message did not retain trailers: %q", msgs[0].Raw)
	}
}

func TestHTTPNoBodyStatusAndCloseFraming(t *testing.T) {
	a := HTTP{}
	msgs, err := a.Decode(replay.ServerToClient, []byte("HTTP/1.1 204 No Content\r\nContent-Length: 99\r\n\r\n"))
	if err != nil || len(msgs) != 1 {
		t.Fatalf("204 response: messages=%d err=%v", len(msgs), err)
	}
	closeMsgs, err := a.Decode(replay.ServerToClient, []byte("HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nbody"))
	if err != nil || len(closeMsgs) != 1 || !a.RequiresEOF(replay.ServerToClient, closeMsgs[0]) {
		t.Fatalf("close response: messages=%d err=%v", len(closeMsgs), err)
	}
}

func TestHTTPHeadPairingAndTransferEncodingPrecedence(t *testing.T) {
	a := HTTP{}
	requests, err := a.Decode(replay.ClientToServer, []byte("HEAD /meta HTTP/1.1\r\nHost: device\r\n\r\nGET /next HTTP/1.1\r\nHost: device\r\n\r\n"))
	if err != nil || len(requests) != 2 {
		t.Fatalf("requests=%d err=%v", len(requests), err)
	}
	responses := []byte("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n4\r\ntest\r\n0\r\n\r\n")
	msgs, err := a.DecodeExchange(replay.ServerToClient, responses, requests)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("responses=%d err=%v", len(msgs), err)
	}
	if len(msgs[0].Fields["body"].([]byte)) != 0 {
		t.Fatal("HEAD response must not consume a Content-Length body")
	}
	if !bytes.Contains(msgs[1].Raw, []byte("4\r\ntest\r\n")) {
		t.Fatalf("chunked response was truncated by Content-Length: %q", msgs[1].Raw)
	}
	if got := a.ConsumedPeers(replay.ServerToClient, msgs); got != 2 {
		t.Fatalf("consumed peers=%d", got)
	}
}

func TestHTTPUnboundedResponseRequiresEOFWithoutConnectionHeader(t *testing.T) {
	a := HTTP{}
	msgs, err := a.Decode(replay.ServerToClient, []byte("HTTP/1.1 200 OK\r\n\r\nbody"))
	if err != nil || len(msgs) != 1 || !a.RequiresEOF(replay.ServerToClient, msgs[0]) {
		t.Fatalf("messages=%d err=%v fields=%v", len(msgs), err, msgs[0].Fields)
	}
}

func dnsQuery(name string, id uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[:2], id)
	binary.BigEndian.PutUint16(b[2:4], 0x0100)
	binary.BigEndian.PutUint16(b[4:6], 1)
	enc, _ := encodeDNSName(name)
	b = append(b, enc...)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint16(b, 1)
	return b
}

func TestDNSCorrelationAndNameRewrite(t *testing.T) {
	a := DNS{Transport: replay.TransportUDP}
	m1, err := a.Decode(replay.ClientToServer, dnsQuery("old.example", 10))
	if err != nil || len(m1) != 1 {
		t.Fatal(err)
	}
	m2, _ := a.Decode(replay.ClientToServer, dnsQuery("old.example", 99))
	if a.Correlate(m1[0], m2[0], nil).Matched {
		t.Fatal("a response with the wrong transaction ID must not correlate")
	}
	m3, _ := a.Decode(replay.ClientToServer, dnsQuery("old.example", 10))
	if !a.Correlate(m1[0], m3[0], nil).Matched {
		t.Fatal("matching transaction ID and question should correlate")
	}
	if diffs := a.Compare(m1[0], m2[0], replay.VerifyLenient); len(diffs) != 0 {
		t.Fatalf("lenient comparison should normalize ID: %+v", diffs)
	}
	prepared, err := a.Prepare(replay.ClientToServer, m1[0], &replay.RuntimeState{Variables: map[string]string{"dns.name": "new.example"}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := a.Decode(replay.ClientToServer, prepared)
	if err != nil || stringField(decoded[0], "qname") != "new.example" {
		t.Fatalf("rewritten qname=%q err=%v", stringField(decoded[0], "qname"), err)
	}
}

func TestDNSTCPFramingAndUDPIDAmbiguity(t *testing.T) {
	first := dnsQuery("one.example", 7)
	second := dnsQuery("two.example", 8)
	stream := binary.BigEndian.AppendUint16(nil, uint16(len(first)))
	stream = append(stream, first...)
	stream = binary.BigEndian.AppendUint16(stream, uint16(len(second)))
	stream = append(stream, second...)
	msgs, err := (DNS{Transport: replay.TransportTCP}).Decode(replay.ClientToServer, stream)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("DNS/TCP messages=%d err=%v", len(msgs), err)
	}

	// The UDP transaction ID deliberately equals the datagram length minus two.
	// It is still an ID, never a TCP length prefix.
	udp := dnsQuery("ambiguous.example", 0)
	binary.BigEndian.PutUint16(udp[:2], uint16(len(udp)-2))
	msgs, err = (DNS{Transport: replay.TransportUDP}).Decode(replay.ClientToServer, udp)
	if err != nil || len(msgs) != 1 || msgs[0].Fields["id"] != uint16(len(udp)-2) {
		t.Fatalf("DNS/UDP framing was ambiguous: messages=%d err=%v fields=%v", len(msgs), err, msgs[0].Fields)
	}
}

func dnsAResponse(name string, id uint16, ttl uint32, address [4]byte) []byte {
	b := dnsQuery(name, id)
	binary.BigEndian.PutUint16(b[2:4], 0x8180)
	binary.BigEndian.PutUint16(b[6:8], 1)
	b = append(b, 0xc0, 0x0c, 0, 1, 0, 1)
	b = binary.BigEndian.AppendUint32(b, ttl)
	b = binary.BigEndian.AppendUint16(b, 4)
	return append(b, address[:]...)
}

func TestDNSLenientNormalizesOnlyIDAndTTL(t *testing.T) {
	a := DNS{Transport: replay.TransportUDP}
	want, err := a.Decode(replay.ServerToClient, dnsAResponse("device.example", 1, 60, [4]byte{192, 0, 2, 1}))
	if err != nil {
		t.Fatal(err)
	}
	ttlDrift, err := a.Decode(replay.ServerToClient, dnsAResponse("device.example", 999, 3600, [4]byte{192, 0, 2, 1}))
	if err != nil {
		t.Fatal(err)
	}
	if diffs := a.Compare(want[0], ttlDrift[0], replay.VerifyLenient); len(diffs) != 0 {
		t.Fatalf("ID/TTL drift should normalize: %+v", diffs)
	}
	changed, err := a.Decode(replay.ServerToClient, dnsAResponse("device.example", 2, 60, [4]byte{192, 0, 2, 99}))
	if err != nil {
		t.Fatal(err)
	}
	if diffs := a.Compare(want[0], changed[0], replay.VerifyLenient); len(diffs) == 0 {
		t.Fatal("changed A record must be reported in lenient mode")
	}
}

func TestDNSExpectedResponseUsesRunName(t *testing.T) {
	a := DNS{Transport: replay.TransportUDP}
	captured, err := a.Decode(replay.ServerToClient, dnsAResponse("old.example", 44, 60, [4]byte{192, 0, 2, 1}))
	if err != nil {
		t.Fatal(err)
	}
	state := &replay.RuntimeState{Variables: map[string]string{"dns.name": "new.example"}}
	normalized, err := replay.NormalizeExpected(a, replay.ServerToClient, captured[0], state)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := a.Decode(replay.ServerToClient, dnsAResponse("new.example", 44, 50, [4]byte{192, 0, 2, 1}))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Correlate(normalized, actual[0], state).Matched {
		t.Fatalf("normalized expected=%v actual=%v", normalized.Fields, actual[0].Fields)
	}
	if diffs := a.Compare(normalized, actual[0], replay.VerifyLenient); len(diffs) != 0 {
		t.Fatalf("correct response to substituted name differs: %+v", diffs)
	}
}

func mqttConnect(client string) []byte {
	body := []byte{0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 60}
	body = mqttPutUTF8(body, client)
	out := []byte{0x10}
	out = appendMQTTLength(out, len(body))
	return append(out, body...)
}

func mqtt5Connect(client string) []byte {
	body := []byte{0, 4, 'M', 'Q', 'T', 'T', 5, 2, 0, 60}
	body = append(body, 3, 0x21, 0, 10) // CONNECT properties: receive maximum=10
	body = mqttPutUTF8(body, client)
	out := []byte{0x10}
	out = appendMQTTLength(out, len(body))
	return append(out, body...)
}

func TestMQTTConnectCredentialSubstitution(t *testing.T) {
	a := MQTT{}
	msgs, err := a.Decode(replay.ClientToServer, mqttConnect("old"))
	if err != nil || len(msgs) != 1 {
		t.Fatal(err)
	}
	prepared, err := a.Prepare(replay.ClientToServer, msgs[0], &replay.RuntimeState{Variables: map[string]string{
		"mqtt.client_id": "client-2", "mqtt.username": "user", "mqtt.password": "secret",
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Decode(replay.ClientToServer, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if stringField(got[0], "clientId") != "client-2" || stringField(got[0], "username") != "user" || got[0].Fields["hasPassword"] != true {
		t.Fatalf("rewritten CONNECT fields: %+v", got[0].Fields)
	}
}

func TestMQTT5ConnectPropertiesAndCredentialSubstitution(t *testing.T) {
	a := MQTT{}
	msgs, err := a.Decode(replay.ClientToServer, mqtt5Connect("old-v5"))
	if err != nil || len(msgs) != 1 || msgs[0].Fields["version"] != byte(5) || stringField(msgs[0], "clientId") != "old-v5" {
		t.Fatalf("MQTT 5 decode: messages=%d fields=%v err=%v", len(msgs), msgs[0].Fields, err)
	}
	prepared, err := a.Prepare(replay.ClientToServer, msgs[0], &replay.RuntimeState{Variables: map[string]string{
		"mqtt.client_id": "new-v5", "mqtt.username": "operator", "mqtt.password": "secret",
	}})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := a.Decode(replay.ClientToServer, prepared)
	if err != nil || len(decoded) != 1 {
		t.Fatalf("MQTT 5 rewritten messages=%d err=%v", len(decoded), err)
	}
	if stringField(decoded[0], "clientId") != "new-v5" || stringField(decoded[0], "username") != "operator" || decoded[0].Fields["hasPassword"] != true {
		t.Fatalf("MQTT 5 rewritten fields=%v", decoded[0].Fields)
	}
	remaining, used, _ := mqttRemaining(prepared[1:])
	body := prepared[1+used : 1+used+remaining]
	_, _, _, payloadOff, ok := mqttConnectLayout(body)
	if !ok || payloadOff != 14 || !bytes.Equal(body[10:14], []byte{3, 0x21, 0, 10}) {
		t.Fatalf("MQTT 5 CONNECT properties were not preserved: %x", body)
	}
}

func mqttQoS1Publish(topic string, id uint16, payload string) []byte {
	body := mqttPutUTF8(nil, topic)
	body = binary.BigEndian.AppendUint16(body, id)
	body = append(body, payload...)
	out := []byte{0x32}
	out = appendMQTTLength(out, len(body))
	return append(out, body...)
}

func TestMQTTLearnsBrokerPacketIDAcrossQoSFlow(t *testing.T) {
	adapter := MQTT{}
	expected, err := adapter.Decode(replay.ServerToClient, mqttQoS1Publish("alarms", 7, "trip"))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := adapter.Decode(replay.ServerToClient, mqttQoS1Publish("alarms", 42, "trip"))
	if err != nil {
		t.Fatal(err)
	}
	state := &replay.RuntimeState{Variables: map[string]string{}, Learned: map[string][]byte{}}
	if match := adapter.Correlate(expected[0], actual[0], state); !match.Matched {
		t.Fatalf("broker PUBLISH did not correlate: %+v", match)
	}
	if diffs := adapter.Compare(expected[0], actual[0], replay.VerifyStrict); len(diffs) != 0 {
		t.Fatalf("fresh broker packet ID should be normalized: %+v", diffs)
	}
	puback, err := adapter.Decode(replay.ClientToServer, []byte{0x40, 0x02, 0, 7})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := adapter.Prepare(replay.ClientToServer, puback[0], state)
	if err != nil || !bytes.Equal(prepared, []byte{0x40, 0x02, 0, 42}) {
		t.Fatalf("PUBACK did not reuse live broker ID: %x err=%v", prepared, err)
	}
	pubrel, err := adapter.Decode(replay.ServerToClient, []byte{0x62, 0x02, 0, 7})
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := adapter.NormalizeExpected(replay.ServerToClient, pubrel[0], state)
	if err != nil || normalized.Fields["packetId"] != uint16(42) || !bytes.Equal(normalized.Raw, []byte{0x62, 0x02, 0, 42}) {
		t.Fatalf("server QoS continuation was not normalized: fields=%v raw=%x err=%v", normalized.Fields, normalized.Raw, err)
	}
}

func TestRulePackLengthFramingVolatileAndCopy(t *testing.T) {
	a, err := CompileRulePackJSON([]byte(`{
      "name":"vendor-x","match":{"transport":"tcp","ports":[9000],"prefixHex":"aa"},
      "framing":{"type":"length-field","lengthOffset":1,"lengthSize":1,"lengthIncludesHeader":true},
      "correlation":[{"name":"id","offset":2,"length":1}],
      "volatile":[{"offset":3,"length":1}],
      "copyFromLive":[{"key":"token","fromOffset":3,"toOffset":4,"length":1}]
    }`))
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := a.Decode(replay.ClientToServer, []byte{0xaa, 5, 7, 1, 0})
	if err != nil || len(msgs) != 1 {
		t.Fatalf("decode: %v", err)
	}
	actual, _ := a.Decode(replay.ServerToClient, []byte{0xaa, 5, 7, 9, 0})
	state := &replay.RuntimeState{Learned: map[string][]byte{}}
	if !a.Correlate(msgs[0], actual[0], state).Matched || state.Learned["token"][0] != 9 {
		t.Fatal("correlation/copy learning failed")
	}
	if diffs := a.Compare(msgs[0], actual[0], replay.VerifyLenient); len(diffs) != 0 {
		t.Fatalf("volatile byte should be ignored: %+v", diffs)
	}
	prepared, err := a.Prepare(replay.ClientToServer, msgs[0], state)
	if err != nil || prepared[4] != 9 {
		t.Fatalf("copy prepare=%x err=%v", prepared, err)
	}
}

func TestRulePackDifferencesDoNotEmbedPayloadBytes(t *testing.T) {
	adapter, err := CompileRulePackJSON([]byte(`{"name":"opaque","match":{"transport":"udp"},"framing":{"type":"datagram"}}`))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("Authorization: Bearer should-not-enter-report")
	expected, _ := adapter.Decode(replay.ServerToClient, secret)
	actual, _ := adapter.Decode(replay.ServerToClient, []byte("different opaque response"))
	differences := adapter.Compare(expected[0], actual[0], replay.VerifyStrict)
	if len(differences) != 1 || strings.Contains(differences[0].Expected, string(secret)) || strings.Contains(differences[0].Expected, hex.EncodeToString(secret)) || !strings.Contains(differences[0].Expected, "sha256:") {
		t.Fatalf("unsafe proprietary difference=%+v", differences)
	}
}

func TestMalformedRulePackRejected(t *testing.T) {
	if _, err := CompileRulePackJSON([]byte(`{"name":"x","match":{"transport":"udp"},"framing":{"type":"fixed","size":0}}`)); err == nil {
		t.Fatal("zero fixed size should fail")
	}
	if _, err := CompileRulePackJSON([]byte(`{"name":"x","match":{"transport":"udp"},"framing":{"type":"datagram"}} {}`)); err == nil {
		t.Fatal("trailing JSON should fail")
	}
}
