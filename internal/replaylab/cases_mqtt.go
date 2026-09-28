package replaylab

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

func init() {
	for _, version := range []byte{4, 5} {
		for _, encrypted := range []bool{false, true} {
			version, encrypted := version, encrypted
			name := "mqtt311"
			if version == 5 {
				name = "mqtt5"
			}
			if encrypted {
				name += "-tls"
			}
			Register(Case{Name: name, Setup: func(ctx context.Context, dir string) (*Fixture, error) {
				return setupMQTTFixture(ctx, dir, version, encrypted)
			}})
		}
	}
}

func labMQTTPacket(header byte, body []byte) []byte {
	out := []byte{header}
	n := len(body)
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 128
		}
		out = append(out, b)
		if n == 0 {
			break
		}
	}
	return append(out, body...)
}

func labMQTTString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func readLabMQTT(conn net.Conn) ([]byte, error) {
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return nil, err
	}
	out := []byte{first[0]}
	length, mult := 0, 1
	for i := 0; i < 4; i++ {
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return nil, err
		}
		out = append(out, b[0])
		length += int(b[0]&127) * mult
		if b[0]&128 == 0 {
			if length > 1<<20 {
				return nil, fmt.Errorf("lab MQTT packet exceeds bound")
			}
			body := make([]byte, length)
			_, err := io.ReadFull(conn, body)
			return append(out, body...), err
		}
		mult *= 128
	}
	return nil, fmt.Errorf("lab MQTT invalid remaining length")
}

func setupMQTTFixture(ctx context.Context, dir string, version byte, encrypted bool) (*Fixture, error) {
	body := []byte{0, 4, 'M', 'Q', 'T', 'T', version, 2, 0, 1}
	if version == 5 {
		body[9] = 60
		body = append(body, 3, 0x22, 0, 1)
	}
	connect := labMQTTPacket(0x10, labMQTTString(body, "replay-lab"))
	connack := []byte{0x20, 2, 0, 0}
	liveConnack := connack
	if version == 5 {
		connack = []byte{0x20, 3, 0, 0, 0}
		liveConnack = []byte{0x20, 6, 0, 0, 3, 0x13, 0, 1}
	}
	publish := func(topic string, id uint16, alias bool) []byte {
		b := labMQTTString(nil, topic)
		b = binary.BigEndian.AppendUint16(b, id)
		if version == 5 {
			if alias {
				b = append(b, 3, 0x23, 0, 1)
			} else {
				b = append(b, 0)
			}
		}
		b = append(b, []byte("stable")...)
		return labMQTTPacket(0x34, b)
	}
	subBody := []byte{0, 9}
	if version == 5 {
		subBody = append(subBody, 0)
	}
	subBody = labMQTTString(subBody, "status")
	subBody = append(subBody, 2)
	subscribe := labMQTTPacket(0x82, subBody)
	suback := []byte{0x90, 3, 0, 9, 2}
	if version == 5 {
		suback = []byte{0x90, 4, 0, 9, 0, 2}
	}
	inbound := publish("status", 7, false)
	outbound := publish("command", 7, false)
	exchanges := []Exchange{
		{Client: connect, Server: connack},
		{Client: subscribe, Server: append(append([]byte(nil), suback...), inbound...), At: 5 * time.Millisecond},
		{Client: []byte{0x50, 2, 0, 7}, Server: []byte{0x62, 2, 0, 7}, At: 10 * time.Millisecond},
		{Client: []byte{0x70, 2, 0, 7}, At: 15 * time.Millisecond},
		{Client: outbound, Server: []byte{0x50, 2, 0, 7}, At: 2300 * time.Millisecond},
		{Client: []byte{0x62, 2, 0, 7}, Server: []byte{0x70, 2, 0, 7}, At: 2310 * time.Millisecond},
		{Client: []byte{0xe0, 0}, At: 2320 * time.Millisecond},
	}
	handler := func(conn net.Conn, stats *Stats) error {
		pings := 0
		read := func(want []byte, allowPing bool) error {
			for {
				got, err := readLabMQTT(conn)
				if err != nil {
					return err
				}
				if allowPing && bytes.Equal(got, []byte{0xc0, 0}) {
					stats.Request()
					if _, err := conn.Write([]byte{0xd0, 0}); err != nil {
						return err
					}
					stats.Response()
					pings++
					continue
				}
				if !bytes.Equal(got, want) {
					return fmt.Errorf("MQTT %d state/identifier mismatch", version)
				}
				stats.Request()
				return nil
			}
		}
		write := func(raw []byte) error {
			_, err := conn.Write(raw)
			if err == nil {
				stats.Response()
			}
			return err
		}
		if err := read(connect, false); err != nil {
			return err
		}
		if err := write(liveConnack); err != nil {
			return err
		}
		if err := read(subscribe, false); err != nil {
			return err
		}
		if err := write(append(append([]byte(nil), suback...), publish("status", 42, version == 5)...)); err != nil {
			return err
		}
		if err := read([]byte{0x50, 2, 0, 42}, false); err != nil {
			return err
		}
		if err := write([]byte{0x62, 2, 0, 42}); err != nil {
			return err
		}
		if err := read([]byte{0x70, 2, 0, 42}, false); err != nil {
			return err
		}
		if err := read(outbound, true); err != nil {
			return err
		}
		if pings == 0 {
			return fmt.Errorf("MQTT keepalive missing during paced idle")
		}
		if err := write([]byte{0x50, 2, 0, 7}); err != nil {
			return err
		}
		if err := read([]byte{0x62, 2, 0, 7}, true); err != nil {
			return err
		}
		if err := write([]byte{0x70, 2, 0, 7}); err != nil {
			return err
		}
		if err := read([]byte{0xe0, 0}, true); err != nil {
			return err
		}
		stats.Note("MQTT %d QoS2 namespaces, live broker identifiers and %d keepalive exchanges verified", version, pings)
		return nil
	}
	fixture, err := SetupStreamFixture(ctx, dir, exchanges, handler, encrypted)
	if err != nil {
		return nil, err
	}
	fixture.Args = append(fixture.Args, "-profile", "timing", "-strict")
	return fixture, nil
}
