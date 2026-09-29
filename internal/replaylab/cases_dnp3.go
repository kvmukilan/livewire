package replaylab

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/kvmukilan/livewire/internal/dissect"
)

func init() {
	for _, encrypted := range []bool{false, true} {
		encrypted := encrypted
		name := "dnp3"
		if encrypted {
			name += "-tls"
		}
		Register(Case{Name: name, Setup: func(ctx context.Context, dir string) (*Fixture, error) { return setupDNP3Fixture(ctx, dir, encrypted) }})
	}
}

func labDNPFrame(source, dest uint16, transport byte, app []byte) []byte {
	control := byte(0x44)
	if source == 1 {
		control = 0xc4
	}
	return (dissect.DNP3{Control: control, Source: source, Dest: dest, UserData: append([]byte{transport}, app...)}).Encode()
}

func labDNPAnalog(start byte, values ...byte) []byte {
	b := []byte{30, 1, 0, start, start + byte(len(values)) - 1}
	for _, v := range values {
		b = append(b, 1, v, 0, 0, 0)
	}
	return b
}

func readLabDNP(conn net.Conn) ([]byte, error) {
	header := make([]byte, 10)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0x64 || header[2] < 5 {
		return nil, fmt.Errorf("invalid DNP3 link header")
	}
	n := int(header[2]) - 5
	tail := make([]byte, n+2*((n+15)/16))
	_, err := io.ReadFull(conn, tail)
	return append(header, tail...), err
}

func setupDNP3Fixture(ctx context.Context, dir string, encrypted bool) (*Fixture, error) {
	request := labDNPFrame(1, 4, 0xc1, []byte{0xc1, 1, 30, 1, 6})
	response := labDNPFrame(4, 1, 0xc1, append([]byte{0xc1, 0x81, 0, 0}, labDNPAnalog(0, 42, 43)...))
	nextRequest := labDNPFrame(1, 4, 0xc2, []byte{0xc2, 1, 30, 1, 6})
	lastResponse := labDNPFrame(4, 1, 0xc2, append([]byte{0xc2, 0x81, 0, 0}, labDNPAnalog(0, 44)...))
	exchanges := []Exchange{{Client: request, Server: response}, {Client: nextRequest, Server: lastResponse, At: 10 * time.Millisecond}}
	handler := func(conn net.Conn, stats *Stats) error {
		read := func(want []byte) error {
			got, err := readLabDNP(conn)
			if err != nil {
				return err
			}
			if !bytes.Equal(got, want) {
				return fmt.Errorf("DNP3 request/confirmation/transport state mismatch")
			}
			stats.Request()
			return nil
		}
		write := func(raw []byte) error {
			_, err := conn.Write(raw)
			if err == nil {
				stats.Response()
			}
			return err
		}
		if err := read(request); err != nil {
			return err
		}
		if err := write(labDNPFrame(4, 1, 0xc8, []byte{0xf8, 0x82, 0, 0})); err != nil {
			return err
		}
		if err := read(labDNPFrame(1, 4, 0xc2, []byte{0xd8, 0})); err != nil {
			return err
		}
		first := append([]byte{0xa1, 0x81, 0, 0}, labDNPAnalog(0, 42)...)
		if err := write(labDNPFrame(4, 1, 0x40|63, first[:3])); err != nil {
			return err
		}
		if err := write(labDNPFrame(4, 1, 0x80, first[3:])); err != nil {
			return err
		}
		if err := read(labDNPFrame(1, 4, 0xc3, []byte{0xc1, 0})); err != nil {
			return err
		}
		if err := write(labDNPFrame(4, 1, 0xc1, append([]byte{0x62, 0x81, 0, 0}, labDNPAnalog(1, 43)...))); err != nil {
			return err
		}
		if err := read(labDNPFrame(1, 4, 0xc4, []byte{0xc2, 0})); err != nil {
			return err
		}
		if err := read(labDNPFrame(1, 4, 0xc5, []byte{0xc2, 1, 30, 1, 6})); err != nil {
			return err
		}
		if err := write(labDNPFrame(4, 1, 0xc9, append([]byte{0xc2, 0x81, 0, 0}, labDNPAnalog(0, 44)...))); err != nil {
			return err
		}
		stats.Note("DNP3 changed transport/application fragmentation, unsolicited confirmation and next-request transport state verified")
		return nil
	}
	fixture, err := SetupStreamFixture(ctx, dir, exchanges, handler, encrypted)
	if err != nil {
		return nil, err
	}
	fixture.Args = append(fixture.Args, "-strict")
	return fixture, nil
}
