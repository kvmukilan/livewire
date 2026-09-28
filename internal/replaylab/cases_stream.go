package replaylab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

func init() {
	for _, encrypted := range []bool{false, true} {
		encrypted := encrypted
		for _, protocol := range []string{"http1", "dns", "modbus"} {
			protocol := protocol
			name := protocol
			if encrypted {
				name += "-tls"
			} else if protocol != "http1" {
				name += "-tcp"
			}
			Register(Case{Name: name, Setup: func(ctx context.Context, dir string) (*Fixture, error) {
				switch protocol {
				case "http1":
					return setupHTTPFixture(ctx, dir, encrypted)
				case "dns":
					return setupDNSFixture(ctx, dir, encrypted)
				default:
					return setupModbusFixture(ctx, dir, encrypted)
				}
			}})
		}
	}
}

func setupHTTPFixture(ctx context.Context, dir string, encrypted bool) (*Fixture, error) {
	requests := [][]byte{[]byte("GET /login HTTP/1.1\r\nHost: localhost\r\n\r\n"), []byte("GET /data HTTP/1.1\r\nHost: localhost\r\nCookie: session=captured\r\n\r\n")}
	responses := [][]byte{[]byte("HTTP/1.1 200 OK\r\nSet-Cookie: session=captured; Path=/\r\nContent-Length: 5\r\n\r\nhello"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld")}
	exchanges := []Exchange{{Client: requests[0], Server: responses[0]}, {Client: requests[1], Server: responses[1]}}
	handler := func(conn net.Conn, stats *Stats) error {
		reader := bufio.NewReader(conn)
		for i, path := range []string{"/login", "/data"} {
			request, err := http.ReadRequest(reader)
			if err != nil {
				return err
			}
			_ = request.Body.Close()
			if request.Method != "GET" || request.URL.Path != path {
				return fmt.Errorf("HTTP request %d method/path differs", i+1)
			}
			if i == 1 {
				cookie, err := request.Cookie("session")
				if err != nil || cookie.Value != "fresh" {
					return fmt.Errorf("HTTP did not reuse live login cookie")
				}
			}
			stats.Request()
			stats.Note("HTTP verified request %d path=%s", i+1, path)
			response := bytes.ReplaceAll(responses[i], []byte("session=captured"), []byte("session=fresh"))
			if err := writeSplit(conn, response); err != nil {
				return err
			}
			stats.Response()
		}
		return nil
	}
	return SetupStreamFixture(ctx, dir, exchanges, handler, encrypted)
}

func labDNSMessage(id uint16, name byte, response bool) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[:2], id)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	message = append(message, 1, name, 3, 'l', 'a', 'b', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0, 0, 1, 0, 1)
	if response {
		binary.BigEndian.PutUint16(message[2:4], 0x8180)
		binary.BigEndian.PutUint16(message[6:8], 1)
		message = append(message, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, name)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(message))), message...)
}

func readLengthFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header))
	if n < 12 || n > 4096 {
		return nil, fmt.Errorf("DNS length outside independent fixture bounds")
	}
	frame := make([]byte, n)
	_, err := io.ReadFull(conn, frame)
	return append(header, frame...), err
}

func setupDNSFixture(ctx context.Context, dir string, encrypted bool) (*Fixture, error) {
	q1, q2 := labDNSMessage(11, 'a', false), labDNSMessage(12, 'b', false)
	r1, r2 := labDNSMessage(11, 'a', true), labDNSMessage(12, 'b', true)
	exchanges := []Exchange{{Client: append(append([]byte{}, q1...), q2...), Server: append(append([]byte{}, r1...), r2...)}}
	handler := func(conn net.Conn, stats *Stats) error {
		var replies [][]byte
		for i, name := range []byte{'a', 'b'} {
			request, err := readLengthFrame(conn)
			if err != nil {
				return err
			}
			want := labDNSMessage(binary.BigEndian.Uint16(request[2:4]), name, false)
			if !bytes.Equal(request, want) {
				return fmt.Errorf("DNS query %d differs from fixture question", i+1)
			}
			stats.Request()
			stats.Note("DNS verified question %d", i+1)
			replies = append(replies, labDNSMessage(binary.BigEndian.Uint16(request[2:4]), name, true))
		}
		// Independent transaction identifiers must survive coalesced replies in
		// the opposite order from the capture.
		if err := writeSplit(conn, append(replies[1], replies[0]...)); err != nil {
			return err
		}
		stats.Response()
		stats.Response()
		return nil
	}
	return SetupStreamFixture(ctx, dir, exchanges, handler, encrypted)
}

func setupModbusFixture(ctx context.Context, dir string, encrypted bool) (*Fixture, error) {
	q1 := []byte{0, 11, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1}
	q2 := []byte{0, 12, 0, 0, 0, 6, 1, 3, 0, 1, 0, 1}
	r1 := []byte{0, 11, 0, 0, 0, 5, 1, 3, 2, 0, 17}
	r2 := []byte{0, 12, 0, 0, 0, 5, 1, 3, 2, 0, 18}
	exchanges := []Exchange{{Client: append(append([]byte{}, q1...), q2...), Server: append(append([]byte{}, r1...), r2...)}}
	handler := func(conn net.Conn, stats *Stats) error {
		var replies [][]byte
		for i, want := range [][]byte{q1, q2} {
			request := make([]byte, len(want))
			if _, err := io.ReadFull(conn, request); err != nil {
				return err
			}
			if !bytes.Equal(request[2:], want[2:]) {
				return fmt.Errorf("modbus request %d function/address/count differs", i+1)
			}
			stats.Request()
			stats.Note("Modbus verified read request %d", i+1)
			reply := append([]byte(nil), r1...)
			if i == 1 {
				reply = append([]byte(nil), r2...)
			}
			copy(reply[:2], request[:2])
			replies = append(replies, reply)
		}
		if err := writeSplit(conn, append(replies[1], replies[0]...)); err != nil {
			return err
		}
		stats.Response()
		stats.Response()
		return nil
	}
	return SetupStreamFixture(ctx, dir, exchanges, handler, encrypted)
}

func writeSplit(conn net.Conn, data []byte) error {
	cut := len(data) / 2
	if _, err := conn.Write(data[:cut]); err != nil {
		return err
	}
	time.Sleep(time.Millisecond)
	_, err := conn.Write(data[cut:])
	return err
}
