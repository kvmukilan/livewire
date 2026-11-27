package secureexec

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

func iec104ASDU(typeID, cot byte, payload ...byte) []byte {
	asdu := append([]byte{typeID, 1, cot, 0, 1, 0}, payload...)
	return dissect.IEC104{Raw: append([]byte{0x68, byte(4 + len(asdu)), 0, 0, 0, 0}, asdu...), Format: dissect.IEC104I}.Encode()
}

// windowedOutstation answers a general interrogation with a burst of solicited
// frames and, like a field device, stops sending while k frames are
// unacknowledged.
type windowedOutstation struct {
	k, points, spontaneous int
	sent, acked            uint16
	stalled                bool
}

func (o *windowedOutstation) serve(c net.Conn) {
	defer c.Close()
	var buffer []byte
	tmp := make([]byte, 4096)
	read := func() ([]dissect.IEC104, error) {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := c.Read(tmp)
		if err != nil {
			return nil, err
		}
		buffer = append(buffer, tmp[:n]...)
		frames, left, err := dissect.ParseIEC104Stream(buffer)
		buffer = buffer[len(buffer)-left:]
		for _, f := range frames {
			if f.Format != dissect.IEC104U {
				o.acked = f.RecvSeq
			}
		}
		return frames, err
	}
	send := func(raw []byte) bool {
		for int(o.sent-o.acked) >= o.k {
			if _, err := read(); err != nil {
				o.stalled = true
				return false
			}
		}
		f, _, _ := dissect.ParseIEC104(raw)
		f.SendSeq = o.sent
		o.sent++
		_, err := c.Write(f.Encode())
		return err == nil
	}
	for {
		frames, err := read()
		if err != nil {
			return
		}
		for _, f := range frames {
			switch {
			case f.Format == dissect.IEC104U && f.UFunc == dissect.IEC104StartDTAct:
				_, _ = c.Write(dissect.IEC104UFrame(dissect.IEC104StartDTCon))
			case f.Format == dissect.IEC104U && f.UFunc == dissect.IEC104StopDTAct:
				_, _ = c.Write(dissect.IEC104UFrame(dissect.IEC104StopDTCon))
			case f.Format == dissect.IEC104I:
				ok := send(iec104ASDU(100, 7, 0, 0, 0, 20))
				for i := 0; ok && i < o.points; i++ {
					if i == 2 {
						for j := 0; ok && j < o.spontaneous; j++ {
							ok = send(iec104ASDU(1, 3, 9, 0, 0, 1))
						}
					}
					ok = ok && send(iec104ASDU(1, 20, byte(i+1), 0, 0, 1))
				}
				if !ok || !send(iec104ASDU(100, 10, 0, 0, 0, 20)) {
					return
				}
			}
		}
	}
}

// A station's send window counts solicited and spontaneous frames alike, so a
// captured interrogation longer than the window, or one extra live event
// inside it, must be acknowledged while the expected burst is still arriving.
func TestIEC104AcknowledgesExpectedBurstBeforeStationWindowFills(t *testing.T) {
	cert, roots := selfSignedTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, c := range []struct{ points, spontaneous int }{{14, 0}, {10, 1}, {40, 3}} {
		t.Run(fmt.Sprintf("points-%d-spontaneous-%d", c.points, c.spontaneous), func(t *testing.T) {
			station := &windowedOutstation{k: 12, points: c.points, spontaneous: c.spontaneous}
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				station.serve(conn)
			}()
			var messages []tlsreplay.AppMessage
			add := func(role tlsreplay.AppRole, data []byte) {
				messages = append(messages, tlsreplay.AppMessage{Role: role, Data: data, CapturedAt: time.Duration(len(messages)) * 10 * time.Millisecond, CapturedPacket: len(messages), HasCaptureTime: true})
			}
			add(tlsreplay.FromClient, dissect.IEC104UFrame(dissect.IEC104StartDTAct))
			add(tlsreplay.FromServer, dissect.IEC104UFrame(dissect.IEC104StartDTCon))
			add(tlsreplay.FromClient, iec104ASDU(100, 6, 0, 0, 0, 20))
			add(tlsreplay.FromServer, iec104ASDU(100, 7, 0, 0, 0, 20))
			for i := 0; i < c.points; i++ {
				add(tlsreplay.FromServer, iec104ASDU(1, 20, byte(i+1), 0, 0, 1))
			}
			add(tlsreplay.FromServer, iec104ASDU(100, 10, 0, 0, 0, 20))
			add(tlsreplay.FromClient, dissect.IEC104SFrame(uint16(c.points+2)))
			add(tlsreplay.FromClient, dissect.IEC104UFrame(dissect.IEC104StopDTAct))
			add(tlsreplay.FromServer, dissect.IEC104UFrame(dissect.IEC104StopDTCon))

			state := replay.NewRuntimeState(nil)
			script, err := BuildTLSAdapterScript(messages, adapters.IEC104{}, state)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			res, err := tlsreplay.ReTerminateContext(ctx, tlsreplay.ReTermConfig{
				SessionID: "tcp-0", Address: ln.Addr().String(),
				TLSConfig: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"},
				Script:    script, Timeout: 10 * time.Second, ExchangeTimeout: 2 * time.Second,
				Adapter: adapters.IEC104{}, State: state, VerifyMode: replay.VerifyLenient,
			})
			if err != nil {
				t.Fatalf("replay: %v", err)
			}
			<-done
			if station.stalled {
				t.Fatal("station window filled and was never acknowledged")
			}
			if want := c.points + 4; res.Mismatches != 0 || res.Observed != want || res.Expected != want {
				t.Fatalf("expected %d compared responses: %+v", want, res)
			}
			if want := uint16(c.points + c.spontaneous + 2); station.sent != want || station.acked != want {
				t.Fatalf("station sent %d, acknowledged %d, want %d", station.sent, station.acked, want)
			}
		})
	}
}
