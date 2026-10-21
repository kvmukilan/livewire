package secureexec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

// iec104Burst builds a spontaneous M_SP_TB_1 burst as a controlled station
// sends after STARTDT and after a reset-process command.
func iec104Burst(sendSeq, recvSeq uint16, count int, stamp byte) []byte {
	asdu := []byte{30, byte(count), 3, 0, 1, 0}
	for i := 0; i < count; i++ {
		asdu = append(asdu, byte(0x26+i), 0x1e, 0x00, byte(i&1), stamp, 0x55, 0x25, 0x0c, 0x14, 0x0a, 0x1a)
	}
	return dissect.IEC104{Raw: append([]byte{0x68, byte(4 + len(asdu)), 0, 0, 0, 0}, asdu...), Format: dissect.IEC104I, SendSeq: sendSeq, RecvSeq: recvSeq}.Encode()
}

var (
	iec104Reset    = []byte{0x68, 0x0e, 0x00, 0x00, 0x04, 0x00, 0x69, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01}
	iec104ResetNeg = []byte{0x68, 0x0e, 0x08, 0x00, 0x02, 0x00, 0x69, 0x01, 0x47, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01}
)

// iec104Outstation is a strict controlled station: it validates every client
// sequence number the way a field device does and closes the connection on a
// violation, sends a different number of spontaneous bursts than any capture,
// and answers the captured reset-process command negatively.
type iec104Outstation struct {
	sent, received, acked uint16
	bursts                int
	failures              chan error
}

func (o *iec104Outstation) send(c net.Conn, raw []byte) error {
	f, _, err := dissect.ParseIEC104(raw)
	if err != nil {
		return err
	}
	if f.Format == dissect.IEC104I {
		f.SendSeq, f.RecvSeq = o.sent, o.received
		o.sent++
		raw = f.Encode()
	}
	_, err = c.Write(raw)
	return err
}

func (o *iec104Outstation) serve(c net.Conn) {
	defer c.Close()
	var buffer []byte
	tmp := make([]byte, 4096)
	for {
		n, err := c.Read(tmp)
		if n > 0 {
			buffer = append(buffer, tmp[:n]...)
		}
		frames, left, perr := dissect.ParseIEC104Stream(buffer)
		if perr != nil {
			o.failures <- perr
			return
		}
		buffer = buffer[len(buffer)-left:]
		for _, f := range frames {
			if f.Format != dissect.IEC104U {
				if f.RecvSeq < o.acked || f.RecvSeq > o.sent {
					o.failures <- fmt.Errorf("client N(R)=%d outside [%d,%d]", f.RecvSeq, o.acked, o.sent)
					return
				}
				o.acked = f.RecvSeq
			}
			switch f.Format {
			case dissect.IEC104I:
				if f.SendSeq != o.received {
					o.failures <- fmt.Errorf("client N(S)=%d, expected %d", f.SendSeq, o.received)
					return
				}
				o.received++
				if f.TypeID != 105 {
					o.failures <- fmt.Errorf("unexpected command type %d", f.TypeID)
					return
				}
				if err := o.send(c, iec104ResetNeg); err != nil {
					return
				}
				for i := 0; i < o.bursts; i++ {
					if err := o.send(c, iec104Burst(0, 0, 21, byte(0x40+i))); err != nil {
						return
					}
				}
			case dissect.IEC104U:
				switch f.UFunc {
				case dissect.IEC104StartDTAct:
					if err := o.send(c, dissect.IEC104UFrame(dissect.IEC104StartDTCon)); err != nil {
						return
					}
					for i := 0; i < o.bursts; i++ {
						if err := o.send(c, iec104Burst(0, 0, 21, byte(0x20+i))); err != nil {
							return
						}
					}
				case dissect.IEC104StopDTAct:
					if err := o.send(c, dissect.IEC104UFrame(dissect.IEC104StopDTCon)); err != nil {
						return
					}
					// Like a field device, wait for the controlling station to
					// release the connection.
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					for {
						if _, err := c.Read(tmp); err != nil {
							return
						}
					}
				case dissect.IEC104TestFRAct:
					if err := o.send(c, dissect.IEC104UFrame(dissect.IEC104TestFRCon)); err != nil {
						return
					}
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func selfSignedTLS(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "outstation"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}

// The captured conversation mirrors a secure IEC 104 fuzzing session: STARTDT,
// two spontaneous bursts, a reset-process command, its negative confirmation,
// one more burst, the client's acknowledgement and STOPDT.
func capturedIEC104Session() []tlsreplay.AppMessage {
	at := func(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }
	records := []struct {
		role tlsreplay.AppRole
		data []byte
		at   time.Duration
	}{
		{tlsreplay.FromClient, dissect.IEC104UFrame(dissect.IEC104StartDTAct), at(10)},
		{tlsreplay.FromServer, dissect.IEC104UFrame(dissect.IEC104StartDTCon), at(40)},
		{tlsreplay.FromServer, iec104Burst(0, 0, 21, 0x01), at(80)},
		{tlsreplay.FromServer, iec104Burst(1, 0, 21, 0x02), at(100)},
		{tlsreplay.FromClient, iec104Reset, at(110)},
		{tlsreplay.FromServer, iec104ResetNeg, at(130)},
		{tlsreplay.FromServer, iec104Burst(3, 1, 21, 0x03), at(150)},
		{tlsreplay.FromClient, dissect.IEC104SFrame(4), at(200)},
		{tlsreplay.FromClient, dissect.IEC104UFrame(dissect.IEC104StopDTAct), at(300)},
		{tlsreplay.FromServer, dissect.IEC104UFrame(dissect.IEC104StopDTCon), at(320)},
	}
	var out []tlsreplay.AppMessage
	for i, r := range records {
		out = append(out, tlsreplay.AppMessage{Role: r.role, Data: r.data, CapturedAt: r.at, CapturedPacket: i, HasCaptureTime: true})
	}
	return out
}

func TestIEC104TLSReterminationSurvivesLiveSequenceAndEventDrift(t *testing.T) {
	cert, roots := selfSignedTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, bursts := range []int{0, 5, 13} {
		t.Run(fmt.Sprintf("bursts-%d", bursts), func(t *testing.T) {
			station := &iec104Outstation{bursts: bursts, failures: make(chan error, 1)}
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				station.serve(c)
			}()
			messages := capturedIEC104Session()
			registry := adapters.DefaultRegistry()
			inner := replay.Session{Transport: replay.TransportTCP, Client: replay.Endpoint{Port: 40054}, Server: replay.Endpoint{Port: 19998}}
			for i, m := range messages {
				dir := replay.ClientToServer
				if m.Role == tlsreplay.FromServer {
					dir = replay.ServerToClient
				}
				inner.Events = append(inner.Events, replay.Event{PacketIndex: i, Direction: dir, Payload: m.Data})
			}
			adapter, score := registry.Best(inner)
			if adapter == nil || adapter.Name() != "iec104" || score == 0 {
				t.Fatalf("inner detection: %v %d", adapter, score)
			}
			state := replay.NewRuntimeState(nil)
			script, err := BuildTLSAdapterScript(messages, adapter, state)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			res, err := tlsreplay.ReTerminateContext(ctx, tlsreplay.ReTermConfig{
				SessionID: "tcp-3", Address: ln.Addr().String(),
				TLSConfig: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"},
				Script:    script, Timeout: 10 * time.Second, ExchangeTimeout: 5 * time.Second,
				Adapter: adapter, State: state, VerifyMode: replay.VerifyLenient,
			})
			select {
			case failure := <-station.failures:
				t.Fatalf("outstation rejected the replay: %v (replay err=%v)", failure, err)
			default:
			}
			if err != nil {
				t.Fatalf("replay: %v", err)
			}
			if res.Requests != 4 || res.Mismatches != 0 || len(res.Differences) != 0 || res.Expected != 3 || res.Observed != 3 {
				t.Fatalf("result: %+v", res)
			}
			// Bursts still in flight at STOPDT need no acknowledgement; the
			// station closes the connection after STOPDT con.
			if station.received != 1 || station.acked > station.sent || station.sent != uint16(2*bursts+1) {
				t.Fatalf("outstation state: %+v", station)
			}
		})
	}
}

func TestIEC104ScriptKeepsOnlyControllingStationExchange(t *testing.T) {
	state := replay.NewRuntimeState(nil)
	script, err := BuildTLSAdapterScript(capturedIEC104Session(), adapters.IEC104{}, state)
	if err != nil {
		t.Fatal(err)
	}
	var roles []string
	for _, m := range script {
		if m.Role == tlsreplay.FromClient {
			roles = append(roles, "C")
		} else {
			roles = append(roles, fmt.Sprintf("S%d", len(m.Expected)))
		}
	}
	if fmt.Sprint(roles) != "[C S1 C S1 C C S1]" {
		t.Fatalf("script shape: %v", roles)
	}
	if _, err := BuildTLSAdapterScript(capturedIEC104Session()[:3], adapters.IEC104{}, state); err != nil {
		t.Fatalf("prefix capture: %v", err)
	}
	truncated := capturedIEC104Session()
	truncated[2].Data = truncated[2].Data[:50]
	if _, err := BuildTLSAdapterScript(truncated, adapters.IEC104{}, state); err == nil {
		t.Fatal("truncated captured APDU must be rejected")
	}
}
