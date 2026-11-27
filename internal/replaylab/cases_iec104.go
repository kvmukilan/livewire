package replaylab

import (
	"context"
	"fmt"
	"net"

	"github.com/kvmukilan/livewire/internal/dissect"
)

func init() {
	for _, encrypted := range []bool{false, true} {
		encrypted := encrypted
		name := "iec104"
		if encrypted {
			name += "-tls"
		}
		Register(Case{Name: name, Setup: func(ctx context.Context, dir string) (*Fixture, error) {
			return setupIEC104Fixture(ctx, dir, encrypted)
		}})
	}
}

const (
	labIEC104Points = 9
	// labIEC104Window is the station's k: it stops sending while this many
	// I frames are unacknowledged.
	labIEC104Window = 12
)

func labIEC104Frame(sendSeq, recvSeq uint16, typeID, cot byte, payload ...byte) []byte {
	asdu := append([]byte{typeID, 1, cot, 0, 1, 0}, payload...)
	return dissect.IEC104{Raw: append([]byte{0x68, byte(4 + len(asdu)), 0, 0, 0, 0}, asdu...), Format: dissect.IEC104I, SendSeq: sendSeq, RecvSeq: recvSeq}.Encode()
}

// labIEC104Interrogation is the station's answer to a general interrogation:
// activation confirmation, the points, activation termination. A live station
// also reports one spontaneous change in the middle of it.
func labIEC104Interrogation(spontaneous bool) [][]byte {
	frames := [][]byte{labIEC104Frame(0, 1, 100, 7, 0, 0, 0, 20)}
	for i := 0; i < labIEC104Points; i++ {
		if spontaneous && i == 3 {
			frames = append(frames, labIEC104Frame(0, 1, 1, 3, 200, 0, 0, 1))
		}
		frames = append(frames, labIEC104Frame(0, 1, 1, 20, byte(i+1), 0, 0, byte(i&1)))
	}
	return append(frames, labIEC104Frame(0, 1, 100, 10, 0, 0, 0, 20))
}

func setupIEC104Fixture(ctx context.Context, dir string, encrypted bool) (*Fixture, error) {
	var burst []byte
	for i, frame := range labIEC104Interrogation(false) {
		f, _, err := dissect.ParseIEC104(frame)
		if err != nil {
			return nil, err
		}
		f.SendSeq = uint16(i)
		burst = append(burst, f.Encode()...)
	}
	captured := uint16(labIEC104Points + 2)
	exchanges := []Exchange{
		{Client: dissect.IEC104UFrame(dissect.IEC104StartDTAct), Server: dissect.IEC104UFrame(dissect.IEC104StartDTCon)},
		{Client: labIEC104Frame(0, 0, 100, 6, 0, 0, 0, 20), Server: burst},
		{Client: append(dissect.IEC104SFrame(captured), dissect.IEC104UFrame(dissect.IEC104StopDTAct)...), Server: dissect.IEC104UFrame(dissect.IEC104StopDTCon)},
	}
	handler := func(conn net.Conn, stats *Stats) error {
		var buffer []byte
		var sent, acked, received uint16
		read := func() ([]dissect.IEC104, error) {
			chunk := make([]byte, 4096)
			n, err := conn.Read(chunk)
			if err != nil {
				return nil, err
			}
			buffer = append(buffer, chunk[:n]...)
			frames, left, err := dissect.ParseIEC104Stream(buffer)
			if err != nil {
				return nil, err
			}
			buffer = append([]byte(nil), buffer[len(buffer)-left:]...)
			for _, f := range frames {
				if f.Format == dissect.IEC104U {
					continue
				}
				if f.RecvSeq < acked || f.RecvSeq > sent {
					return nil, fmt.Errorf("IEC 104 client N(R)=%d outside [%d,%d]", f.RecvSeq, acked, sent)
				}
				acked = f.RecvSeq
			}
			return frames, nil
		}
		for {
			frames, err := read()
			if err != nil {
				return err
			}
			for _, f := range frames {
				switch {
				case f.Format == dissect.IEC104U && f.UFunc == dissect.IEC104StartDTAct:
					stats.Request()
					if _, err := conn.Write(dissect.IEC104UFrame(dissect.IEC104StartDTCon)); err != nil {
						return err
					}
					stats.Response()
				case f.Format == dissect.IEC104I:
					if f.SendSeq != received || f.TypeID != 100 || f.COT != 6 {
						return fmt.Errorf("IEC 104 unexpected command N(S)=%d type=%d cause=%d", f.SendSeq, f.TypeID, f.COT)
					}
					received++
					stats.Request()
					for _, raw := range labIEC104Interrogation(true) {
						for sent-acked >= labIEC104Window {
							if _, err := read(); err != nil {
								return fmt.Errorf("IEC 104 send window was never acknowledged: %w", err)
							}
						}
						out, _, err := dissect.ParseIEC104(raw)
						if err != nil {
							return err
						}
						out.SendSeq, out.RecvSeq = sent, received
						sent++
						if _, err := conn.Write(out.Encode()); err != nil {
							return err
						}
						if !out.Unsolicited() {
							stats.Response()
						}
					}
					stats.Note("IEC 104 interrogation answered with %d frames inside a window of %d", sent, labIEC104Window)
				case f.Format == dissect.IEC104U && f.UFunc == dissect.IEC104StopDTAct:
					if acked != sent {
						return fmt.Errorf("IEC 104 client acknowledged %d of %d frames before STOPDT", acked, sent)
					}
					stats.Request()
					if _, err := conn.Write(dissect.IEC104UFrame(dissect.IEC104StopDTCon)); err != nil {
						return err
					}
					stats.Response()
					return nil
				}
			}
		}
	}
	return SetupStreamFixture(ctx, dir, exchanges, handler, encrypted)
}
