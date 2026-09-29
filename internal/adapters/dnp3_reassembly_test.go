package adapters

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
)

func dnpTransportFrame(source, dest uint16, transport byte, payload []byte) []byte {
	return (dissect.DNP3{Control: 0x44, Source: source, Dest: dest, UserData: append([]byte{transport}, payload...)}).Encode()
}

func dnpAnalogObjects(start byte, values ...byte) []byte {
	b := []byte{30, 1, 0, start, start + byte(len(values)) - 1}
	for _, v := range values {
		b = append(b, 1, v, 0, 0, 0)
	}
	return b
}

func TestDNP3LiveResponseCanChangeBothFragmentationLayers(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	request := dnpTransportFrame(1, 4, 0xc1, []byte{0xc1, 1, 30, 1, 6})
	captured := dnpTransportFrame(4, 1, 0xc3, append([]byte{0xc1, 0x81, 0, 0}, dnpAnalogObjects(0, 42, 43)...))
	session := &replay.Session{ID: "dnp-fragments", Transport: replay.TransportTCP, Events: []replay.Event{{Direction: replay.ClientToServer, Payload: request}, {Direction: replay.ServerToClient, Payload: captured}}}
	done := make(chan error, 1)
	go func() {
		server.SetDeadline(time.Now().Add(3 * time.Second))
		defer server.Close()
		got := make([]byte, len(request))
		if _, err := io.ReadFull(server, got); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(got, request) {
			done <- fmt.Errorf("request drift")
			return
		}
		checkConfirm := func(seq byte) error {
			header := make([]byte, 10)
			if _, err := io.ReadFull(server, header); err != nil {
				return err
			}
			n := int(header[2]) - 5
			tail := make([]byte, n+2*((n+15)/16))
			if _, err := io.ReadFull(server, tail); err != nil {
				return err
			}
			f, _, err := dissect.ParseDNP3(append(header, tail...))
			if err != nil {
				return err
			}
			if f.Source != 1 || f.Dest != 4 || f.AppFunc != 0 || f.AppSeq != seq || f.AppUNS {
				return fmt.Errorf("invalid confirmation: %+v", f)
			}
			return nil
		}
		first := append([]byte{0xa1, 0x81, 0, 0}, dnpAnalogObjects(0, 42)...)
		for _, frame := range [][]byte{dnpTransportFrame(4, 1, 0x40|63, first[:3]), dnpTransportFrame(4, 1, 0x80, first[3:])} {
			if _, err := server.Write(frame); err != nil {
				done <- err
				return
			}
		}
		if err := checkConfirm(1); err != nil {
			done <- err
			return
		}
		last := append([]byte{0x62, 0x81, 0, 0}, dnpAnalogObjects(1, 43)...)
		if _, err := server.Write(dnpTransportFrame(4, 1, 0xc1, last)); err != nil {
			done <- err
			return
		}
		done <- checkConfirm(2)
	}()
	result, err := replay.RunTCPSemanticContext(context.Background(), replay.TCPSemanticConfig{Session: session, Adapter: DNP3{}, Verify: replay.VerifyStrict, Timeout: time.Second, Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }})
	if err != nil || !result.Completed || !result.Matched {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDNP3CapturedConfirmTurnsNormalizeToWholeResponse(t *testing.T) {
	a := DNP3{}
	first := dnpTransportFrame(4, 1, 0xc1, append([]byte{0xa1, 0x81, 0, 0}, dnpAnalogObjects(0, 42)...))
	confirm := dnpTransportFrame(1, 4, 0xc1, []byte{0xc1, 0})
	last := dnpTransportFrame(4, 1, 0xc2, append([]byte{0x42, 0x81, 0, 0}, dnpAnalogObjects(1, 43)...))
	turns, err := a.NormalizeConversation([]replay.ConversationTurn{{Direction: replay.ServerToClient, Payload: first}, {Direction: replay.ClientToServer, Payload: confirm}, {Direction: replay.ServerToClient, Payload: last}})
	if err != nil || len(turns) != 1 {
		t.Fatalf("turns=%+v err=%v", turns, err)
	}
	want, err := a.Decode(replay.ServerToClient, turns[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	live, err := a.Decode(replay.ServerToClient, dnpTransportFrame(4, 1, 0xc9, append([]byte{0xc1, 0x81, 0, 0}, dnpAnalogObjects(0, 42, 43)...)))
	if err != nil {
		t.Fatal(err)
	}
	if diffs := a.Compare(want[0], live[0], replay.VerifyStrict); len(diffs) > 0 {
		t.Fatalf("fragmentation differences leaked into application comparison: %+v", diffs)
	}
}

func TestDNP3UnsolicitedFragmentQueuesLiveConfirmation(t *testing.T) {
	a := DNP3{}
	state := replay.NewRuntimeState(nil)
	frame := dnpTransportFrame(4, 1, 0xc8, []byte{0xff, 0x82, 0, 0})
	m, n, err := a.DecodeAvailableState(replay.ServerToClient, frame, nil, false, state)
	if err != nil || n != len(frame) || len(m) != 1 || len(state.Pending) != 1 {
		t.Fatalf("messages=%v consumed=%d replies=%v err=%v", m, n, state.Pending, err)
	}
	f, _, err := dissect.ParseDNP3(state.Pending[0].Raw)
	if err != nil || !f.AppUNS || f.AppSeq != 15 || f.AppFunc != 0 {
		t.Fatalf("confirmation=%+v err=%v", f, err)
	}
}

func TestDNP3ObjectIdentityRemainsStructuralWhenValueDriftAllowed(t *testing.T) {
	a := DNP3{}
	message := func(index, value byte) replay.Message {
		t.Helper()
		m, err := a.Decode(replay.ServerToClient, dnpTransportFrame(4, 1, 0xc1, append([]byte{0xc1, 0x81, 0, 0}, dnpAnalogObjects(index, value)...)))
		if err != nil {
			t.Fatal(err)
		}
		return m[0]
	}
	want := message(0, 42)
	if diff := a.Compare(want, message(0, 43), replay.VerifyLenient); len(diff) != 1 || diff[0].Structural {
		t.Fatalf("value policy changed: %+v", diff)
	}
	if diff := a.Compare(want, message(1, 42), replay.VerifyLenient); len(diff) != 1 || !diff[0].Structural {
		t.Fatalf("different point index was tolerated: %+v", diff)
	}
}
