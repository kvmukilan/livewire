package ipreasm

import (
	"bytes"
	"testing"

	"github.com/kvmukilan/livewire/internal/wire"
)

func FuzzIPv6FragmentReassembly(f *testing.F) {
	f.Add([]byte("0123456789ABCDEF"), uint8(1), false)
	f.Add(bytes.Repeat([]byte{0xff}, 73), uint8(7), true)
	f.Fuzz(func(t *testing.T, payload []byte, splitSelector uint8, reverse bool) {
		if len(payload) > 4096 {
			t.Skip()
		}
		if len(payload) < 8 {
			payload = append(append([]byte(nil), payload...), make([]byte, 8-len(payload))...)
		}
		full := udpDatagram(1200, 5300, payload)
		// Every non-final fragment must have an 8-byte-aligned payload.
		choices := (len(full) - 1) / 8
		if choices == 0 {
			choices = 1
		}
		split := (int(splitSelector)%choices + 1) * 8
		if split >= len(full) {
			split = len(full) - 1
			split -= split % 8
		}
		if split <= 0 {
			split = 8
		}
		first := makeIPv6Fragment(0x10203040, 0, true, full[:split])
		last := makeIPv6Fragment(0x10203040, split, false, full[split:])
		frames := [][]byte{first, last}
		if reverse {
			frames[0], frames[1] = frames[1], frames[0]
		}
		out, dropped, err := ReassembleAll(frames, wire.LinkEthernet)
		if err != nil || dropped != 0 || len(out) != 1 {
			t.Fatalf("reassembly err=%v dropped=%d frames=%d", err, dropped, len(out))
		}
		packet, err := wire.Parse(out[0], wire.LinkEthernet)
		if err != nil || packet.IsFragment() || !packet.IsIPv6() || !packet.IsUDP() {
			t.Fatalf("rebuilt packet invalid: err=%v", err)
		}
		if !bytes.Equal(packet.Payload(), payload) {
			t.Fatalf("payload length=%d want=%d", len(packet.Payload()), len(payload))
		}
	})
}

func FuzzMalformedFragmentFrames(f *testing.F) {
	full := udpDatagram(1200, 5300, []byte("0123456789ABCDEF"))
	f.Add(makeIPv6Fragment(7, 0, true, full[:16]), makeIPv6Fragment(7, 16, false, full[16:]))
	f.Add([]byte{0, 1, 2}, []byte{3, 4, 5})
	f.Fuzz(func(t *testing.T, first, second []byte) {
		if len(first)+len(second) > 1<<20 {
			t.Skip()
		}
		_, _, _ = ReassembleAll([][]byte{first, second}, wire.LinkEthernet)
		_ = CountFragments([][]byte{first, second}, wire.LinkEthernet)
	})
}
