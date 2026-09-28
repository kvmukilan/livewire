package adapters

import (
	"fmt"
	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
)

type dnpFragment struct {
	Active bool
	Next   uint8
	Bytes  int
}

func (DNP3) Observe(dir replay.Direction, expected, actual replay.Message, state *replay.RuntimeState) error {
	frames, rest, err := dissect.ParseDNP3Stream(actual.Raw)
	if err != nil {
		return err
	}
	if rest != 0 {
		return fmt.Errorf("dnp3: incomplete observed frame")
	}
	learnedUnsolicited := false
	for _, d := range frames {
		key := fmt.Sprintf("dnp3.fragments.%s.%d.%d", dir, d.Source, d.Dest)
		fragment, _ := state.Protocol[key].(dnpFragment)
		if d.HasTransport {
			if dir == replay.ClientToServer {
				state.Protocol[dnpTxKey(d.Source, d.Dest)] = (d.TransportSeq + 1) & 63
			}
			if d.TransportFIR {
				if fragment.Active {
					return fmt.Errorf("dnp3: new fragment before previous transport message completed")
				}
				fragment = dnpFragment{Active: true}
			}
			if fragment.Active && !d.TransportFIR && d.TransportSeq != fragment.Next {
				return fmt.Errorf("dnp3: transport fragment sequence gap")
			}
			fragment.Next = (d.TransportSeq + 1) & 63
			fragment.Bytes += len(d.UserData)
			if fragment.Bytes > maxRuleFrame {
				return fmt.Errorf("dnp3: fragmented message exceeds limit")
			}
			if d.TransportFIN {
				fragment = dnpFragment{}
			}
			state.Protocol[key] = fragment
		}
		if dir == replay.ServerToClient && d.TransportFIR && d.HasApp && d.AppUNS && !learnedUnsolicited {
			w, _, e := dissect.ParseDNP3(expected.Raw)
			if e != nil {
				return e
			}
			state.Learned[dnpUnsolicitedKey(w.Source, w.Dest, w.AppSeq)] = []byte{d.AppSeq}
			learnedUnsolicited = true
		}
	}
	return nil
}

func dnpUnsolicitedKey(source, dest uint16, seq uint8) string {
	return fmt.Sprintf("dnp3.unsolicited.%d.%d.%d", source, dest, seq)
}
