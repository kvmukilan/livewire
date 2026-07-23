package lab

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

type SimulatorConfig struct {
	Mode          string // pass | nat | firewall | proxy
	NATClientIP   netip.Addr
	NATClientPort uint16
	ProxyIP       netip.Addr
	ProxySeqDelta uint32
	Delay         time.Duration
	DropEvery     int
	Duplicate     int
	Reorder       int
	MTU           int
}

// DUTSimulator is an in-memory dual-interface device used by end-to-end tests.
// It covers pass-through, NAT/PAT, firewall rejection, TCP sequence proxying,
// delay, loss, duplication, bounded reorder, and MTU changes.
type DUTSimulator struct {
	mu        sync.Mutex
	cfg       SimulatorConfig
	clientRX  chan []byte
	serverRX  chan []byte
	count     [2]int
	held      [2][][]byte
	natClient replayTuple
	natPublic replayTuple
}

type replayTuple struct {
	ip   netip.Addr
	port uint16
}

func NewDUTSimulator(cfg SimulatorConfig) (*DUTSimulator, error) {
	if cfg.Mode == "" {
		cfg.Mode = "pass"
	}
	switch cfg.Mode {
	case "pass", "nat", "firewall", "proxy":
	default:
		return nil, fmt.Errorf("lab simulator: unknown mode %q", cfg.Mode)
	}
	if cfg.Mode == "nat" && !cfg.NATClientIP.IsValid() {
		return nil, fmt.Errorf("lab simulator: nat mode needs NATClientIP")
	}
	if cfg.Duplicate < 0 || cfg.Reorder < 0 || cfg.DropEvery < 0 || cfg.MTU < 0 {
		return nil, fmt.Errorf("lab simulator: invalid impairment")
	}
	return &DUTSimulator{cfg: cfg, clientRX: make(chan []byte, 1024), serverRX: make(chan []byte, 1024)}, nil
}

func (s *DUTSimulator) Backends() Backends {
	return Backends{
		ClientTX: &simSender{s: s, direction: 0}, ClientRX: &simReceiver{ch: s.clientRX},
		ServerTX: &simSender{s: s, direction: 1}, ServerRX: &simReceiver{ch: s.serverRX},
	}
}

func (s *DUTSimulator) process(direction int, frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count[direction]++
	if s.cfg.DropEvery > 0 && s.count[direction]%s.cfg.DropEvery == 0 {
		return nil
	}
	if s.cfg.Mode == "firewall" {
		if p, err := wire.Parse(frame, wire.LinkEthernet); err == nil && p.IsTCP() {
			if rst := synthRST(frame); len(rst) > 0 {
				s.deliverLocked(1-direction, rst)
			}
		}
		return nil
	}
	frames := [][]byte{append([]byte(nil), frame...)}
	for i := range frames {
		frames[i] = s.transform(direction, frames[i])
	}
	if s.cfg.MTU > 0 {
		var fragmented [][]byte
		for _, f := range frames {
			parts, _ := fragmentForMTU(f, wire.LinkEthernet, s.cfg.MTU, uint32(s.count[direction]))
			fragmented = append(fragmented, parts...)
		}
		frames = fragmented
	}
	for _, f := range frames {
		for n := 0; n <= s.cfg.Duplicate; n++ {
			s.enqueueLocked(direction, append([]byte(nil), f...))
		}
	}
	return nil
}

func (s *DUTSimulator) transform(direction int, frame []byte) []byte {
	p, err := wire.Parse(frame, wire.LinkEthernet)
	if err != nil {
		return frame
	}
	switch s.cfg.Mode {
	case "nat":
		if direction == 0 {
			s.natClient = replayTuple{p.SrcIP(), p.SrcPort()}
			port := s.cfg.NATClientPort
			if port == 0 {
				port = p.SrcPort()
			}
			s.natPublic = replayTuple{s.cfg.NATClientIP, port}
			p.SetSrcIP(s.natPublic.ip)
			p.SetSrcPort(s.natPublic.port)
		} else if s.natClient.ip.IsValid() {
			p.SetDstIP(s.natClient.ip)
			p.SetDstPort(s.natClient.port)
		}
	case "proxy":
		if s.cfg.ProxyIP.IsValid() {
			if direction == 0 {
				p.SetSrcIP(s.cfg.ProxyIP)
			} else {
				p.SetDstIP(s.cfg.ProxyIP)
			}
		}
		if p.IsTCP() && s.cfg.ProxySeqDelta != 0 {
			if direction == 0 {
				p.SetSeq(units.Seq(p.Seq().Uint32() + s.cfg.ProxySeqDelta))
			} else {
				p.SetAck(units.Ack(p.AckNum().Uint32() - s.cfg.ProxySeqDelta))
			}
		}
	}
	p.RecalcChecksums()
	return p.Buf
}

func (s *DUTSimulator) enqueueLocked(direction int, frame []byte) {
	if s.cfg.Reorder > 1 {
		s.held[direction] = append(s.held[direction], frame)
		if len(s.held[direction]) < s.cfg.Reorder {
			return
		}
		for i := len(s.held[direction]) - 1; i >= 0; i-- {
			s.deliverLocked(direction, s.held[direction][i])
		}
		s.held[direction] = nil
		return
	}
	s.deliverLocked(direction, frame)
}

func (s *DUTSimulator) deliverLocked(direction int, frame []byte) {
	ch := s.serverRX
	if direction == 1 {
		ch = s.clientRX
	}
	deliver := func() {
		select {
		case ch <- frame:
		default:
		}
	}
	if s.cfg.Delay > 0 {
		time.AfterFunc(s.cfg.Delay, deliver)
	} else {
		deliver()
	}
}

func (s *DUTSimulator) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for direction := range s.held {
		for i := len(s.held[direction]) - 1; i >= 0; i-- {
			s.deliverLocked(direction, s.held[direction][i])
		}
		s.held[direction] = nil
	}
}

type simSender struct {
	s         *DUTSimulator
	direction int
}

func (s *simSender) Send(frame []byte) error                       { return s.s.process(s.direction, frame) }
func (s *simSender) Recv([]byte, time.Duration) (int, bool, error) { return 0, false, nil }
func (s *simSender) Now() time.Time                                { return time.Now() }
func (s *simSender) LinkType() wire.LinkType                       { return wire.LinkEthernet }
func (s *simSender) Caps() backend.Capabilities                    { return backend.Layer2 | backend.BatchSend }
func (s *simSender) Close() error                                  { return nil }

type simReceiver struct{ ch <-chan []byte }

func (s *simReceiver) Send([]byte) error {
	return fmt.Errorf("lab simulator: receive endpoint cannot send")
}
func (s *simReceiver) Recv(buf []byte, timeout time.Duration) (int, bool, error) {
	if timeout <= 0 {
		select {
		case frame := <-s.ch:
			return copy(buf, frame), true, nil
		default:
			return 0, false, nil
		}
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case frame := <-s.ch:
		return copy(buf, frame), true, nil
	case <-t.C:
		return 0, false, nil
	}
}
func (s *simReceiver) Now() time.Time             { return time.Now() }
func (s *simReceiver) LinkType() wire.LinkType    { return wire.LinkEthernet }
func (s *simReceiver) Caps() backend.Capabilities { return backend.Layer2 | backend.CanReceive }
func (s *simReceiver) Close() error               { return nil }

func synthRST(frame []byte) []byte {
	p, err := wire.Parse(append([]byte(nil), frame...), wire.LinkEthernet)
	if err != nil || !p.IsTCP() {
		return nil
	}
	srcIP, dstIP, srcPort, dstPort := p.SrcIP(), p.DstIP(), p.SrcPort(), p.DstPort()
	seq, ack := p.Seq().Uint32(), p.AckNum().Uint32()
	segLen := p.SegmentLen()
	p.SetSrcIP(dstIP)
	p.SetDstIP(srcIP)
	p.SetSrcPort(dstPort)
	p.SetDstPort(srcPort)
	p.SetSeq(units.Seq(ack))
	p.SetAck(units.Ack(seq + segLen))
	p.SetFlags(wire.FlagRST | wire.FlagACK)
	out := p.RebuildWithPayload(nil)
	if np, err := wire.Parse(out, wire.LinkEthernet); err == nil {
		np.RecalcChecksums()
		return np.Buf
	}
	return out
}
