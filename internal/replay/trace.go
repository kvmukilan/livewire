package replay

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/kvmukilan/livewire/internal/flow"
	"github.com/kvmukilan/livewire/internal/ipreasm"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

type ExtractOptions struct {
	UDPIdle time.Duration
}

type tupleBuilder struct {
	transport  Transport
	key        flow.Key
	clientDir  flow.Dir
	knownDir   bool
	first      int
	events     []tupleEvent
	fragmented bool
}

type tupleEvent struct {
	idx         int
	at          time.Duration
	dir         flow.Dir
	rec         *pcapio.Record
	payload     []byte
	fragmented  bool
	reassembled []byte
}

type icmpKey struct {
	a, b netip.Addr
	id   uint16
	v6   bool
}

type icmpBuilder struct {
	key        icmpKey
	client     netip.Addr
	server     netip.Addr
	first      int
	events     []Event
	fragmented bool
}

type captureFragmentKey struct {
	src, dst netip.Addr
	id       uint32
	next     uint8
	link     wire.LinkType
	iface    uint32
}

type captureFragmentSet struct {
	indexes  []int
	frames   [][]byte
	bytes    int
	started  time.Time
	link     wire.LinkType
	hasFirst bool
	hasLast  bool
}

type reassembledFragment struct {
	frame  []byte
	leader int
}

// ExtractTrace classifies every record into a TCP/UDP/ICMP session or an
// explicit raw lane. No packet is discarded.
func ExtractTrace(records []*pcapio.Record, opts ExtractOptions) *Trace {
	if opts.UDPIdle <= 0 {
		opts.UDPIdle = 30 * time.Second
	}
	t := &Trace{Packets: len(records)}
	if len(records) == 0 {
		return t
	}
	t.Started = records[0].Time
	for _, r := range records[1:] {
		if r.Time.Before(t.Started) {
			t.Started = r.Time
		}
	}

	fragments := classifyFragments(records)
	tcp := map[flow.Key]*tupleBuilder{}
	udp := map[flow.Key][]*tupleBuilder{}
	icmp := map[icmpKey]*icmpBuilder{}
	for idx, rec := range records {
		at := rec.Time.Sub(t.Started)
		p, err := wire.Parse(rec.Data, rec.LinkType)
		if err != nil {
			t.Raw = append(t.Raw, Event{PacketIndex: idx, At: at, Direction: DirectionUnknown, Record: rec})
			continue
		}
		if p.IsFragment() && fragments[idx] == nil {
			t.Raw = append(t.Raw, Event{PacketIndex: idx, At: at, Direction: DirectionUnknown, Record: rec})
			continue
		}
		fragmented := false
		var reassembled []byte
		if f := fragments[idx]; f != nil {
			p, err = wire.Parse(f.frame, rec.LinkType)
			if err != nil {
				t.Raw = append(t.Raw, Event{PacketIndex: idx, At: at, Direction: DirectionUnknown, Record: rec})
				continue
			}
			fragmented = true
			if idx == f.leader {
				reassembled = append([]byte(nil), f.frame...)
			}
		}
		if p.IsTCP() || p.IsUDP() {
			key, dir, ok := flow.KeyFromPacket(p)
			if !ok {
				t.Raw = append(t.Raw, Event{PacketIndex: idx, At: at, Direction: DirectionUnknown, Record: rec})
				continue
			}
			var payload []byte
			if !fragmented || len(reassembled) > 0 {
				payload = append([]byte(nil), p.Payload()...)
			}
			ev := tupleEvent{idx: idx, at: at, dir: dir, rec: rec, payload: payload, fragmented: fragmented, reassembled: reassembled}
			if p.IsTCP() {
				b := tcp[key]
				if b == nil {
					b = &tupleBuilder{transport: TransportTCP, key: key, first: idx}
					tcp[key] = b
				}
				b.fragmented = b.fragmented || fragmented
				if p.HasFlags(wire.FlagSYN) && !p.HasFlags(wire.FlagACK) {
					b.clientDir, b.knownDir = dir, true
				}
				b.events = append(b.events, ev)
				continue
			}

			list := udp[key]
			var b *tupleBuilder
			if len(list) > 0 {
				last := list[len(list)-1]
				if len(last.events) > 0 && at-last.events[len(last.events)-1].at <= opts.UDPIdle {
					b = last
				}
			}
			if b == nil {
				b = &tupleBuilder{transport: TransportUDP, key: key, first: idx}
				udp[key] = append(list, b)
			}
			b.fragmented = b.fragmented || fragmented
			if !b.knownDir {
				b.clientDir = inferUDPClientDir(key, dir)
				b.knownDir = true
			}
			b.events = append(b.events, ev)
			continue
		}

		request, id, _, ok := p.ICMPEcho()
		if ok {
			a, b := orderedIPs(p.SrcIP(), p.DstIP())
			k := icmpKey{a: a, b: b, id: id, v6: p.IsIPv6()}
			ib := icmp[k]
			if ib == nil {
				ib = &icmpBuilder{key: k, first: idx}
				icmp[k] = ib
			}
			ib.fragmented = ib.fragmented || fragmented
			if request || !ib.client.IsValid() {
				if request {
					ib.client, ib.server = p.SrcIP(), p.DstIP()
				} else {
					ib.client, ib.server = p.DstIP(), p.SrcIP()
				}
			}
			d := ClientToServer
			if p.SrcIP() != ib.client {
				d = ServerToClient
			}
			var payload []byte
			if !fragmented || len(reassembled) > 0 {
				payload = append([]byte(nil), p.Payload()...)
			}
			ib.events = append(ib.events, Event{PacketIndex: idx, At: at, Direction: d, Record: rec, Payload: payload, Fragmented: fragmented, Reassembled: reassembled})
			continue
		}

		t.Raw = append(t.Raw, Event{PacketIndex: idx, At: at, Direction: DirectionUnknown, Record: rec})
	}

	type ordered struct {
		first int
		s     *Session
	}
	var all []ordered
	for _, b := range tcp {
		all = append(all, ordered{b.first, b.session()})
	}
	for _, list := range udp {
		for _, b := range list {
			all = append(all, ordered{b.first, b.session()})
		}
	}
	for _, b := range icmp {
		tr := TransportICMP4
		if b.key.v6 {
			tr = TransportICMP6
		}
		s := &Session{Transport: tr, Client: Endpoint{IP: b.client}, Server: Endpoint{IP: b.server}, Events: b.events, Fragmented: b.fragmented}
		if b.fragmented {
			s.Warnings = append(s.Warnings, "complete IP fragment set reassembled for classification; original fragments retained for wire replay")
		}
		all = append(all, ordered{b.first, s})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].first < all[j].first })
	counts := map[Transport]int{}
	for _, x := range all {
		x.s.ID = fmt.Sprintf("%s-%d", x.s.Transport, counts[x.s.Transport])
		counts[x.s.Transport]++
		t.Sessions = append(t.Sessions, x.s)
	}
	return t
}

func (b *tupleBuilder) session() *Session {
	client := b.key.Lo
	server := b.key.Hi
	if b.clientDir == flow.DirHiToLo {
		client, server = server, client
	}
	s := &Session{Transport: b.transport, Client: Endpoint{IP: client.Addr, Port: client.Port}, Server: Endpoint{IP: server.Addr, Port: server.Port}, Fragmented: b.fragmented}
	for _, e := range b.events {
		d := ServerToClient
		if e.dir == b.clientDir {
			d = ClientToServer
		}
		s.Events = append(s.Events, Event{PacketIndex: e.idx, At: e.at, Direction: d, Record: e.rec, Payload: e.payload, Fragmented: e.fragmented, Reassembled: e.reassembled})
	}
	if b.transport == TransportTCP && !b.knownDir {
		s.Warnings = append(s.Warnings, "TCP capture starts mid-session; client direction inferred from the first packet")
	}
	if b.fragmented {
		s.Warnings = append(s.Warnings, "complete IP fragment set reassembled for classification; original fragments retained for wire replay")
	}
	return s
}

// classifyFragments reassembles complete IPv4/IPv6 datagrams for transport and
// adapter classification. Each original fragment still becomes its own Event;
// only the earliest fragment carries the synthetic whole datagram used by
// functional replay. Incomplete or unreasonably large sets remain raw lanes.
func classifyFragments(records []*pcapio.Record) map[int]*reassembledFragment {
	const maxSetBytes = 16 << 20
	const maxSetFrames = 4096
	sets := map[captureFragmentKey]*captureFragmentSet{}
	out := map[int]*reassembledFragment{}
	for idx, rec := range records {
		p, err := wire.Parse(rec.Data, rec.LinkType)
		if err != nil || !p.IsFragment() {
			continue
		}
		key := captureFragmentKey{src: p.SrcIP(), dst: p.DstIP(), next: p.Proto(), link: rec.LinkType, iface: rec.InterfaceID}
		if p.IsIPv6() {
			id, _, _, next, _, _, ok := p.IPv6Fragment()
			if !ok {
				continue
			}
			key.id, key.next = id, next
		} else {
			key.id = uint32(p.FragmentID())
		}
		set := sets[key]
		if set == nil || rec.Time.Sub(set.started) > 30*time.Second || len(set.frames) >= maxSetFrames || set.bytes+len(rec.Data) > maxSetBytes {
			set = &captureFragmentSet{started: rec.Time, link: rec.LinkType}
			sets[key] = set
		}
		set.indexes = append(set.indexes, idx)
		set.frames = append(set.frames, rec.Data)
		set.bytes += len(rec.Data)
		set.hasFirst = set.hasFirst || p.FragmentOffset() == 0
		set.hasLast = set.hasLast || !p.MoreFragments()
		if !set.hasFirst || !set.hasLast {
			continue
		}
		whole, dropped, _ := ipreasm.ReassembleAll(set.frames, set.link)
		if dropped != 0 || len(whole) != 1 {
			continue
		}
		if rp, err := wire.Parse(whole[0], set.link); err != nil || rp.IsFragment() {
			delete(sets, key)
			continue
		}
		info := &reassembledFragment{frame: append([]byte(nil), whole[0]...), leader: set.indexes[0]}
		for _, packetIndex := range set.indexes {
			out[packetIndex] = info
		}
		delete(sets, key)
	}
	return out
}

func inferUDPClientDir(k flow.Key, first flow.Dir) flow.Dir {
	loServer := likelyServerPort(k.Lo.Port)
	hiServer := likelyServerPort(k.Hi.Port)
	switch {
	case loServer && !hiServer:
		return flow.DirHiToLo
	case hiServer && !loServer:
		return flow.DirLoToHi
	default:
		return first
	}
}

func likelyServerPort(p uint16) bool {
	if p <= 1024 {
		return true
	}
	switch p {
	case 1883, 8883, 20000, 47808:
		return true
	default:
		return false
	}
}

func orderedIPs(a, b netip.Addr) (netip.Addr, netip.Addr) {
	if a.Compare(b) <= 0 {
		return a, b
	}
	return b, a
}
