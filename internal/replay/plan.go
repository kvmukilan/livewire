package replay

import (
	"net/netip"
	"sort"
)

func BuildPlan(t *Trace, profile Profile, registry *Registry) ReplayPlan {
	if registry == nil {
		registry = NewRegistry()
	}
	p := ReplayPlan{Profile: profile, Packets: t.Packets}
	groups := registry.CoordinatedGroups(t)
	groupMembers := map[string]bool{}
	if profile == ProfileFunctional || profile == ProfileTiming {
		for _, item := range groups {
			for _, id := range item.Group.RelatedSessionIDs {
				groupMembers[id] = true
			}
		}
	}
	sessions := map[string]*Session{}
	for _, session := range t.Sessions {
		sessions[session.ID] = session
	}
	for _, s := range t.Sessions {
		if groupMembers[s.ID] {
			continue
		}
		e := PlanEntry{SessionID: s.ID, Transport: s.Transport, PacketIndexes: packetIndexes(s.Events), Warnings: append([]string(nil), s.Warnings...), Blockers: append([]string(nil), s.Blockers...)}
		if item, ok := groups[s.ID]; ok && (profile == ProfileFunctional || profile == ProfileTiming) {
			e.Adapter = item.Adapter
			e.Driver = item.Adapter + "-coordinator"
			e.Mode = ModeCoordinated
			e.Fidelity = FidelitySemantic
			e.RelatedSessionIDs = append([]string(nil), item.Group.RelatedSessionIDs...)
			e.Warnings = append(e.Warnings, item.Group.Warnings...)
			e.Blockers = append(e.Blockers, item.Group.Blockers...)
			for _, id := range item.Group.RelatedSessionIDs {
				if related := sessions[id]; related != nil {
					e.PacketIndexes = append(e.PacketIndexes, packetIndexes(related.Events)...)
					e.Warnings = append(e.Warnings, related.Warnings...)
					e.Blockers = append(e.Blockers, related.Blockers...)
				}
			}
			sort.Ints(e.PacketIndexes)
			e.Transformations = []string{"control and negotiated data sessions coordinated by " + item.Adapter}
			if len(e.Blockers) > 0 {
				e.Driver, e.Mode, e.Fidelity = "none", ModeBlocked, FidelityBlocked
			}
			p.Entries = append(p.Entries, e)
			continue
		}
		if eventsTruncated(s.Events) {
			e.Blockers = append(e.Blockers, "capture contains snaplen-truncated frames; missing bytes cannot be replayed")
		}
		if s.Transport == TransportTCP && profile != ProfileWire {
			if _, _, err := TCPPayloadStreams(s); err != nil {
				e.Blockers = append(e.Blockers, "adaptive TCP payload reconstruction failed: "+err.Error())
			}
		}
		if len(e.Blockers) > 0 {
			e.Driver, e.Mode, e.Fidelity = "none", ModeBlocked, FidelityBlocked
			p.Entries = append(p.Entries, e)
			continue
		}
		if a, score := registry.Best(*s); a != nil && score > 0 && (profile == ProfileFunctional || profile == ProfileTiming) && !multicastSession(s) && !unsolicitedOneSided(s) {
			e.Adapter, e.Driver, e.Mode, e.Fidelity = a.Name(), semanticDriver(s.Transport), ModeSemantic, FidelitySemantic
			e.Transformations = []string{"application messages decoded and dynamic fields prepared by " + a.Name()}
		} else if profile == ProfileWire || !statefulTransport(s.Transport) || multicastSession(s) || unsolicitedOneSided(s) || fragmentedNeedsWire(s, profile) {
			e.Driver, e.Mode, e.Fidelity = "frame-injector", ModeWire, FidelityWire
			e.Transformations = []string{"frames emitted without live protocol adaptation"}
			if multicastSession(s) {
				e.Warnings = append(e.Warnings, "multicast/broadcast exchange uses wire replay; no single live peer can be correlated")
			}
			if unsolicitedOneSided(s) {
				e.Warnings = append(e.Warnings, "receive-only UDP exchange uses wire replay in one-sided mode; use lab to originate it from a simulated server")
			}
			if fragmentedNeedsWire(s, profile) {
				e.Warnings = append(e.Warnings, "fragmented session uses original-frame wire replay because the requested stateful transport behavior cannot be safely adapted")
			}
		} else {
			e.Driver = statefulDriver(s.Transport)
			e.Mode = ModeStateful
			switch profile {
			case ProfileTiming:
				e.Fidelity = FidelityTiming
			case ProfileTransport:
				e.Fidelity = FidelityTransport
			default:
				e.Fidelity = FidelityTransport
			}
			e.Transformations = []string{"addresses and checksums retargeted", "live replies correlated at the transport layer"}
		}
		p.Entries = append(p.Entries, e)
	}
	if len(t.Raw) > 0 {
		raw := PlanEntry{
			SessionID: "raw-0", Transport: TransportRaw, Driver: "frame-injector", Mode: ModeWire, Fidelity: FidelityWire,
			PacketIndexes: packetIndexes(t.Raw),
			Warnings:      []string{"frames have no supported stateful session model and will only be emitted in explicit wire mode"},
		}
		if eventsTruncated(t.Raw) {
			raw.Driver, raw.Mode, raw.Fidelity = "none", ModeBlocked, FidelityBlocked
			raw.Blockers = []string{"raw lane contains snaplen-truncated frames; exact wire replay is impossible"}
		}
		p.Entries = append(p.Entries, raw)
	}
	return p
}

func semanticDriver(t Transport) string {
	switch t {
	case TransportTCP:
		return "semantic-tcp"
	case TransportUDP:
		return "semantic-datagram"
	case TransportICMP4, TransportICMP6:
		return "semantic-icmp"
	default:
		return "semantic-adapter"
	}
}

func statefulDriver(t Transport) string {
	switch t {
	case TransportTCP:
		return "tcp-state-machine"
	case TransportUDP:
		return "udp-turns"
	case TransportICMP4, TransportICMP6:
		return "icmp-echo"
	default:
		return "none"
	}
}

func eventsTruncated(events []Event) bool {
	for _, event := range events {
		if event.Record != nil && event.Record.OrigLen > 0 && (event.Record.CapLen < event.Record.OrigLen || len(event.Record.Data) < event.Record.OrigLen) {
			return true
		}
	}
	return false
}

func fragmentedNeedsWire(s *Session, profile Profile) bool {
	if !s.Fragmented {
		return false
	}
	return profile == ProfileTransport || s.Transport == TransportTCP
}

func statefulTransport(t Transport) bool {
	return t == TransportTCP || t == TransportUDP || t == TransportICMP4 || t == TransportICMP6
}

func multicastSession(s *Session) bool {
	return isGroup(s.Client.IP) || isGroup(s.Server.IP)
}

func unsolicitedOneSided(s *Session) bool {
	if s.Transport != TransportUDP {
		return false
	}
	sawServer := false
	for _, event := range s.Events {
		if event.Direction == ClientToServer {
			return false
		}
		sawServer = sawServer || event.Direction == ServerToClient
	}
	return sawServer
}

func isGroup(a netip.Addr) bool {
	return a.IsValid() && (a.IsMulticast() || a == netip.IPv4Unspecified() || a == netip.IPv6Unspecified())
}
