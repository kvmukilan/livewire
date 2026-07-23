package lab

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/kvmukilan/livewire/internal/replay"
)

// BuildReplayPlan describes the drivers the two-sided harness will actually
// execute. It is deliberately separate from the one-sided planner: lab actors
// adapt both transport endpoints and do not claim application semantics.
func BuildReplayPlan(trace *replay.Trace, profile replay.Profile) replay.ReplayPlan {
	profile = normalizedLabProfile(profile)
	plan := replay.ReplayPlan{Profile: profile}
	if trace == nil {
		return plan
	}
	plan.Packets = trace.Packets
	for _, session := range trace.Sessions {
		entry := replay.PlanEntry{
			SessionID: session.ID, Transport: session.Transport,
			PacketIndexes: labPacketIndexes(session.Events),
			Warnings:      append([]string(nil), session.Warnings...),
		}
		for _, blocker := range session.Blockers {
			entry.Warnings = append(entry.Warnings, "one-sided application blocker does not prevent opaque two-sided transport: "+blocker)
		}
		if truncatedLabEvents(session.Events) {
			entry.Blockers = append(entry.Blockers, "capture contains snaplen-truncated frames; missing wire bytes cannot be reproduced")
		}
		if profile != replay.ProfileWire && session.Transport == replay.TransportTCP {
			if _, _, err := replay.TCPPayloadStreams(session); err != nil {
				entry.Blockers = append(entry.Blockers, "two-sided TCP actor cannot establish a complete captured sequence space: "+err.Error())
			}
		}
		if len(entry.Blockers) > 0 {
			entry.Driver, entry.Mode, entry.Fidelity = "none", replay.ModeBlocked, replay.FidelityBlocked
			plan.Entries = append(plan.Entries, entry)
			continue
		}
		if profile == replay.ProfileWire || labGroupEndpoint(session.Client.IP) || labGroupEndpoint(session.Server.IP) {
			entry.Driver, entry.Mode, entry.Fidelity = "frame-injector", replay.ModeWire, replay.FidelityWire
			entry.Transformations = []string{"configured topology link and endpoint mappings applied; captured frame behavior otherwise preserved"}
			if profile != replay.ProfileWire {
				entry.Warnings = append(entry.Warnings, "multicast/broadcast session uses explicit wire actors because no single peer response can be statefully correlated")
			}
		} else {
			entry.Driver, entry.Mode = labDriver(session.Transport), replay.ModeStateful
			entry.Fidelity = replay.FidelityTransport
			if profile == replay.ProfileTiming {
				entry.Fidelity = replay.FidelityTiming
			}
			entry.Transformations = []string{"both captured endpoints retargeted through the DUT", "opposite-direction actors gated on observed DUT crossings"}
			if session.Transport == replay.TransportTCP {
				entry.Transformations = append(entry.Transformations, "TCP acknowledgement and SACK state adjusted to observed peer sequence clocks")
			}
			if profile == replay.ProfileFunctional {
				entry.Warnings = append(entry.Warnings, "two-sided lab achieves adaptive transport fidelity; application-semantic equivalence is not claimed")
			}
		}
		plan.Entries = append(plan.Entries, entry)
	}
	if len(trace.Raw) > 0 {
		entry := replay.PlanEntry{
			SessionID: "raw-0", Transport: replay.TransportRaw, Driver: "frame-injector", Mode: replay.ModeWire, Fidelity: replay.FidelityWire,
			PacketIndexes:   labPacketIndexes(trace.Raw),
			Warnings:        []string{"frames without a supported session model are an explicit raw lane and do not claim live adaptation", "raw-lane IP and transport bytes remain captured values because unknown address-bound checksums cannot be repaired safely"},
			Transformations: []string{"topology side inferred from captured endpoint addresses where possible; configured side link mapping applied"},
		}
		if truncatedLabEvents(trace.Raw) {
			entry.Driver, entry.Mode, entry.Fidelity = "none", replay.ModeBlocked, replay.FidelityBlocked
			entry.Blockers = []string{"raw lane contains snaplen-truncated frames; exact injection is impossible"}
		}
		plan.Entries = append(plan.Entries, entry)
	}
	return plan
}

func labDriver(transport replay.Transport) string {
	switch transport {
	case replay.TransportTCP:
		return "tcp-dual-actor"
	case replay.TransportUDP:
		return "udp-dual-actor"
	case replay.TransportICMP4, replay.TransportICMP6:
		return "icmp-dual-actor"
	default:
		return "frame-injector"
	}
}

func labPacketIndexes(events []replay.Event) []int {
	out := make([]int, len(events))
	for i := range events {
		out[i] = events[i].PacketIndex
	}
	sort.Ints(out)
	return out
}

func truncatedLabEvents(events []replay.Event) bool {
	for _, event := range events {
		if event.Record != nil && event.Record.OrigLen > 0 && (event.Record.CapLen < event.Record.OrigLen || len(event.Record.Data) < event.Record.OrigLen) {
			return true
		}
	}
	return false
}

func labGroupEndpoint(address netip.Addr) bool {
	return address.IsValid() && (address.IsMulticast() || address == netip.IPv4Unspecified() || address == netip.IPv6Unspecified())
}

func normalizedLabProfile(profile replay.Profile) replay.Profile {
	if profile == "" {
		return replay.ProfileTiming
	}
	return profile
}

func validateLabPlan(plan replay.ReplayPlan) error {
	if err := plan.ValidateCoverage(); err != nil {
		return fmt.Errorf("lab replay plan: %w", err)
	}
	for _, entry := range plan.Entries {
		if entry.Mode == replay.ModeBlocked {
			return fmt.Errorf("lab replay plan blocks %s: %s", entry.SessionID, entry.Blockers[0])
		}
	}
	return nil
}
