package backend

import "net/netip"

// LiveConfig parameterises opening a live backend for a stateful replay.
type LiveConfig struct {
	Iface      string     // interface to send/receive on
	Target     netip.Addr // the device's IP
	TargetPort uint16     // the device's TCP port
	LocalPort  uint16     // the spoofed client source port (for the recv filter)
	Promisc    bool       // enable promiscuous mode (needed when spoofing the client MAC)
}

// LiveBackend pairs an opened PacketBackend with the L2 addressing needed to
// rebuild frames: the interface's own MAC (new source) and the next-hop MAC
// toward the target (new destination).
type LiveBackend struct {
	Backend    PacketBackend
	LocalMAC   [6]byte
	NextHopMAC [6]byte
}

// OpenLive opens a live backend for the platform, resolves next-hop addressing,
// and installs a receive filter for the replayed flow.
func OpenLive(cfg LiveConfig) (*LiveBackend, error) { return openLive(cfg) }

// OpenSender opens a send-only backend for stateless replay (no filter, no
// next-hop resolution).
func OpenSender(iface string) (PacketBackend, error) { return openSender(iface) }

// OpenCapture opens a receive-capable backend for recording frames to a pcap.
func OpenCapture(iface string, promisc bool) (PacketBackend, error) {
	return openCapture(iface, promisc)
}
