package replayintent

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
)

func tlsSession(id string, clientPort, serverPort uint16, serverIP string) *replay.Session {
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
	return &replay.Session{ID: id, Transport: replay.TransportTCP,
		Client: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: clientPort},
		Server: replay.Endpoint{IP: netip.MustParseAddr(serverIP), Port: serverPort},
		Events: []replay.Event{{Direction: replay.ClientToServer, Record: &pcapio.Record{}, Payload: hello}}}
}

func TestDetectRunsSeveralTLSSessionsToOneServer(t *testing.T) {
	trace := &replay.Trace{Sessions: []*replay.Session{tlsSession("tcp-0", 40000, 19998, "192.0.2.42"), tlsSession("tcp-1", 40001, 19998, "192.0.2.42")}}
	route := Detect(trace, nil)
	if route.Kind != TLS || route.Reason != "" || len(route.Sessions) != 2 || route.Session.ID != "tcp-0" || !route.Includes("tcp-1") || route.Includes("tcp-9") {
		t.Fatalf("route: %+v", route)
	}
	trace.Sessions = append(trace.Sessions, tlsSession("tcp-2", 40002, 19998, "192.0.2.43"))
	if route := Detect(trace, nil); route.Kind != Opaque || !strings.Contains(route.Reason, "different servers") {
		t.Fatalf("mixed targets: %+v", route)
	}
}

func TestSelectByPortKeepsOnlySessionsWithApplicationData(t *testing.T) {
	empty := &replay.Session{ID: "tcp-2", Transport: replay.TransportTCP, Client: replay.Endpoint{Port: 40002}, Server: replay.Endpoint{Port: 19998}, Events: []replay.Event{{Direction: replay.ClientToServer, Record: &pcapio.Record{}}}}
	other := tlsSession("tcp-3", 40003, 443, "192.0.2.42")
	trace := &replay.Trace{Packets: 4, Sessions: []*replay.Session{tlsSession("tcp-0", 40000, 19998, "192.0.2.42"), tlsSession("tcp-1", 40001, 19998, "192.0.2.42"), empty, other}}
	selected, err := Select(trace, []string{"port:19998"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Sessions) != 2 || selected.Sessions[0].ID != "tcp-0" || selected.Sessions[1].ID != "tcp-1" || len(selected.Excluded) != 2 {
		t.Fatalf("selection: %+v excluded %+v", selected.Sessions, selected.Excluded)
	}
	if _, err := Select(trace, []string{"port:2404"}, nil); err == nil || !strings.Contains(err.Error(), "port 2404") {
		t.Fatalf("unknown port: %v", err)
	}
}
