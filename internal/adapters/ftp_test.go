package adapters

import (
	"net/netip"
	"testing"

	"github.com/kvmukilan/livewire/internal/replay"
)

func TestFTPDecodeCommandsAndMultilineReplies(t *testing.T) {
	a := FTP{}
	commands, err := a.Decode(replay.ClientToServer, []byte("USER alice\r\nPASS secret\r\nEPSV\r\n"))
	if err != nil || len(commands) != 3 {
		t.Fatalf("commands=%d err=%v", len(commands), err)
	}
	if got := stringField(commands[1], "argument"); got != "[REDACTED]" {
		t.Fatalf("PASS argument was not redacted: %q", got)
	}
	replies, err := a.Decode(replay.ServerToClient, []byte("220-ready\r\n220 service ready\r\n229 Entering Extended Passive Mode (|||49152|)\r\n"))
	if err != nil || len(replies) != 2 {
		t.Fatalf("replies=%d err=%v", len(replies), err)
	}
	if intField(replies[0], "code") != 220 || intField(replies[1], "class") != 2 {
		t.Fatalf("unexpected reply fields: %#v", replies)
	}
}

func TestFTPPlanCoordinatesNegotiatedDataSession(t *testing.T) {
	control := &replay.Session{
		ID: "tcp-0", Transport: replay.TransportTCP,
		Client: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 40000},
		Server: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.20"), Port: 21},
		Events: []replay.Event{
			{PacketIndex: 0, Direction: replay.ClientToServer, Payload: []byte("EPSV\r\nRETR x\r\n")},
			{PacketIndex: 1, Direction: replay.ServerToClient, Payload: []byte("229 Entering Extended Passive Mode (|||50000|)\r\n150 opening\r\n226 done\r\n")},
		},
	}
	data := &replay.Session{
		ID: "tcp-1", Transport: replay.TransportTCP,
		Client: replay.Endpoint{IP: control.Client.IP, Port: 41000}, Server: replay.Endpoint{IP: control.Server.IP, Port: 50000},
		Events: []replay.Event{{PacketIndex: 2, Direction: replay.ServerToClient, Payload: []byte("data")}},
	}
	trace := &replay.Trace{Packets: 3, Sessions: []*replay.Session{control, data}}
	plan := replay.BuildPlan(trace, replay.ProfileFunctional, DefaultRegistry())
	if err := plan.ValidateCoverage(); err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 1 || plan.Entries[0].Mode != replay.ModeCoordinated || len(plan.Entries[0].RelatedSessionIDs) != 1 {
		t.Fatalf("plan=%+v", plan)
	}
	for _, profile := range []replay.Profile{replay.ProfileTiming, replay.ProfileTransport, replay.ProfileWire} {
		candidate := replay.BuildPlan(trace, profile, DefaultRegistry())
		if err := candidate.ValidateCoverage(); err != nil {
			t.Fatalf("%s coverage: %v plan=%+v", profile, err, candidate)
		}
	}
}

func TestFTPPlanCoordinatesActiveIPv6Data(t *testing.T) {
	control := &replay.Session{
		ID: "tcp-0", Transport: replay.TransportTCP,
		Client: replay.Endpoint{IP: netip.MustParseAddr("2001:db8::10"), Port: 40000},
		Server: replay.Endpoint{IP: netip.MustParseAddr("2001:db8::20"), Port: 21},
		Events: []replay.Event{
			{PacketIndex: 0, Direction: replay.ClientToServer, Payload: []byte("EPRT |2|2001:db8::10|50002|\r\n")},
			{PacketIndex: 1, Direction: replay.ServerToClient, Payload: []byte("200 active endpoint accepted\r\n")},
			{PacketIndex: 2, Direction: replay.ClientToServer, Payload: []byte("NLST\r\n")},
			{PacketIndex: 3, Direction: replay.ServerToClient, Payload: []byte("150 opening\r\n")},
			{PacketIndex: 4, Direction: replay.ServerToClient, Payload: []byte("226 done\r\n")},
		},
	}
	data := &replay.Session{
		ID: "tcp-1", Transport: replay.TransportTCP,
		Client: replay.Endpoint{IP: control.Server.IP, Port: 20}, Server: replay.Endpoint{IP: control.Client.IP, Port: 50002},
		Events: []replay.Event{{PacketIndex: 5, Direction: replay.ServerToClient, Payload: []byte("listing")}},
	}
	plan := replay.BuildPlan(&replay.Trace{Packets: 6, Sessions: []*replay.Session{control, data}}, replay.ProfileFunctional, DefaultRegistry())
	if err := plan.ValidateCoverage(); err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 1 || plan.Entries[0].Mode != replay.ModeCoordinated || len(plan.Entries[0].RelatedSessionIDs) != 1 {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestFTPPrepareCredentialsAndCompareClasses(t *testing.T) {
	a := FTP{}
	msg := replay.Message{Kind: "ftp-command", Raw: []byte("PASS old\r\n"), Fields: map[string]any{"command": "PASS"}}
	got, err := a.Prepare(replay.ClientToServer, msg, &replay.RuntimeState{Variables: map[string]string{"ftp.password": "new"}})
	if err != nil || string(got) != "PASS new\r\n" {
		t.Fatalf("prepared=%q err=%v", got, err)
	}
	want := replay.Message{Kind: "ftp-reply", Fields: map[string]any{"code": 226, "class": 2}}
	live := replay.Message{Kind: "ftp-reply", Fields: map[string]any{"code": 250, "class": 2}}
	if diffs := a.Compare(want, live, replay.VerifyLenient); len(diffs) != 0 {
		t.Fatalf("lenient differences: %#v", diffs)
	}
	if diffs := a.Compare(want, live, replay.VerifyStrict); len(diffs) == 0 {
		t.Fatal("strict comparison accepted a different reply code")
	}
}
