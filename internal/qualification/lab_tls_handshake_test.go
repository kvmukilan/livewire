package qualification

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func syntheticTLSHandshakeReports(t *testing.T, version string, event labEvent) ([][]byte, []string) {
	t.Helper()
	hash := func(value string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(value))) }
	var reports [][]byte
	var peer []string
	for attempt := 0; attempt < event.Repeat; attempt++ {
		var report labTLSHandshakeReport
		report.Tool, report.Version, report.Kind, report.When = "livewire", version, "tls", event.Started
		if err := json.Unmarshal([]byte(`{"entries":[{"fidelity":"handshake","mode":"semantic","adapter":"tls-handshake","driver":"tls-handshake"}]}`), &report.ReplayPlan); err != nil {
			t.Fatal(err)
		}
		o := &report.Outcome
		no := false
		o.Adapter, o.Status, o.Cleanup, o.ReasonCode, o.ProtocolVersion, o.ALPN = "tls-handshake", "incomplete", "complete", "captured_plaintext_unavailable", "TLS 1.3", "livewire-lab/1"
		o.TLSSecretsSource = "none"
		o.HandshakeCompleted, o.PeerIdentityChecked = true, true
		o.Completed, o.Verified, o.Matched, o.ApplicationReplayCompleted = &no, &no, &no, &no
		o.CapturedClientHello = labTLSHello{ServerName: "localhost", ALPN: []string{o.ALPN}, OfferedVersions: []uint16{0x304, 0x303}, UsedVersions: []uint16{0x304, 0x303}, SHA256: hash("captured hello"), RandomSHA256: hash("captured random")}
		o.FreshClientHello = o.CapturedClientHello
		o.FreshClientHello.SHA256 = hash(fmt.Sprint("fresh hello ", event.Round, " ", attempt))
		o.FreshClientHello.RandomSHA256 = hash(fmt.Sprint("fresh random ", event.Round, " ", attempt))
		zero := 0
		p := labTLSHandshakePeer{ServerName: "localhost", ALPN: o.ALPN, Version: o.ProtocolVersion, CapturedRandomSHA256: o.CapturedClientHello.RandomSHA256, ClientRandomSHA256: o.FreshClientHello.RandomSHA256, ApplicationBytes: &zero, Completed: true}
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		peer = append(peer, "tls-handshake "+string(data))
		data, err = json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, data)
	}
	return reports, peer
}

func TestTLSHandshakeProofRequiresFreshConnectionWithoutApplicationClaims(t *testing.T) {
	e := labEvent{Round: 1, Repeat: 3, Started: time.Unix(1700000000, 0), Finished: time.Unix(1700000001, 0)}
	for _, mutation := range []string{"valid", "verified", "matched", "completed", "application-complete", "missing-completed", "comparisons", "expected", "observed", "requests", "responses", "wrong-kind", "wrong-version", "wrong-time", "peer-identity", "cleanup", "wrong-fidelity", "wrong-reason", "no-handshake", "has-secrets", "captured-random", "peer-random", "peer-appbytes", "peer-omits-appbytes", "peer-failed", "peer-version", "peer-alpn", "missing-attempt", "missing-peer", "duplicate-peer", "unsafe-offer", "fresh-unsafe-offer", "changed-capture", "same-random"} {
		t.Run(mutation, func(t *testing.T) {
			reports, peer := syntheticTLSHandshakeReports(t, "1.1.0", e)
			var report labTLSHandshakeReport
			if err := json.Unmarshal(reports[0], &report); err != nil {
				t.Fatal(err)
			}
			var p labTLSHandshakePeer
			if err := json.Unmarshal([]byte(peer[0][len("tls-handshake "):]), &p); err != nil {
				t.Fatal(err)
			}
			yes, one := true, 1
			switch mutation {
			case "verified":
				report.Outcome.Verified = &yes
			case "matched":
				report.Outcome.Matched = &yes
			case "completed":
				report.Outcome.Completed = &yes
			case "application-complete":
				report.Outcome.ApplicationReplayCompleted = &yes
			case "missing-completed":
				report.Outcome.Completed = nil
			case "comparisons":
				report.Outcome.Compared = 1
			case "expected":
				report.Outcome.Expected = 1
			case "observed":
				report.Outcome.Observed = 1
			case "requests":
				report.Outcome.Requests = 1
			case "responses":
				report.Outcome.Responses = 1
			case "wrong-kind":
				report.Kind = "ssh"
			case "wrong-version":
				report.Version = "1.0.1"
			case "wrong-time":
				report.When = report.When.Add(-time.Hour)
			case "peer-identity":
				report.Outcome.PeerIdentityChecked = false
			case "cleanup":
				report.Outcome.Cleanup = "failed"
			case "wrong-fidelity":
				report.ReplayPlan.Entries[0].Fidelity = "semantic"
			case "wrong-reason":
				report.Outcome.ReasonCode = ""
			case "no-handshake":
				report.Outcome.HandshakeCompleted = false
			case "has-secrets":
				report.Outcome.TLSSecretsSource = "external"
			case "captured-random":
				report.Outcome.FreshClientHello.RandomSHA256 = report.Outcome.CapturedClientHello.RandomSHA256
			case "peer-random":
				p.ClientRandomSHA256 = p.CapturedRandomSHA256
			case "peer-appbytes":
				p.ApplicationBytes = &one
			case "peer-omits-appbytes":
				p.ApplicationBytes = nil
			case "peer-failed":
				p.Completed = false
			case "peer-version":
				p.Version = "TLS 1.2"
			case "peer-alpn":
				p.ALPN = "other"
			case "missing-attempt":
				reports = reports[:2]
			case "unsafe-offer":
				report.Outcome.CapturedClientHello.UsedVersions = append(report.Outcome.CapturedClientHello.UsedVersions, 0x301)
			case "fresh-unsafe-offer":
				report.Outcome.FreshClientHello.OfferedVersions = append(report.Outcome.FreshClientHello.OfferedVersions, 0x301)
			case "changed-capture":
				report.Outcome.CapturedClientHello.SHA256 = report.Outcome.FreshClientHello.SHA256
			}
			reports[0], _ = json.Marshal(report)
			data, _ := json.Marshal(p)
			peer[0] = "tls-handshake " + string(data)
			switch mutation {
			case "same-random":
				reports[1], peer[1] = reports[0], peer[0]
			case "missing-peer":
				peer = peer[1:]
			case "duplicate-peer":
				peer = append(peer, peer[0])
			}
			v := TLSHandshakeLabVerifier{Version: "1.1.0"}
			count, err := v.Check(e.Started, e.Finished, e.Repeat, peer, reports)
			if mutation == "valid" {
				if err != nil || count != 3 {
					t.Fatalf("valid handshake evidence rejected: count=%d err=%v", count, err)
				}
				if _, err := v.Check(e.Started, e.Finished, e.Repeat, peer, reports); err == nil {
					t.Fatal("random reuse across processes accepted")
				}
			} else if err == nil {
				t.Fatalf("invalid %s evidence accepted", mutation)
			}
		})
	}
}

func TestApplicationMatrixPreservesHistoricalCases(t *testing.T) {
	for _, version := range []string{"1.0.0", "1.0.1", "1.1.0"} {
		cases := ApplicationLabCasesForVersion(version)
		want := 16
		if UsesStatelessReproduce(version) {
			want++
		}
		if len(cases) != want {
			t.Fatalf("%s has %d cases, want %d", version, len(cases), want)
		}
	}
}
