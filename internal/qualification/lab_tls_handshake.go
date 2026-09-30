package qualification

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

type labTLSHello struct {
	ServerName      string   `json:"serverName"`
	ALPN            []string `json:"alpn"`
	OfferedVersions []uint16 `json:"offeredVersions"`
	UsedVersions    []uint16 `json:"usedVersions"`
	SHA256          string   `json:"sha256"`
	RandomSHA256    string   `json:"randomSha256"`
}

type labTLSHandshakePeer struct {
	ServerName, ALPN, Version                string
	CapturedRandomSHA256, ClientRandomSHA256 string
	ApplicationBytes                         *int
	Completed                                bool
}

type labTLSHandshakeReport struct {
	Tool, Version, Kind string
	When                time.Time
	ReplayPlan          struct {
		Entries []struct {
			Fidelity, Mode, Adapter, Driver string
			Blockers                        []string
		}
	}
	Outcome struct {
		Adapter, Status, Cleanup, Error, ReasonCode, ProtocolVersion, ALPN string
		TLSSecretsSource                                                   string
		HandshakeCompleted, PeerIdentityChecked                            bool
		Completed, Verified, Matched, ApplicationReplayCompleted           *bool
		Compared                                                           int `json:"comparedResponses"`
		Expected                                                           int `json:"expectedResponses"`
		Observed                                                           int `json:"observedResponses"`
		Requests, Responses, Mismatches                                    int
		CapturedClientHello, FreshClientHello                              labTLSHello
	}
}

// TLSHandshakeLabVerifier binds reports to the independent TLS peer, preserving
// random uniqueness across CLI processes in one lab run. Successful handshakes
// are separate from application replay: the latter must remain incomplete.
type TLSHandshakeLabVerifier struct {
	Version      string
	seenRandoms  map[string]bool
	capturedHash string
}

// Check requires one independently observed fresh handshake per secure report.
func (v *TLSHandshakeLabVerifier) Check(started, finished time.Time, repeat int, peerEvents []string, reports [][]byte) (int, error) {
	if !UsesStatelessReproduce(v.Version) || repeat < 2 || len(reports) != repeat {
		return 0, fmt.Errorf("TLS handshake requires every repeated secure report")
	}
	var peers []labTLSHandshakePeer
	for _, event := range peerEvents {
		if !strings.HasPrefix(event, "tls-handshake ") {
			continue
		}
		var peer labTLSHandshakePeer
		if err := json.Unmarshal([]byte(strings.TrimPrefix(event, "tls-handshake ")), &peer); err != nil {
			return 0, fmt.Errorf("invalid independent TLS handshake observation: %w", err)
		}
		peers = append(peers, peer)
	}
	if len(peers) != repeat {
		return 0, fmt.Errorf("incomplete independent TLS handshake observations")
	}
	newRandoms := map[string]bool{}
	capturedHash := v.capturedHash
	for i, data := range reports {
		var report labTLSHandshakeReport
		if err := json.Unmarshal(data, &report); err != nil {
			return 0, fmt.Errorf("invalid TLS handshake report: %w", err)
		}
		if report.Tool != "livewire" || strings.TrimPrefix(report.Version, "v") != strings.TrimPrefix(v.Version, "v") || report.Kind != "tls" || report.When.IsZero() || report.When.Before(started.Add(-2*time.Second)) || report.When.After(finished.Add(2*time.Second)) {
			return 0, fmt.Errorf("TLS handshake report identity or timestamp differs")
		}
		if len(report.ReplayPlan.Entries) != 1 {
			return 0, fmt.Errorf("TLS handshake report must select exactly one session")
		}
		entry := report.ReplayPlan.Entries[0]
		if entry.Fidelity != "handshake" || entry.Mode != "semantic" || entry.Adapter != "tls-handshake" || entry.Driver != "tls-handshake" || len(entry.Blockers) != 0 {
			return 0, fmt.Errorf("TLS handshake report misstates handshake-only fidelity")
		}
		o := report.Outcome
		falseField := func(value *bool) bool { return value != nil && !*value }
		if o.Adapter != "tls-handshake" || o.Status != "incomplete" || o.TLSSecretsSource != "none" || !o.HandshakeCompleted || !falseField(o.ApplicationReplayCompleted) || !falseField(o.Completed) || !falseField(o.Verified) || !falseField(o.Matched) || o.Compared != 0 || o.Expected != 0 || o.Observed != 0 || o.Requests != 0 || o.Responses != 0 || o.Error != "" || o.Mismatches != 0 || o.Cleanup != "complete" || !o.PeerIdentityChecked || o.ReasonCode != "captured_plaintext_unavailable" {
			return 0, fmt.Errorf("TLS handshake outcome incomplete or falsely claims application replay")
		}
		version := uint16(0)
		switch o.ProtocolVersion {
		case "TLS 1.2":
			version = 0x303
		case "TLS 1.3":
			version = 0x304
		default:
			return 0, fmt.Errorf("TLS handshake negotiated unsupported protocol version")
		}
		captured, fresh, peer := o.CapturedClientHello, o.FreshClientHello, peers[i]
		for _, hello := range []labTLSHello{captured, fresh} {
			if hello.ServerName != "localhost" || !slices.Equal(hello.ALPN, []string{"livewire-lab/1"}) || !labSHA256(hello.SHA256) || !labSHA256(hello.RandomSHA256) || !slices.Contains(hello.OfferedVersions, version) {
				return 0, fmt.Errorf("TLS handshake ClientHello differs from independent fixture")
			}
		}
		if len(captured.UsedVersions) == 0 || !slices.Contains(captured.UsedVersions, version) {
			return 0, fmt.Errorf("TLS handshake negotiated version was not selected from capture")
		}
		for _, used := range captured.UsedVersions {
			if used != 0x303 && used != 0x304 || !slices.Contains(captured.OfferedVersions, used) || !slices.Contains(fresh.OfferedVersions, used) {
				return 0, fmt.Errorf("TLS handshake version offer differs from safe captured offer")
			}
		}
		for _, offered := range fresh.OfferedVersions {
			if !slices.Contains(captured.UsedVersions, offered) {
				return 0, fmt.Errorf("TLS handshake fresh offer introduces an unselected version")
			}
		}
		if !peer.Completed || peer.ApplicationBytes == nil || *peer.ApplicationBytes != 0 || peer.ServerName != captured.ServerName || peer.ALPN != o.ALPN || o.ALPN != "livewire-lab/1" || peer.Version != o.ProtocolVersion || peer.CapturedRandomSHA256 != captured.RandomSHA256 || peer.ClientRandomSHA256 != fresh.RandomSHA256 || fresh.RandomSHA256 == captured.RandomSHA256 || fresh.SHA256 == captured.SHA256 || newRandoms[fresh.RandomSHA256] || v.seenRandoms[fresh.RandomSHA256] {
			return 0, fmt.Errorf("TLS handshake peer evidence differs, reuses captured state or contains application bytes")
		}
		if capturedHash != "" && capturedHash != captured.SHA256 {
			return 0, fmt.Errorf("TLS handshake captured ClientHello changed across attempts")
		}
		capturedHash = captured.SHA256
		newRandoms[fresh.RandomSHA256] = true
	}
	if v.seenRandoms == nil {
		v.seenRandoms = map[string]bool{}
	}
	for hash := range newRandoms {
		v.seenRandoms[hash] = true
	}
	v.capturedHash = capturedHash
	return len(peers), nil
}

func labSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(digest) == 32
}
