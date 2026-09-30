package secureexec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

func prepareTLSHandshake(c Config, host string) (*Prepared, error) {
	if c.Inspection.Plan.Profile != replay.ProfileFunctional || c.Verify == replay.VerifyStrict || c.Scenario != nil || len(c.Variables) > 0 {
		return nil, fmt.Errorf("without TLS secrets only a fresh handshake is available; application verification, timing, variables, and scenarios require the matching key log")
	}
	client, _, err := replay.TCPPayloadStreams(c.Inspection.Route.Session)
	if err != nil {
		return nil, err
	}
	hello, err := tlsreplay.ParseClientHello(client)
	if err != nil {
		return nil, err
	}
	name := c.ServerName
	if name == "" {
		name = hello.ServerName
	}
	if name == "" {
		name = host
	}
	tc := &tls.Config{ServerName: name, NextProtos: append([]string(nil), hello.ALPN...), MinVersion: hello.UsedVersions[len(hello.UsedVersions)-1], MaxVersion: hello.UsedVersions[0], InsecureSkipVerify: c.Insecure} // #nosec G402 -- explicit operator lab override
	if len(c.CA) > 0 {
		roots, e := x509.SystemCertPool()
		if e != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(c.CA) {
			return nil, fmt.Errorf("CA contains no parseable certificates")
		}
		tc.RootCAs = roots
	}
	return &Prepared{sessionID: c.Inspection.Route.Session.ID, run: func(ctx context.Context) (Outcome, error) {
		o := Outcome{Adapter: "tls-handshake", CapturedClientHello: hello, VerificationEvidence: replay.VerificationEvidence{Scope: "fresh TLS handshake only; captured application plaintext unavailable"}}
		result, err := tlsreplay.HandshakeContext(ctx, c.Target, tc, c.Timeout)
		if result != nil {
			o.Cleanup = result.Cleanup
			o.HandshakeCompleted = result.State.HandshakeComplete
			o.PeerIdentityChecked = result.State.HandshakeComplete && !c.Insecure
			if result.State.HandshakeComplete {
				o.ProtocolVersion = tls.VersionName(result.State.Version)
				o.CipherSuite = tls.CipherSuiteName(result.State.CipherSuite)
				o.ALPN = result.State.NegotiatedProtocol
			}
			o.FreshClientHello = result.ClientHello
		}
		return o, err
	}}, nil
}
