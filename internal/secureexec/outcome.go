package secureexec

import (
	"context"
	"github.com/kvmukilan/livewire/internal/ftpreplay"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

// Finalize applies the same evidence rules to primary and compatibility commands.
// Context preserves cancellation identity even when an error was redacted.
func (o *Outcome) Finalize(ctx context.Context, err error) {
	if ctx != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		o.Completed = false
	}
	o.Verified = o.Verified && o.Responses > 0
	o.Matched = o.Matched && o.Verified && o.Completed
	o.Status = replay.ResultStatus(o.Completed, o.Verified, o.Matched, false, err)
	o.ReasonCode = replay.FailureReason(o.Completed, o.Verified, o.Matched, err)
	if o.Adapter == "tls-handshake" {
		o.Completed, o.Verified, o.Matched = false, false, false
		o.Status = replay.ResultStatus(false, false, false, false, err)
		if err == nil {
			o.ReasonCode = "captured_plaintext_unavailable"
		}
	}
	o.ApplicationReplayCompleted = o.Completed
	if o.Observed == 0 {
		o.Observed = o.Responses
	}
	if o.Scope == "" {
		o.Scope = "application responses"
	}
}

type Outcome struct {
	replay.VerificationEvidence
	Status                     string                         `json:"status,omitempty"`
	Completed                  bool                           `json:"completed"`
	Verified                   bool                           `json:"verified"`
	Matched                    bool                           `json:"matched"`
	Adapter                    string                         `json:"adapter"`
	ProtocolVersion            string                         `json:"protocolVersion,omitempty"`
	CipherSuite                string                         `json:"cipherSuite,omitempty"`
	ALPN                       string                         `json:"alpn,omitempty"`
	PeerIdentityChecked        bool                           `json:"peerIdentityChecked"`
	HandshakeCompleted         bool                           `json:"handshakeCompleted,omitempty"`
	TLSSecretsSource           string                         `json:"tlsSecretsSource,omitempty"`
	ApplicationReplayCompleted bool                           `json:"applicationReplayCompleted"`
	CapturedClientHello        *tlsreplay.ClientHelloMetadata `json:"capturedClientHello,omitempty"`
	FreshClientHello           *tlsreplay.ClientHelloMetadata `json:"freshClientHello,omitempty"`
	Requests                   int                            `json:"requests"`
	Responses                  int                            `json:"responses"`
	Mismatches                 int                            `json:"mismatches"`
	Differences                []replay.Difference            `json:"differences,omitempty"`
	Commands                   []CommandEvidence              `json:"commands,omitempty"`
	Transfers                  []ftpreplay.TransferResult     `json:"transfers,omitempty"`
	Error                      string                         `json:"error,omitempty"`
}

type CommandEvidence struct {
	Index        int    `json:"index"`
	OutputBytes  int    `json:"outputBytes"`
	OutputSHA256 string `json:"outputSha256"`
	Matched      bool   `json:"matched"`
}
