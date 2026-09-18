package secureexec

import (
	"context"
	"github.com/kvmukilan/livewire/internal/ftpreplay"
	"github.com/kvmukilan/livewire/internal/replay"
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
}

type Outcome struct {
	Status              string                     `json:"status,omitempty"`
	Completed           bool                       `json:"completed"`
	Verified            bool                       `json:"verified"`
	Matched             bool                       `json:"matched"`
	Adapter             string                     `json:"adapter"`
	ProtocolVersion     string                     `json:"protocolVersion,omitempty"`
	CipherSuite         string                     `json:"cipherSuite,omitempty"`
	ALPN                string                     `json:"alpn,omitempty"`
	PeerIdentityChecked bool                       `json:"peerIdentityChecked"`
	Requests            int                        `json:"requests"`
	Responses           int                        `json:"responses"`
	Mismatches          int                        `json:"mismatches"`
	Differences         []replay.Difference        `json:"differences,omitempty"`
	Commands            []CommandEvidence          `json:"commands,omitempty"`
	Transfers           []ftpreplay.TransferResult `json:"transfers,omitempty"`
	Error               string                     `json:"error,omitempty"`
}

type CommandEvidence struct {
	Index        int    `json:"index"`
	OutputBytes  int    `json:"outputBytes"`
	OutputSHA256 string `json:"outputSha256"`
	Matched      bool   `json:"matched"`
}
