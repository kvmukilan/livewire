package secureexec

import (
	"github.com/kvmukilan/livewire/internal/ftpreplay"
	"github.com/kvmukilan/livewire/internal/replay"
)

type Outcome struct {
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
