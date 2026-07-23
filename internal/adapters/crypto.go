package adapters

import (
	"fmt"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
)

// TLS and SSH adapters classify encrypted streams. Actual execution is routed
// to tlsreplay/sshreplay only after required secrets are validated; Decode never
// pretends ciphertext is an application message.
type TLS struct{}

func (TLS) Name() string { return "tls-reterminate" }
func (TLS) Detect(s replay.Session) replay.Confidence {
	if dissect.DetectTLS(firstPayload(s)).IsTLS {
		return 100
	}
	return portConfidence(s, 443, 8883)
}
func (TLS) Decode(_ replay.Direction, _ []byte) ([]replay.Message, error) {
	return nil, fmt.Errorf("tls: provide a matching key log and inner adapter")
}
func (TLS) Prepare(_ replay.Direction, _ replay.Message, _ *replay.RuntimeState) ([]byte, error) {
	return nil, fmt.Errorf("tls: ciphertext cannot be prepared directly")
}
func (TLS) Correlate(_, _ replay.Message, _ *replay.RuntimeState) replay.Match   { return replay.Match{} }
func (TLS) Compare(_, _ replay.Message, _ replay.VerifyMode) []replay.Difference { return nil }

type SSH struct{}

func (SSH) Name() string { return "ssh-reterminate" }
func (SSH) Detect(s replay.Session) replay.Confidence {
	if dissect.DetectSSH(firstPayload(s)) {
		return 100
	}
	return portConfidence(s, 22)
}
func (SSH) Decode(_ replay.Direction, _ []byte) ([]replay.Message, error) {
	return nil, fmt.Errorf("ssh: provide credentials and an explicit command script")
}
func (SSH) Prepare(_ replay.Direction, _ replay.Message, _ *replay.RuntimeState) ([]byte, error) {
	return nil, fmt.Errorf("ssh: ciphertext cannot be prepared directly")
}
func (SSH) Correlate(_, _ replay.Message, _ *replay.RuntimeState) replay.Match   { return replay.Match{} }
func (SSH) Compare(_, _ replay.Message, _ replay.VerifyMode) []replay.Difference { return nil }
