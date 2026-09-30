package secureexec

import (
	"fmt"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

// SelectTLSKeyLog snapshots explicitly selected secrets first, then secrets
// embedded in the already-loaded PCAPNG. Neither source is ever serialized.
func SelectTLSKeyLog(embedded, explicit []byte, explicitProvided bool) ([]byte, string, error) {
	if explicitProvided {
		if len(explicit) == 0 {
			return nil, "", fmt.Errorf("explicit key log is empty; refusing handshake fallback")
		}
		return append([]byte(nil), explicit...), "external", nil
	}
	if len(embedded) > 0 {
		if _, err := tlsreplay.ParseKeyLogStrict(embedded); err != nil {
			return nil, "", err
		}
		return append([]byte(nil), embedded...), "embedded", nil
	}
	return nil, "none", nil
}
