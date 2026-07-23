package main

import (
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func TestAssessCaptureFlagsMissingAndTruncatedInput(t *testing.T) {
	recs := []*pcapio.Record{{
		Data: []byte{0, 1, 2}, CapLen: 3, OrigLen: 100, LinkType: wire.LinkEthernet,
	}}
	r := assessCapture(recs, []*engine.Flow{{}})
	if r.Confidence >= 100 {
		t.Fatalf("bad capture should reduce confidence: %+v", r)
	}
	var details string
	for _, f := range r.Findings {
		details += f.Code + " "
	}
	if !strings.Contains(details, "truncated-packets") || !strings.Contains(details, "missing-handshake") {
		t.Fatalf("expected truncation and handshake findings, got %q", details)
	}
}

func TestAssessCaptureNeverReturnsNegativeConfidence(t *testing.T) {
	var flows []*engine.Flow
	for i := 0; i < 20; i++ {
		flows = append(flows, &engine.Flow{})
	}
	r := assessCapture(nil, flows)
	if r.Confidence < 0 {
		t.Fatalf("confidence must be clamped, got %d", r.Confidence)
	}
}
