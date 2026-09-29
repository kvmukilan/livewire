package webui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
)

func TestStatelessScheduleRejectedBeforeOpeningBackend(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []*pcapio.Record
		want    string
	}{
		{"missing record", []*pcapio.Record{nil}, "record 0 is missing"},
		{"timestamp overflow", []*pcapio.Record{
			{Time: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)},
			{Time: time.Date(2400, 1, 1, 0, 0, 0, 0, time.UTC)},
		}, "exceeds supported duration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := &job{ctx: context.Background(), stop: make(chan struct{})}
			// If schedule validation happens after backend acquisition, this
			// fails with an interface/open error instead of the capture error.
			(&Server{}).runStateless(j, tc.records, "definitely-missing-replay-interface")
			if !j.Done || j.OK || j.Summary != "invalid replay schedule" || len(j.Lines) != 1 || !strings.Contains(j.Lines[0], tc.want) {
				t.Fatalf("invalid schedule was not rejected before open: done=%v ok=%v summary=%q lines=%v", j.Done, j.OK, j.Summary, j.Lines)
			}
		})
	}
}
