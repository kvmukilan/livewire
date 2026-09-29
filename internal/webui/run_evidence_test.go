package webui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/evidence"
	"github.com/kvmukilan/livewire/internal/iterate"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/wire"
)

func TestDashboardEvidencePublicationFailureInvalidatesResults(t *testing.T) {
	for _, collision := range []bool{false, true} {
		t.Run(map[bool]string{false: "published", true: "publication-collision"}[collision], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "actual.pcap")
			stream := evidence.New(path)
			defer stream.Close()
			frame := webUDPFrame()
			if err := stream.Record(pcapio.Record{Time: time.Now(), Data: frame, CapLen: len(frame), OrigLen: len(frame), LinkType: wire.LinkEthernet}); err != nil {
				t.Fatal(err)
			}
			if collision {
				// Simulate a real no-replace publication failure after all packet
				// writes succeeded. An existing artifact must remain untouched.
				if err := os.WriteFile(path, []byte("other artifact"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			results := []webSessionResult{
				{Entry: replay.PlanEntry{Mode: replay.ModeSemantic}, Completed: true, Verified: true, Matched: true, Sent: 2, Received: 2},
				{Entry: replay.PlanEntry{Mode: replay.ModeWire}, Completed: true, Sent: 7},
				{Entry: replay.PlanEntry{Mode: replay.ModeSemantic}, Error: "original peer failure", Sent: 1},
			}
			per := []iterate.Tally{{Same: 1, WireOnly: 1}, {Incomplete: 1}}
			count, err := commitWebEvidence(stream, results, per)
			if count != 1 || collision != (err != nil) {
				t.Fatalf("count=%d err=%v collision=%v", count, err, collision)
			}
			if !collision {
				if !results[0].Completed || !results[0].Verified || !results[0].Matched || !results[1].Completed || per[0].Same != 1 || per[0].WireOnly != 1 {
					t.Fatalf("successful publication changed results: %+v %+v", results, per)
				}
				return
			}
			for _, result := range results {
				if result.Completed || result.Verified || result.Matched || result.verdict() != iterate.Incomplete || result.ReasonCode != "evidence_publication_failed" || !strings.Contains(result.Error, "publish replay evidence") {
					t.Fatalf("publication failure retained a success claim: %+v", result)
				}
			}
			if results[0].Sent != 2 || results[0].Received != 2 || results[1].Sent != 7 || !strings.Contains(results[2].Error, "original peer failure") {
				t.Fatalf("observed traffic or original failure was lost: %+v", results)
			}
			summary := iterate.Summarize(per, 2)
			if summary.Status != "incomplete" || summary.Incomplete != 2 || summary.Sessions.Incomplete != 3 || summary.Same != 0 || summary.WireOnly != 0 {
				t.Fatalf("aggregate retained a success claim: %+v", summary)
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil || string(body) != "other artifact" {
				t.Fatalf("existing artifact replaced: %q %v", body, readErr)
			}
			partials, globErr := filepath.Glob(filepath.Join(dir, ".actual.pcap.tmp-*"))
			if globErr != nil || len(partials) != 1 {
				t.Fatalf("failed evidence was not retained as a private partial: %v %v", partials, globErr)
			}
			capture, loadErr := pcapio.LoadFile(partials[0], pcapio.DefaultLimits())
			if loadErr != nil || len(capture.Records) != 1 {
				t.Fatalf("partial evidence unreadable: %v records=%d", loadErr, len(capture.Records))
			}
		})
	}
}
