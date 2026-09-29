package webui

import (
	"errors"
	"fmt"

	"github.com/kvmukilan/livewire/internal/evidence"
	"github.com/kvmukilan/livewire/internal/iterate"
)

// An unpublished evidence artifact cannot support a successful run report.
// Preserve observed traffic counts and comparison details, but invalidate the
// completion claims before producing either session or aggregate verdicts.
func commitWebEvidence(stream *evidence.Stream, results []webSessionResult, per []iterate.Tally) (int, error) {
	count, err := stream.Commit()
	if err == nil {
		return count, nil
	}
	err = fmt.Errorf("publish replay evidence: %w", err)
	for i := range results {
		result := &results[i]
		result.Completed, result.Verified, result.Matched = false, false, false
		if result.Error == "" {
			result.Error = err.Error()
		} else {
			result.Error = errors.Join(errors.New(result.Error), err).Error()
		}
		result.ReasonCode = "evidence_publication_failed"
	}
	for i := range per {
		per[i] = iterate.Tally{Incomplete: per[i].Total()}
	}
	return count, err
}
