package replay

import (
	"context"
	"errors"
	"strings"
)

// VerificationEvidence states what was actually compared. Counts are messages
// for application drivers and bytes for the raw TCP verifier, as Scope states.
type VerificationEvidence struct {
	Scope           string   `json:"verificationScope,omitempty"`
	Expected        int      `json:"expectedResponses"`
	Observed        int      `json:"observedResponses"`
	Compared        int      `json:"comparedResponses"`
	ReasonCode      string   `json:"reasonCode,omitempty"`
	Cleanup         string   `json:"cleanup,omitempty"`
	Transformations []string `json:"transformations,omitempty"`
}

func FailureReason(completed, verified, matched bool, err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case err != nil && (strings.Contains(err.Error(), "resource limit") || strings.Contains(err.Error(), "exceeds")):
		return "resource_limit"
	case err != nil && strings.Contains(err.Error(), "uncertain"):
		return "uncertain_operation"
	case err != nil:
		return "execution_failed"
	case !completed:
		return "exchange_incomplete"
	case !verified:
		return "insufficient_verification_evidence"
	case !matched:
		return "response_difference"
	default:
		return ""
	}
}
