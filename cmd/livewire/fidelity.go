package main

import (
	"fmt"
	"strings"

	"github.com/kvmukilan/livewire/internal/engine"
)

// fidelityProfile is a user-facing replay intent. It keeps the guided command
// understandable while making every fidelity trade-off explicit in reports.
type fidelityProfile struct {
	Name        string
	Description string
	Verify      engine.VerifyMode
	Adaptive    bool
	Pace        bool
	RawL4       bool
}

func parseFidelityProfile(s string) (fidelityProfile, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "functional":
		return fidelityProfile{
			Name: "functional", Description: "preserve application requests and ordering; adapt TCP to the live device",
			Verify: engine.VerifyLenient, Adaptive: true,
		}, nil
	case "timing":
		return fidelityProfile{
			Name: "timing", Description: "functional replay with captured packet gaps and cross-flow overlap",
			Verify: engine.VerifyLenient, Adaptive: true, Pace: true,
		}, nil
	case "transport":
		return fidelityProfile{
			Name: "transport", Description: "preserve captured client TCP flags, retransmissions, ACK pattern, and timing",
			Verify: engine.VerifyLenient, Pace: true, RawL4: true,
		}, nil
	case "wire":
		return fidelityProfile{
			Name: "wire", Description: "inject captured frames at captured timing without claiming live adaptation",
			Verify: engine.VerifyOff, Pace: true, RawL4: true,
		}, nil
	default:
		return fidelityProfile{}, fmt.Errorf("unknown replay profile %q (use functional, timing, transport, or wire)", s)
	}
}
