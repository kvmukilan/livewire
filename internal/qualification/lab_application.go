package qualification

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type applicationLabOutcome struct {
	Adapter             string                   `json:"adapter"`
	Mode                string                   `json:"mode"`
	Status              string                   `json:"status"`
	Attempt             int                      `json:"attempt"`
	Completed           bool                     `json:"completed"`
	Verified            bool                     `json:"verified"`
	Matched             bool                     `json:"matched"`
	Compared            int                      `json:"comparedResponses"`
	Responses           int                      `json:"responses"`
	Mismatches          int                      `json:"mismatches"`
	Error               string                   `json:"error"`
	Cleanup             string                   `json:"cleanup"`
	PeerIdentityChecked bool                     `json:"peerIdentityChecked"`
	TLSSecretsSource    string                   `json:"tlsSecretsSource"`
	Transfers           []applicationLabTransfer `json:"transfers"`
}

type applicationLabTransfer struct {
	Command        string `json:"command"`
	ExpectedBytes  int    `json:"expectedBytes"`
	ActualBytes    int    `json:"actualBytes"`
	ExpectedSHA256 string `json:"expectedSha256"`
	ActualSHA256   string `json:"actualSha256"`
	Matched        bool   `json:"matched"`
}

type applicationLabReport struct {
	Tool     string                  `json:"tool"`
	Version  string                  `json:"version"`
	Kind     string                  `json:"kind"`
	Intent   string                  `json:"intent"`
	When     time.Time               `json:"when"`
	Attempts int                     `json:"attempts"`
	Sessions []applicationLabOutcome `json:"sessions"`
	Outcome  applicationLabOutcome   `json:"outcome"`
}

// Independently check the retained CLI outcome rather than trusting the lab's
// success flag. This contract applies only to releases >=1.1.0; historical
// evidence continues to use its original validation rules.
func validateApplicationCLIReports(version string, event labEvent, reports [][]byte) error {
	kind, adapter := applicationLabProtocol(event.Case)
	if adapter == "" {
		return fmt.Errorf("unknown application fixture %s", event.Case)
	}
	wantReports := 1
	if kind != "" {
		wantReports = event.Repeat
	}
	if len(reports) != wantReports {
		return fmt.Errorf("incomplete CLI reports for %s", event.Case)
	}
	verified := 0
	for _, data := range reports {
		var report applicationLabReport
		if err := json.Unmarshal(data, &report); err != nil {
			return fmt.Errorf("invalid application CLI report: %w", err)
		}
		if report.Tool != "livewire" || strings.TrimPrefix(report.Version, "v") != strings.TrimPrefix(version, "v") || report.Kind != kind {
			return fmt.Errorf("application CLI report identity differs from %s", event.Case)
		}
		// Generic reports use second precision, while secure reports retain
		// subsecond time. Permit clock serialization rounding, not older runs.
		if report.When.IsZero() || report.When.Before(event.Started.Add(-2*time.Second)) || report.When.After(event.Finished.Add(2*time.Second)) {
			return fmt.Errorf("application CLI report time outside execution")
		}
		outcomes := report.Sessions
		if kind == "" {
			if report.Intent != "application" || report.Attempts != event.Repeat || len(outcomes) != event.Repeat {
				return fmt.Errorf("application CLI report omits repeated live sessions")
			}
		} else {
			if len(report.Sessions) != 0 {
				return fmt.Errorf("secure CLI report contains unexpected sessions")
			}
			outcomes = []applicationLabOutcome{report.Outcome}
		}
		attempts := map[int]bool{}
		for _, outcome := range outcomes {
			if !outcome.Completed || !outcome.Verified || !outcome.Matched || outcome.Status != "matched" || outcome.Error != "" || outcome.Cleanup == "failed" || outcome.Mismatches != 0 || outcome.Adapter != adapter {
				return fmt.Errorf("application CLI outcome did not complete, verify and match %s", event.Case)
			}
			if kind == "" {
				if outcome.Mode != "semantic" || outcome.Cleanup != "complete" || outcome.Attempt < 1 || outcome.Attempt > event.Repeat || attempts[outcome.Attempt] {
					return fmt.Errorf("application CLI session mode, cleanup or attempt differs")
				}
				attempts[outcome.Attempt] = true
			}
			if kind == "tls" {
				want := "external"
				if event.Case == "http1-tls" {
					want = "embedded"
				}
				if outcome.TLSSecretsSource != want {
					return fmt.Errorf("TLS secrets source differs from the qualified fixture path")
				}
			}
			if (kind == "tls" || kind == "ssh" || strings.HasPrefix(event.Case, "ftps-")) && !outcome.PeerIdentityChecked {
				return fmt.Errorf("secure CLI outcome did not verify peer identity")
			}
			if kind == "ftp" {
				// The public lab fixture has a fixed, synthetic transfer body.
				body := []byte("livewire software-lab transfer\x00\x01\xff\n")
				digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
				commands := map[string]bool{}
				if len(outcome.Transfers) != 2 {
					return fmt.Errorf("FTP CLI outcome lacks both transfer directions")
				}
				for _, transfer := range outcome.Transfers {
					if (transfer.Command != "RETR" && transfer.Command != "STOR") || commands[transfer.Command] || !transfer.Matched || transfer.ExpectedBytes != len(body) || transfer.ActualBytes != len(body) || transfer.ExpectedSHA256 != digest || transfer.ActualSHA256 != digest {
						return fmt.Errorf("FTP CLI transfer differs from independent fixture")
					}
					commands[transfer.Command] = true
				}
			}
			compared := outcome.Compared
			if kind == "ftp" || kind == "ssh" {
				compared = outcome.Responses
			}
			if compared <= 0 {
				return fmt.Errorf("application CLI outcome lacks positive comparisons")
			}
			verified += compared
		}
	}
	if verified != event.VerifiedResponses {
		return fmt.Errorf("application CLI comparisons differ from transcript")
	}
	return nil
}

func applicationLabProtocol(name string) (kind, adapter string) {
	switch name {
	case "ftp", "ftps-explicit", "ftps-implicit":
		return "ftp", "ftp"
	case "ssh":
		return "ssh", "ssh-reterminate"
	}
	if strings.HasSuffix(name, "-tls") {
		kind = "tls"
		name = strings.TrimSuffix(name, "-tls")
	}
	switch name {
	case "http1":
		adapter = "http/1"
	case "dns", "dns-tcp":
		adapter = "dns/tcp"
	case "mqtt311", "mqtt5":
		adapter = "mqtt"
	case "modbus", "modbus-tcp":
		adapter = "modbus-tcp"
	case "dnp3":
		adapter = "dnp3"
	}
	return kind, adapter
}
