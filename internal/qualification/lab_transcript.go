package qualification

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// The two independent labs have different observation mechanisms, but their
// summaries must agree exactly with the successful executions in their logs.
// Hashes bind the retained files; they do not authenticate the person running
// the lab or replace review of the independent peer's assertions.
type labEvent struct {
	Event              string    `json:"event"`
	Case               string    `json:"case"`
	Command            string    `json:"command"`
	Round              int       `json:"round"`
	Repeat             int       `json:"repeat"`
	Started            time.Time `json:"started"`
	Finished           time.Time `json:"finished"`
	Error              string    `json:"error"`
	Before             labCounts `json:"before"`
	After              labCounts `json:"after"`
	VerifiedResponses  int       `json:"verifiedResponses"`
	CLIReport          string    `json:"cliReport"`
	CLIReports         []string  `json:"cliReports"`
	Output             string    `json:"output"`
	Requests           int       `json:"requests"`
	Responses          int       `json:"responses"`
	CleanupVerified    bool      `json:"cleanupVerified"`
	Verified           bool      `json:"verified"`
	IndependentCapture string    `json:"independentCapture"`
	CaptureSHA256      string    `json:"captureSha256"`
	Report             string    `json:"report"`
	ReportSHA256       string    `json:"reportSha256"`
	Impairment         string    `json:"impairment"`
}

type labCounts struct {
	Requests, Responses, ActiveConnections, Errors int
}

func validateLabTranscript(run LabRun, base string) error {
	files := make(map[string]Evidence, len(run.Evidence))
	for _, e := range run.Evidence {
		if _, exists := files[e.Path]; exists {
			return fmt.Errorf("duplicate evidence path %s", e.Path)
		}
		files[e.Path] = e
	}
	read := func(path, sum string) ([]byte, error) {
		e, ok := files[path]
		if !ok || (sum != "" && sum != e.SHA256) {
			return nil, fmt.Errorf("transcript references unbound evidence %q", path)
		}
		data, _, err := verifiedLabEvidence(base, e)
		return data, err
	}
	name := "transcript.jsonl"
	if run.Suite == "packet" {
		name = "events.jsonl"
	}
	data, err := read(name, "")
	if err != nil {
		return err
	}
	totals := map[string]LabCaseResult{}
	rounds := map[string]int{}
	packetCleanup := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for line := 1; scanner.Scan(); line++ {
		var event labEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("invalid transcript line %d: %w", line, err)
		}
		if run.Suite == "packet" {
			switch event.Event {
			case "setup":
				continue
			case "cleanup":
				if !event.Verified {
					return fmt.Errorf("packet cleanup failed")
				}
				packetCleanup = true
				continue
			case "pass":
				if packetCleanup {
					return fmt.Errorf("packet execution after cleanup")
				}
				if (event.Command != "live" && event.Command != "reproduce") || event.Case == "" || event.Error != "" || event.Repeat < 2 || event.Round < 1 || event.Started.Before(run.Started) || event.Finished.After(run.Finished) || event.Finished.Before(event.Started) || !event.CleanupVerified {
					return fmt.Errorf("invalid packet execution at transcript line %d", line)
				}
			default:
				return fmt.Errorf("packet transcript contains unsuccessful event %q", event.Event)
			}
			if event.Command != run.Command {
				continue // the packet lab records both commands in one transcript
			}
		}
		if event.Command != run.Command || event.Case == "" || event.Error != "" || event.Repeat < 2 ||
			event.Round != rounds[event.Case]+1 || event.Started.Before(run.Started) || event.Finished.After(run.Finished) || event.Finished.Before(event.Started) {
			return fmt.Errorf("invalid successful execution at transcript line %d", line)
		}
		prior := totals[event.Case]
		if !prior.LastAt.IsZero() && event.Started.Before(prior.LastAt) {
			return fmt.Errorf("overlapping executions for %s", event.Case)
		}
		requests, responses := event.Requests, event.Responses
		if run.Suite == "application" {
			requests = event.After.Requests - event.Before.Requests
			responses = event.VerifiedResponses
			if event.Before.Errors != 0 || event.After.Errors != 0 || event.After.ActiveConnections != 0 || event.Before.ActiveConnections != 0 || event.After.Responses-event.Before.Responses < event.Repeat {
				return fmt.Errorf("peer failure or cleanup missing for %s", event.Case)
			}
			if _, err := read(event.Output, ""); err != nil {
				return err
			}
			paths := event.CLIReports
			if len(paths) == 0 {
				paths = []string{event.CLIReport}
			}
			if len(paths) != 1 && len(paths) != event.Repeat {
				return fmt.Errorf("incomplete CLI reports for %s", event.Case)
			}
			seen := map[string]bool{}
			for _, path := range paths {
				if seen[path] {
					return fmt.Errorf("duplicate CLI report for %s", event.Case)
				}
				seen[path] = true
				if _, err := read(path, ""); err != nil {
					return err
				}
			}
		} else {
			if !event.CleanupVerified {
				return fmt.Errorf("packet execution cleanup missing")
			}
			if event.Case == "stateful-tcp" && !strings.Contains(event.Impairment, "loss") {
				return fmt.Errorf("stateful TCP packet impairment missing")
			}
			if event.CaptureSHA256 == "" || event.ReportSHA256 == "" {
				return fmt.Errorf("packet observation hashes missing")
			}
			capture, err := read(event.IndependentCapture, event.CaptureSHA256)
			if err != nil {
				return err
			}
			if len(capture) <= 24 {
				return fmt.Errorf("empty independent packet capture")
			}
			if _, err := read(event.Report, event.ReportSHA256); err != nil {
				return err
			}
		}
		if requests < event.Repeat || (event.Case != "wire" && event.Case != "transport-tcp" && responses < event.Repeat) || responses < 0 {
			return fmt.Errorf("missing independent observations for %s", event.Case)
		}
		if prior.Passes == 0 {
			prior.Name, prior.FirstAt = event.Case, event.Started
		}
		prior.LastAt = event.Finished
		prior.Passes++
		prior.RepeatedProcessPasses++
		prior.RequestsObserved += requests
		prior.ResponsesVerified += responses
		prior.CleanupVerified = true
		totals[event.Case] = prior
		rounds[event.Case] = event.Round
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if run.Suite == "packet" && !packetCleanup {
		return fmt.Errorf("packet cleanup transcript missing")
	}
	if len(totals) != len(run.Cases) {
		return fmt.Errorf("transcript case set differs from run summary")
	}
	for _, c := range run.Cases {
		observed := totals[c.Name]
		if c.Name != observed.Name || c.Passes != observed.Passes || c.Failures != 0 || c.RequestsObserved != observed.RequestsObserved || c.ResponsesVerified != observed.ResponsesVerified || c.RepeatedProcessPasses != observed.RepeatedProcessPasses || !c.CleanupVerified || !c.FirstAt.Equal(observed.FirstAt) || !c.LastAt.Equal(observed.LastAt) {
			return fmt.Errorf("%s summary differs from execution transcript", c.Name)
		}
	}
	return nil
}
