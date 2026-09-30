package replaylab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/qualification"
)

type Options struct {
	Binary         string
	SourceRoot     string
	Output         string
	Version        string
	Command        string
	Environment    string
	Duration       time.Duration
	Interval       time.Duration
	ProcessTimeout time.Duration
	Repeat         int
	Cases          []string
	Progress       func(string)
	clock          func() time.Time // test seam for host suspend and clock corrections
}

type caseState struct {
	fixture *Fixture
	result  qualification.LabCaseResult
}

type runEvent struct {
	Case               string    `json:"case"`
	Round              int       `json:"round"`
	Command            string    `json:"command"`
	Repeat             int       `json:"repeat"`
	Started            time.Time `json:"started"`
	Finished           time.Time `json:"finished"`
	Before             Counters  `json:"before"`
	After              Counters  `json:"after"`
	PeerEvents         []string  `json:"peerEvents,omitempty"`
	CLIReport          string    `json:"cliReport"`
	CLIReports         []string  `json:"cliReports,omitempty"`
	Output             string    `json:"output"`
	VerifiedResponses  int       `json:"verifiedResponses"`
	HandshakesObserved int       `json:"handshakesObserved,omitempty"`
	Error              string    `json:"error,omitempty"`
}

// Run never marks a short smoke execution as a two-hour qualification. The
// release gate independently checks every case's span and uninterrupted cadence.
func Run(ctx context.Context, o Options) (result qualification.LabRun, retErr error) {
	if o.Command != "live" && (o.Command != "reproduce" || qualification.UsesStatelessReproduce(o.Version)) {
		return result, fmt.Errorf("application lab requires live; reproduce is stateless from v1.1.0")
	}
	if o.Duration < 0 || o.Interval < 0 {
		return result, fmt.Errorf("lab durations cannot be negative")
	}
	if o.Repeat < 2 {
		return result, fmt.Errorf("lab requires at least two CLI iterations per process")
	}
	if o.ProcessTimeout <= 0 {
		o.ProcessTimeout = 45 * time.Second
	}
	if qualification.UsesStatelessReproduce(o.Version) && (o.Interval > qualification.LabMaxIdleGap || o.ProcessTimeout > qualification.LabMaxExecutionDuration) {
		return result, fmt.Errorf("lab interval or process timeout exceeds qualification continuity limits")
	}
	if o.clock == nil {
		o.clock = time.Now
	}
	var err error
	o.Binary, err = filepath.Abs(o.Binary)
	if err != nil {
		return result, err
	}
	o.Output, err = filepath.Abs(o.Output)
	if err != nil {
		return result, err
	}
	o.SourceRoot, err = filepath.Abs(o.SourceRoot)
	if err != nil {
		return result, err
	}
	if len(o.Cases) == 0 {
		o.Cases = Cases()
	}
	selected := map[string]bool{}
	for _, name := range o.Cases {
		if _, ok := registry[name]; !ok {
			return result, fmt.Errorf("unknown lab case %s", name)
		}
		if selected[name] {
			return result, fmt.Errorf("duplicate lab case %s", name)
		}
		selected[name] = true
	}
	if len(o.Cases) == 0 {
		return result, fmt.Errorf("no registered lab cases")
	}
	if err = os.MkdirAll(o.Output, 0700); err != nil {
		return result, err
	}
	transcriptPath := filepath.Join(o.Output, "transcript.jsonl")
	transcript, err := os.OpenFile(transcriptPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	defer transcript.Close()
	encoder := json.NewEncoder(transcript)
	binaryHash, err := qualification.FileSHA256(o.Binary)
	if err != nil {
		return result, err
	}
	sourceDigest, err := qualification.SourceDigest(o.SourceRoot)
	if err != nil {
		return result, err
	}
	result = qualification.LabRun{SchemaVersion: 1, Version: o.Version, Suite: "application", Platform: runtime.GOOS + "-" + runtime.GOARCH, Environment: o.Environment, Command: o.Command, BinarySHA256: binaryHash, SourceDigest: sourceDigest, Started: time.Now().UTC()}
	if result.Environment == "" {
		result.Environment = "independent loopback software protocol peers; synthetic TCP captures and real locally generated TLS records; no physical devices"
	}
	serverCtx, stopServers := context.WithCancel(ctx)
	defer stopServers()
	states := make([]caseState, 0, len(o.Cases))
	defer func() {
		result.Interrupted = ctx.Err() != nil || retErr != nil
		result.CleanupVerified = true
		for i := range states {
			s := &states[i]
			if s.fixture != nil {
				closeErr := s.fixture.Close()
				clean := closeErr == nil && s.fixture.Snapshot().ActiveConnections == 0
				s.result.CleanupVerified = s.result.CleanupVerified && clean
				if !clean {
					retErr = errors.Join(retErr, fmt.Errorf("%s fixture cleanup failed: %v", s.result.Name, closeErr))
				}
			}
			result.CleanupVerified = result.CleanupVerified && s.result.CleanupVerified
			result.Cases = append(result.Cases, s.result)
		}
		result.Finished = time.Now().UTC()
		if err := transcript.Sync(); err != nil {
			retErr = errors.Join(retErr, err)
		}
		if sum, err := qualification.FileSHA256(transcriptPath); err == nil {
			result.Evidence = append(result.Evidence, qualification.Evidence{Path: "transcript.jsonl", SHA256: sum})
		} else {
			retErr = errors.Join(retErr, err)
		}
		if sum, err := qualification.FileSHA256(o.Binary); err != nil || sum != binaryHash {
			retErr = errors.Join(retErr, fmt.Errorf("lab binary changed during execution"))
			result.Interrupted = true
		}
		if sum, err := qualification.SourceDigest(o.SourceRoot); err != nil || sum != sourceDigest {
			retErr = errors.Join(retErr, fmt.Errorf("lab source changed during execution"))
			result.Interrupted = true
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err == nil {
			err = writeNew(filepath.Join(o.Output, "report.json"), append(data, '\n'))
		}
		retErr = errors.Join(retErr, err)
	}()
	for _, name := range o.Cases {
		fixture, err := registry[name].Setup(serverCtx, filepath.Join(o.Output, "fixtures", name))
		if err != nil {
			states = append(states, caseState{result: qualification.LabCaseResult{Name: name, Failures: 1}})
			return result, fmt.Errorf("setup %s: %w", name, err)
		}
		if fixture.Snapshot == nil || fixture.Close == nil || fixture.Capture == "" {
			return result, fmt.Errorf("case %s returned incomplete fixture", name)
		}
		states = append(states, caseState{fixture: fixture, result: qualification.LabCaseResult{Name: name, CleanupVerified: true}})
	}
	continuity := qualification.LabContinuity{Version: o.Version}
	handshakeProof := qualification.TLSHandshakeLabVerifier{Version: o.Version}
	for round := 1; ; round++ {
		for i := range states {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			s := &states[i]
			name := s.result.Name
			attemptDir := filepath.Join(o.Output, "attempts", fmt.Sprintf("%06d-%s", round, name))
			if err := os.MkdirAll(attemptDir, 0700); err != nil {
				return result, err
			}
			reportPath := filepath.Join(attemptDir, "report.json")
			outputPath := filepath.Join(attemptDir, "output.txt")
			// Exercise the public front-door defaults; an explicit mode would hide
			// routing regressions in the workflow these labs qualify.
			args := []string{o.Command, s.fixture.Capture, "-n", fmt.Sprint(o.Repeat), "-gap", "0s", "-report", reportPath}
			if name != "tls-handshake" {
				args = append(args, "-strict-exit")
			}
			args = append(args, s.fixture.Args...)
			event := runEvent{Case: name, Round: round, Command: o.Command, Repeat: o.Repeat, Started: o.clock().UTC(), Before: s.fixture.Snapshot(), CLIReport: relative(o.Output, reportPath), Output: relative(o.Output, outputPath)}
			if err := continuity.CheckStart(name, event.Started); err != nil {
				s.result.Failures++
				event.Finished, event.Error = event.Started, err.Error()
				return result, errors.Join(err, encoder.Encode(event))
			}
			processCtx, cancel := context.WithTimeout(ctx, o.ProcessTimeout)
			cmd := exec.CommandContext(processCtx, o.Binary, args...)
			cmd.Dir = o.SourceRoot
			var output limitedBuffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			processErr := cmd.Run()
			if processCtx.Err() != nil {
				processErr = errors.Join(processErr, processCtx.Err())
			}
			cancel()
			text := redactOutput(output.String(), s.fixture.Args)
			if err := writeNew(outputPath, []byte(text)); err != nil {
				return result, err
			}
			cleanupDeadline := time.Now().Add(time.Second)
			for s.fixture.Snapshot().ActiveConnections != 0 && time.Now().Before(cleanupDeadline) {
				select {
				case <-ctx.Done():
				case <-time.After(10 * time.Millisecond):
				}
			}
			event.After = s.fixture.Snapshot()
			event.Finished = o.clock().UTC()
			if s.fixture.Events != nil {
				event.PeerEvents = s.fixture.Events()
			}
			reportPaths, pathsErr := CLIReportPaths(reportPath, o.Repeat)
			verified, handshakes := 0, 0
			var reportErr error
			if name == "tls-handshake" {
				var reports [][]byte
				for _, path := range reportPaths {
					data, err := os.ReadFile(path)
					pathsErr = errors.Join(pathsErr, err)
					reports = append(reports, data)
				}
				handshakes, reportErr = handshakeProof.Check(event.Started, event.Finished, o.Repeat, event.PeerEvents, reports)
			} else {
				verified, reportErr = checkCLIReport(reportPath, o.Repeat, o.Version, name)
			}
			for _, path := range reportPaths {
				event.CLIReports = append(event.CLIReports, relative(o.Output, path))
			}
			if len(event.CLIReports) > 0 {
				event.CLIReport = event.CLIReports[0]
			}
			event.VerifiedResponses = verified
			event.HandshakesObserved = handshakes
			checkErr := errors.Join(processErr, reportErr, pathsErr, continuity.Observe(name, event.Started, event.Finished))
			requests := event.After.Requests - event.Before.Requests
			responses := event.After.Responses - event.Before.Responses
			if name == "tls-handshake" {
				if requests != 0 || responses != 0 {
					checkErr = errors.Join(checkErr, fmt.Errorf("TLS handshake-only case sent application traffic"))
				}
			} else if requests < int64(o.Repeat) || responses < int64(o.Repeat) {
				checkErr = errors.Join(checkErr, fmt.Errorf("independent peer counts below CLI repetitions: requests=%d responses=%d repeats=%d", requests, responses, o.Repeat))
			}
			if event.After.Errors != event.Before.Errors {
				checkErr = errors.Join(checkErr, fmt.Errorf("independent peer rejected replay traffic"))
			}
			if event.After.ActiveConnections != 0 {
				checkErr = errors.Join(checkErr, fmt.Errorf("CLI left %d connections open", event.After.ActiveConnections))
				s.result.CleanupVerified = false
			}
			if checkErr != nil {
				s.result.Failures++
				event.Error = checkErr.Error()
			} else {
				s.result.Passes++
				s.result.RepeatedProcessPasses++
				if s.result.FirstAt.IsZero() {
					s.result.FirstAt = event.Started
				}
				s.result.LastAt = event.Finished
				s.result.RequestsObserved += int(requests)
				s.result.ResponsesVerified += verified
				s.result.HandshakesObserved += handshakes
			}
			if err := encoder.Encode(event); err != nil {
				return result, err
			}
			if err := transcript.Sync(); err != nil {
				return result, err
			}
			for _, path := range append([]string{outputPath}, reportPaths...) {
				if sum, err := qualification.FileSHA256(path); err == nil {
					result.Evidence = append(result.Evidence, qualification.Evidence{Path: relative(o.Output, path), SHA256: sum})
				}
			}
			if o.Progress != nil {
				o.Progress(fmt.Sprintf("round=%d case=%s passes=%d failures=%d requests=%d compared=%d", round, name, s.result.Passes, s.result.Failures, requests, verified))
			}
			if checkErr != nil {
				return result, fmt.Errorf("%s round %d: %w", name, round, checkErr)
			}
		}
		complete := true
		for _, s := range states {
			complete = complete && s.result.Passes >= 3 && s.result.LastAt.Sub(s.result.FirstAt) >= o.Duration
		}
		if complete {
			return result, nil
		}
		timer := time.NewTimer(o.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return result, ctx.Err()
		case <-timer.C:
		}
	}
}

func relative(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.ToSlash(rel)
}
func writeNew(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	return errors.Join(e, f.Close())
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	left := (128 << 10) - b.Len()
	if left > 0 {
		if len(p) > left {
			p = p[:left]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func redactOutput(value string, args []string) string {
	for i, arg := range args {
		if (arg == "-pass" || arg == "-password") && i+1 < len(args) && args[i+1] != "" {
			value = strings.ReplaceAll(value, args[i+1], "<redacted>")
		}
	}
	return value
}

// CLIReportPaths identifies either the aggregate generic report or every
// explicitly numbered secure-attempt report. Never glob or accept a partial
// attempt set: both would weaken repeated-process qualification evidence.
func CLIReportPaths(path string, repeats int) ([]string, error) {
	if repeats < 1 {
		return nil, fmt.Errorf("invalid report repetition count")
	}
	if info, err := os.Stat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("CLI report is not a regular file")
		}
		return []string{path}, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	ext := filepath.Ext(path)
	stem := strings.TrimSuffix(path, ext)
	paths := make([]string, repeats)
	for i := range paths {
		paths[i] = fmt.Sprintf("%s.attempt-%d%s", stem, i+1, ext)
		info, err := os.Stat(paths[i])
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("CLI attempt report is not a regular file")
		}
	}
	return paths, nil
}

func checkCLIReport(path string, repeats int, version string, caseNames ...string) (int, error) {
	caseName := ""
	if len(caseNames) > 0 {
		caseName = caseNames[0]
	}
	ftpFixture := caseName == "ftp" || caseName == "ftps-explicit" || caseName == "ftps-implicit"
	paths, err := CLIReportPaths(path, repeats)
	if err != nil {
		return 0, err
	}
	if len(paths) == 1 && paths[0] == path {
		if ftpFixture {
			return 0, fmt.Errorf("FTP fixture requires transfer evidence in every secure-attempt report")
		}
		return checkAggregateCLIReport(path, repeats, version)
	}
	verified := 0
	for attempt, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return 0, err
		}
		var report struct {
			Tool    string `json:"tool"`
			Version string `json:"version"`
			Kind    string `json:"kind"`
			Outcome struct {
				TLSSecretsSource    string `json:"tlsSecretsSource"`
				Completed           bool   `json:"completed"`
				Verified            bool   `json:"verified"`
				Matched             bool   `json:"matched"`
				Compared            int    `json:"comparedResponses"`
				Responses           int    `json:"responses"`
				Mismatches          int    `json:"mismatches"`
				Error               string `json:"error"`
				Cleanup             string `json:"cleanup"`
				PeerIdentityChecked bool   `json:"peerIdentityChecked"`
				ProtocolVersion     string `json:"protocolVersion"`
				Transfers           []struct {
					Command        string `json:"command"`
					ExpectedBytes  int    `json:"expectedBytes"`
					ActualBytes    int    `json:"actualBytes"`
					ExpectedSHA256 string `json:"expectedSha256"`
					ActualSHA256   string `json:"actualSha256"`
					Matched        bool   `json:"matched"`
				} `json:"transfers"`
			} `json:"outcome"`
		}
		if err = json.Unmarshal(data, &report); err != nil {
			return 0, err
		}
		if report.Tool != "livewire" || report.Kind == "" {
			return 0, fmt.Errorf("secure report missing tool or protocol kind")
		}
		if ftpFixture && report.Kind != "ftp" {
			return 0, fmt.Errorf("FTP fixture report has protocol kind %q", report.Kind)
		}
		if version != "" && strings.TrimPrefix(report.Version, "v") != strings.TrimPrefix(version, "v") {
			return 0, fmt.Errorf("secure report version %q differs from lab version %q", report.Version, version)
		}
		o := report.Outcome
		if qualification.UsesStatelessReproduce(version) && report.Kind == "tls" {
			want := "external"
			if caseName == "http1-tls" {
				want = "embedded"
			}
			if o.TLSSecretsSource != want {
				return 0, fmt.Errorf("TLS secrets source differs from the qualified fixture path")
			}
		}
		if !o.Completed || !o.Verified || !o.Matched || o.Error != "" || o.Cleanup == "failed" || o.Mismatches != 0 {
			return 0, fmt.Errorf("secure attempt %d did not complete, verify and match: %s", attempt+1, o.Error)
		}
		if (report.Kind == "tls" || report.Kind == "ssh" || strings.HasPrefix(caseName, "ftps-") || strings.Contains(strings.ToUpper(o.ProtocolVersion), "TLS")) && !o.PeerIdentityChecked {
			return 0, fmt.Errorf("secure attempt %d did not verify peer identity", attempt+1)
		}
		if report.Kind == "ftp" {
			if len(o.Transfers) == 0 {
				return 0, fmt.Errorf("FTP attempt %d lacks data transfer evidence", attempt+1)
			}
			fixtureHash := fmt.Sprintf("sha256:%x", sha256.Sum256(ftpLabData))
			commands := map[string]bool{}
			for _, transfer := range o.Transfers {
				digest, decodeErr := hex.DecodeString(strings.TrimPrefix(transfer.ExpectedSHA256, "sha256:"))
				if !transfer.Matched || transfer.ExpectedBytes <= 0 || transfer.ActualBytes != transfer.ExpectedBytes || !strings.HasPrefix(transfer.ExpectedSHA256, "sha256:") || decodeErr != nil || len(digest) != sha256.Size || transfer.ActualSHA256 != transfer.ExpectedSHA256 {
					return 0, fmt.Errorf("FTP attempt %d lacks matching transfer bytes and hashes", attempt+1)
				}
				if ftpFixture && (commands[transfer.Command] || (transfer.Command != "RETR" && transfer.Command != "STOR") || transfer.ExpectedBytes != len(ftpLabData) || transfer.ExpectedSHA256 != fixtureHash) {
					return 0, fmt.Errorf("FTP attempt %d transfer differs from the independent fixture", attempt+1)
				}
				commands[transfer.Command] = true
			}
			if ftpFixture && (!commands["RETR"] || !commands["STOR"]) {
				return 0, fmt.Errorf("FTP attempt %d must verify both download and upload", attempt+1)
			}
		}
		compared := o.Compared
		if compared == 0 {
			compared = o.Responses
		}
		if compared <= 0 {
			return 0, fmt.Errorf("secure attempt %d lacks positive response comparisons", attempt+1)
		}
		verified += compared
	}
	return verified, nil
}

func checkAggregateCLIReport(path string, repeats int, version string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var report struct {
		Tool     string `json:"tool"`
		Version  string `json:"version"`
		Attempts int    `json:"attempts"`
		Sessions []struct {
			Attempt   int    `json:"attempt"`
			Completed bool   `json:"completed"`
			Verified  bool   `json:"verified"`
			Matched   bool   `json:"matched"`
			Compared  int    `json:"comparedResponses"`
			Received  int    `json:"received"`
			Error     string `json:"error"`
			Cleanup   string `json:"cleanup"`
		} `json:"sessions"`
	}
	if err = json.Unmarshal(data, &report); err != nil {
		return 0, err
	}
	if report.Tool != "livewire" || report.Attempts != repeats || len(report.Sessions) < repeats {
		return 0, fmt.Errorf("CLI report missing expected tool, attempts, or session evidence")
	}
	if version != "" && strings.TrimPrefix(report.Version, "v") != strings.TrimPrefix(version, "v") {
		return 0, fmt.Errorf("CLI report version %q differs from lab version %q", report.Version, version)
	}
	attempts := map[int]bool{}
	verified := 0
	for _, session := range report.Sessions {
		if !session.Completed || !session.Verified || !session.Matched || session.Error != "" || session.Cleanup == "failed" {
			return 0, fmt.Errorf("CLI session did not complete, verify and match: attempt=%d error=%s", session.Attempt, session.Error)
		}
		attempts[session.Attempt] = true
		if session.Compared > 0 {
			verified += session.Compared
		} else {
			verified += session.Received
		}
	}
	for i := 1; i <= repeats; i++ {
		if !attempts[i] {
			return 0, fmt.Errorf("CLI report omits attempt %d", i)
		}
	}
	if verified < repeats {
		return 0, fmt.Errorf("CLI report lacks positive response comparison evidence")
	}
	return verified, nil
}
