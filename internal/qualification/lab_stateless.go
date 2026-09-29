package qualification

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

// v1.0.0 retains its original six-run gate. Later stable releases also exercise
// the distinct stateless replay command; old evidence is not relabeled.
func requiresStatelessLab(version string) bool {
	parts := strings.Split(strings.SplitN(strings.TrimPrefix(version, "v"), "-", 2)[0], ".")
	if len(parts) != 3 {
		return true
	}
	numbers := [3]int{}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return true
		}
		numbers[i] = n
	}
	return numbers[0] > 1 || numbers[0] == 1 && (numbers[1] > 0 || numbers[2] >= 1)
}

type statelessLabEvent struct {
	labEvent
	Fixture        string `json:"fixture"`
	FixtureSHA256  string `json:"fixtureSha256"`
	FramesObserved int    `json:"framesObserved"`
	Firewall       string `json:"firewall"`
	FirewallSHA256 string `json:"firewallSha256"`
}

func validateStatelessTranscript(run LabRun, base string) error {
	if run.Platform != "linux-amd64" || run.Command != "replay" || len(run.Cases) != 1 || run.Cases[0].Name != "mixed-frames" {
		return fmt.Errorf("unexpected stateless run identity or case set")
	}
	files := map[string]Evidence{}
	for _, ref := range run.Evidence {
		if _, exists := files[ref.Path]; exists {
			return fmt.Errorf("duplicate stateless evidence %s", ref.Path)
		}
		files[ref.Path] = ref
	}
	read := func(path, hash string) ([]byte, error) {
		ref, ok := files[path]
		if !ok || hash != "" && ref.SHA256 != hash {
			return nil, fmt.Errorf("unbound stateless evidence %s", path)
		}
		data, _, err := verifiedLabEvidence(base, ref)
		return data, err
	}
	data, err := read("events.jsonl", "")
	if err != nil {
		return err
	}
	observed := LabCaseResult{Name: "mixed-frames", CleanupVerified: true}
	cleaned := false
	usedArtifacts := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		var event statelessLabEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return err
		}
		switch event.Event {
		case "setup":
			if cleaned || observed.Passes != 0 {
				return fmt.Errorf("stateless setup after execution")
			}
			continue
		case "cleanup":
			if cleaned || !event.Verified {
				return fmt.Errorf("stateless cleanup failed or repeated")
			}
			cleaned = true
			continue
		case "pass":
			if cleaned || event.Command != "replay" || event.Case != "mixed-frames" || event.Error != "" || event.Round != observed.Passes+1 || event.Repeat < 2 || event.Repeat > 1000 || !event.CleanupVerified || event.Requests != 0 || event.Responses != 0 || event.Started.Before(run.Started) || event.Finished.After(run.Finished) || event.Finished.Before(event.Started) || !observed.LastAt.IsZero() && event.Started.Before(observed.LastAt) {
				return fmt.Errorf("invalid stateless execution")
			}
		default:
			return fmt.Errorf("unsuccessful stateless event %q", event.Event)
		}
		if event.FixtureSHA256 == "" || event.CaptureSHA256 == "" || event.ReportSHA256 == "" || event.FirewallSHA256 == "" {
			return fmt.Errorf("stateless execution hashes missing")
		}
		for _, path := range []string{event.IndependentCapture, event.Report, event.Output, event.Firewall} {
			if path == "" || usedArtifacts[path] {
				return fmt.Errorf("stateless execution reuses or omits an observation artifact")
			}
			usedArtifacts[path] = true
		}
		fixture, err := read(event.Fixture, event.FixtureSHA256)
		if err != nil {
			return err
		}
		capture, err := read(event.IndependentCapture, event.CaptureSHA256)
		if err != nil {
			return err
		}
		frames, err := compareStatelessFrames(fixture, capture, event.Repeat, event.Started, event.Finished)
		if err != nil || frames != event.FramesObserved {
			return fmt.Errorf("stateless frame proof differs: %v", err)
		}
		report, err := read(event.Report, event.ReportSHA256)
		if err != nil {
			return err
		}
		var outcome struct {
			Tool, Version, Mode, Status, CaptureDigest, Error string
			Completed                                         bool
			Verified                                          *bool
			Passes, FramesPerPass, FramesSent                 int
		}
		if err := json.Unmarshal(report, &outcome); err != nil {
			return err
		}
		if outcome.Tool != "livewire" || outcome.Version != run.Version || outcome.Mode != "wire" || outcome.Status != "wire" || !outcome.Completed || outcome.Verified == nil || *outcome.Verified || outcome.Error != "" || outcome.Passes != event.Repeat || outcome.FramesSent != frames || outcome.FramesPerPass != frames/event.Repeat || outcome.CaptureDigest != fmt.Sprintf("sha256:%x", sha256.Sum256(fixture)) {
			return fmt.Errorf("stateless CLI outcome differs from independent frames or claims verification")
		}
		if _, err := read(event.Output, ""); err != nil {
			return err
		}
		firewall, err := read(event.Firewall, event.FirewallSHA256)
		if err != nil {
			return err
		}
		if bytes.Contains(bytes.ToLower(firewall), []byte("livewire")) || bytes.Contains(firewall, []byte("--tcp-flags")) {
			return fmt.Errorf("stateless replay left a firewall guard")
		}
		if observed.Passes == 0 {
			observed.FirstAt = event.Started
		}
		observed.LastAt = event.Finished
		observed.Passes++
		observed.RepeatedProcessPasses++
		observed.FramesObserved += frames
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	c := run.Cases[0]
	if !cleaned || c.Name != observed.Name || c.Passes != observed.Passes || c.RepeatedProcessPasses != observed.RepeatedProcessPasses || c.Failures != 0 || c.RequestsObserved != 0 || c.ResponsesVerified != 0 || c.FramesObserved != observed.FramesObserved || !c.CleanupVerified || !c.FirstAt.Equal(observed.FirstAt) || !c.LastAt.Equal(observed.LastAt) {
		return fmt.Errorf("stateless summary differs from execution transcript or cleanup missing")
	}
	return nil
}

func compareStatelessFrames(fixture, actual []byte, repeats int, started, finished time.Time) (int, error) {
	limits := pcapio.Limits{MaxRecords: 100000, MaxCaptureData: 64 << 20}
	want, err := pcapio.Load(bytes.NewReader(fixture), limits)
	if err != nil {
		return 0, err
	}
	got, err := pcapio.Load(bytes.NewReader(actual), limits)
	if err != nil {
		return 0, err
	}
	if repeats < 2 || repeats > 1000 || len(want.Records) == 0 || len(got.Records) != len(want.Records)*repeats {
		return 0, fmt.Errorf("stateless frame count differs")
	}
	kinds, directions := map[string]bool{}, map[string]bool{}
	for _, record := range want.Records {
		b := record.Data
		if record.LinkType != wire.LinkEthernet || record.CapLen != record.OrigLen || len(b) < 60 {
			return 0, fmt.Errorf("stateless fixture is not complete padded Ethernet")
		}
		directions[string(b[:12])] = true
		switch binary.BigEndian.Uint16(b[12:14]) {
		case 0x0800:
			switch b[23] {
			case 6:
				kinds["tcp"] = true
				at := 14 + int(b[14]&15)*4
				if at+20 <= len(b) {
					at += int(b[at+12]>>4) * 4
					if at+5 <= len(b) && b[at] == 23 && b[at+1] == 3 {
						kinds["tls-bytes"] = true
					}
				}
			case 17:
				kinds["udp"] = true
			case 1:
				kinds["icmp4"] = true
			}
		case 0x86dd:
			if b[20] == 58 {
				kinds["icmp6"] = true
			}
		default:
			kinds["unknown-ether-type"] = true
		}
	}
	for _, kind := range []string{"tcp", "tls-bytes", "udp", "icmp4", "icmp6", "unknown-ether-type"} {
		if !kinds[kind] {
			return 0, fmt.Errorf("stateless fixture lacks %s", kind)
		}
	}
	both := false
	for pair := range directions {
		both = both || pair[:6] != pair[6:12] && directions[pair[6:12]+pair[:6]]
	}
	if !both {
		return 0, fmt.Errorf("stateless fixture lacks both captured directions")
	}
	for i, record := range got.Records {
		if record.LinkType != wire.LinkEthernet || record.CapLen != record.OrigLen || !bytes.Equal(record.Data, want.Records[i%len(want.Records)].Data) {
			return 0, fmt.Errorf("stateless frame %d bytes or order differ", i)
		}
		// Kernel capture and Python event timestamps use the same host clock.
		// Allow two seconds for clock/record precision, never an old round's
		// observation stretched over a two-hour transcript.
		if record.Time.Before(started.Add(-2*time.Second)) || record.Time.After(finished.Add(2*time.Second)) {
			return 0, fmt.Errorf("stateless frame %d timestamp is outside its execution", i)
		}
	}
	return len(got.Records), nil
}
