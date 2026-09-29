package qualification

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SoftwareLabProfile qualifies executable behavior on controlled software peers.
// It makes no claim about physical NICs, field devices, or uncoached human pilots.
const SoftwareLabProfile = "software-lab"

var ApplicationLabCases = []string{
	"http1", "dns-tcp", "modbus-tcp", "mqtt311", "mqtt5", "dnp3",
	"http1-tls", "dns-tls", "modbus-tls", "mqtt311-tls", "mqtt5-tls", "dnp3-tls",
	"ftp", "ftps-explicit", "ftps-implicit", "ssh",
}

var PacketLabCases = []string{"dns-udp", "udp", "icmp4", "icmp6", "stateful-tcp", "transport-tcp", "wire"}

// LabCaseResult records repeated checks of actual CLI behavior against a peer
// with independent request and response assertions. Times span the first and
// last successful executions, not a sleep after one successful check.
type LabCaseResult struct {
	Name                  string    `json:"name"`
	Passes                int       `json:"passes"`
	Failures              int       `json:"failures"`
	FirstAt               time.Time `json:"firstAt"`
	LastAt                time.Time `json:"lastAt"`
	RequestsObserved      int       `json:"requestsObserved"`
	ResponsesVerified     int       `json:"responsesVerified"`
	FramesObserved        int       `json:"framesObserved,omitempty"`
	CleanupVerified       bool      `json:"cleanupVerified"`
	RepeatedProcessPasses int       `json:"repeatedProcessPasses"`
}

// LabRun is written by the lab, and independently checked by the release gate.
// Evidence must include a redacted event transcript with its SHA256 digest.
type LabRun struct {
	SchemaVersion   int             `json:"schemaVersion"`
	Version         string          `json:"version"`
	Suite           string          `json:"suite"` // application or packet
	Platform        string          `json:"platform"`
	Environment     string          `json:"environment"`
	Command         string          `json:"command"`
	BinarySHA256    string          `json:"binarySha256"`
	SourceDigest    string          `json:"sourceDigest"`
	Started         time.Time       `json:"started"`
	Finished        time.Time       `json:"finished"`
	Interrupted     bool            `json:"interrupted"`
	CleanupVerified bool            `json:"cleanupVerified"`
	Cases           []LabCaseResult `json:"cases"`
	Evidence        []Evidence      `json:"evidence"`
}

type SoftwareLab struct {
	PhysicalQualified   bool       `json:"physicalQualified"`
	HumanPilotQualified bool       `json:"humanPilotQualified"`
	Limitations         []string   `json:"limitations"`
	Runs                []Evidence `json:"runs"`
	Checks              []Evidence `json:"checks"`
}

// LabChecks binds automated regression and dashboard state evidence to the
// same source. Physical qualification remains a separate, unchanged profile.
type LabChecks struct {
	SourceDigest string          `json:"sourceDigest"`
	Platform     string          `json:"platform"`
	Checks       map[string]bool `json:"checks"`
	Evidence     []Evidence      `json:"evidence"`
}

var SoftwareChecks = []string{"build", "vet", "test", "race", "dashboard", "corpus", "protocol-faults", "recovery-cleanup"}

func validateSoftwareLab(doc Manifest, o ValidateOptions) []string {
	var errs []string
	need := func(ok bool, message string) {
		if !ok {
			errs = append(errs, message)
		}
	}
	need(doc.SchemaVersion == 1, "unsupported qualification schema")
	need(doc.Version == o.Version, "qualification version mismatch")
	need(doc.SourceDigest == o.SourceDigest && doc.SourceDigest != "", "qualification source changed; requalify")
	need(len(doc.BlockingFindings) == 0, "unresolved blocking findings")
	lab := doc.SoftwareLab
	if lab == nil {
		return append(errs, "software-lab evidence missing")
	}
	need(!lab.PhysicalQualified && !lab.HumanPilotQualified, "software-lab cannot assert physical or human-pilot qualification")
	need(len(lab.Limitations) > 0, "software-lab scope limitations missing")
	seen := map[string]bool{}
	for _, ref := range lab.Runs {
		data, path, err := verifiedLabEvidence(o.Base, ref)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		var run LabRun
		if err := json.Unmarshal(data, &run); err != nil {
			errs = append(errs, "invalid lab run: "+err.Error())
			continue
		}
		key := run.Platform + "/" + run.Suite + "/" + run.Command
		need(!seen[key], "duplicate lab run: "+key)
		seen[key] = true
		label := key + ": "
		need(run.SchemaVersion == 1 && run.Version == o.Version && run.SourceDigest == o.SourceDigest, label+"run does not match release source/version")
		need(run.Environment != "", label+"environment missing")
		need(!run.Interrupted && run.CleanupVerified, label+"interrupted or cleanup unverified")
		need(run.Finished.Sub(run.Started) >= SoakSeconds*time.Second, label+"two-hour run missing")
		stateless := run.Suite == "stateless"
		need((!stateless && (run.Command == "live" || run.Command == "reproduce")) || (stateless && run.Command == "replay" && run.Platform == "linux-amd64"), label+"unknown command or stateless platform")
		need(run.Platform == "windows-amd64" || run.Platform == "linux-amd64", label+"unknown platform")
		name := "livewire-" + o.Version + "-" + run.Platform
		if strings.HasPrefix(run.Platform, "windows") {
			name += ".exe"
		}
		sum, ok := packagedBinarySHA256(o.Artifacts, name)
		need(ok && sum == run.BinarySHA256, label+"tested binary differs from release or is missing")
		required := ApplicationLabCases
		if run.Suite == "packet" {
			required = PacketLabCases
		}
		if stateless {
			required = []string{"mixed-frames"}
		}
		need(run.Suite == "application" || run.Suite == "packet" || stateless, label+"unknown suite")
		cases := map[string]LabCaseResult{}
		for _, c := range run.Cases {
			_, duplicate := cases[c.Name]
			need(!duplicate, label+"duplicate case "+c.Name)
			cases[c.Name] = c
			need(c.Failures == 0, label+c.Name+": failed executions")
		}
		for _, name := range required {
			c, exists := cases[name]
			need(exists && c.Passes >= 3 && c.Failures == 0 && c.CleanupVerified, label+name+": repeated checks or cleanup missing")
			need(!c.FirstAt.Before(run.Started) && !c.LastAt.After(run.Finished) && c.LastAt.Sub(c.FirstAt) >= SoakSeconds*time.Second, label+name+": case was not exercised across two hours")
			if stateless {
				need(c.FramesObserved >= c.Passes && c.RequestsObserved == 0 && c.ResponsesVerified == 0, label+name+": independent frames missing or application response claim")
			} else {
				need(c.RequestsObserved >= c.Passes && (name == "wire" || name == "transport-tcp" || c.ResponsesVerified >= c.Passes), label+name+": independent traffic/response checks missing")
			}
			need(c.RepeatedProcessPasses >= 3, label+name+": CLI repetition checks missing")
		}
		need(len(run.Evidence) > 0, label+"transcript evidence missing")
		for _, e := range run.Evidence {
			if _, _, err := verifiedLabEvidence(filepath.Dir(path), e); err != nil {
				errs = append(errs, label+err.Error())
			}
		}
		if err := validateLabTranscript(run, filepath.Dir(path)); err != nil {
			errs = append(errs, label+err.Error())
		}
	}
	for _, platformSuite := range []string{"windows-amd64/application", "linux-amd64/application", "linux-amd64/packet"} {
		for _, command := range []string{"live", "reproduce"} {
			need(seen[platformSuite+"/"+command], "missing lab run: "+platformSuite+"/"+command)
		}
	}
	if requiresStatelessLab(o.Version) {
		need(seen["linux-amd64/stateless/replay"], "missing lab run: linux-amd64/stateless/replay")
	}
	checked := map[string]bool{}
	for _, ref := range lab.Checks {
		data, path, err := verifiedLabEvidence(o.Base, ref)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		var checks LabChecks
		if err := json.Unmarshal(data, &checks); err != nil {
			errs = append(errs, "invalid lab checks: "+err.Error())
			continue
		}
		need(!checked[checks.Platform], "duplicate platform checks: "+checks.Platform)
		checked[checks.Platform] = true
		need(checks.SourceDigest == o.SourceDigest, checks.Platform+": checks refer to different source")
		for _, name := range SoftwareChecks {
			need(checks.Checks[name], checks.Platform+": missing automated check "+name)
		}
		need(len(checks.Evidence) > 0, checks.Platform+": automated evidence missing")
		for _, e := range checks.Evidence {
			if _, _, err := verifiedLabEvidence(filepath.Dir(path), e); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	for _, p := range Platforms {
		need(checked[p], "missing software checks: "+p)
	}
	return errs
}

func verifiedLabEvidence(base string, ref Evidence) ([]byte, string, error) {
	if ref.Path == "" || filepath.IsAbs(ref.Path) {
		return nil, "", fmt.Errorf("invalid lab evidence path %q", ref.Path)
	}
	root, err := filepath.Abs(base)
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(root, filepath.FromSlash(ref.Path))
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, "", fmt.Errorf("missing lab evidence %s: %w", ref.Path, err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, "", err
	}
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, "", fmt.Errorf("lab evidence escapes its directory: %s", ref.Path)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return nil, "", fmt.Errorf("lab evidence is missing, nonregular or exceeds 64MiB: %s", ref.Path)
	}
	sum, err := FileSHA256(resolved)
	if err != nil || sum != ref.SHA256 {
		return nil, "", fmt.Errorf("lab evidence checksum mismatch: %s", ref.Path)
	}
	data, err := os.ReadFile(resolved)
	return data, resolved, err
}
