package webui

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/ftpreplay"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/runvars"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

type ftpReq struct {
	Pcap               string            `json:"pcap"`
	Target             string            `json:"target"`
	Keylog             string            `json:"keylog,omitempty"`
	ServerName         string            `json:"serverName,omitempty"`
	CA                 string            `json:"ca,omitempty"`
	InsecureSkipVerify bool              `json:"insecureSkipVerify,omitempty"`
	Verify             string            `json:"verify,omitempty"`
	TimeoutSeconds     int               `json:"timeoutSeconds,omitempty"`
	Variables          map[string]string `json:"variables,omitempty"`
}

func (s *Server) handleFTP(w http.ResponseWriter, r *http.Request) {
	var req ftpReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	pcapPath, err := s.pcapPath(req.Pcap)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if _, port, err := net.SplitHostPort(req.Target); err != nil {
		writeErr(w, 400, fmt.Errorf("target must be host:port"))
		return
	} else if parsed, err := net.LookupPort("tcp", port); err != nil || parsed < 1 || parsed > 65535 {
		writeErr(w, 400, fmt.Errorf("target port must be between 1 and 65535"))
		return
	}
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = 30
	}
	if req.TimeoutSeconds < 1 || req.TimeoutSeconds > 600 {
		writeErr(w, 400, fmt.Errorf("timeoutSeconds must be between 1 and 600"))
		return
	}
	if _, err := parseWebFTPVerify(req.Verify); err != nil {
		writeErr(w, 400, err)
		return
	}
	keylogPath, caPath := "", ""
	if req.Keylog != "" {
		keylogPath, err = s.existingArtifactPath(req.Keylog, ".keylog", ".log", ".txt")
		if err != nil {
			writeErr(w, 400, err)
			return
		}
	}
	if req.CA != "" {
		caPath, err = s.existingArtifactPath(req.CA, ".pem", ".crt")
		if err != nil {
			writeErr(w, 400, err)
			return
		}
	}
	_, err = s.startJob("ftp", func(j *job) { s.runFTP(j, pcapPath, keylogPath, caPath, req) })
	if err != nil {
		writeErr(w, 409, err)
		return
	}
	writeJSON(w, map[string]any{"started": true})
}

func (s *Server) runFTP(j *job, pcapPath, keylogPath, caPath string, req ftpReq) {
	j.protectVariables(req.Variables)
	records, _, err := s.loadPcap(pcapPath)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "load failed")
		return
	}
	trace := replay.ExtractTrace(records, replay.ExtractOptions{})
	control, err := selectWebFTPControl(trace)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "control selection failed")
		return
	}
	var keylog *tlsreplay.KeyLog
	if keylogPath != "" {
		f, err := s.openRootedPath(keylogPath)
		if err != nil {
			j.log(err.Error())
			j.finish(false, "key log open failed")
			return
		}
		keylog, err = tlsreplay.ParseKeyLog(f)
		closeErr := f.Close()
		err = errors.Join(err, closeErr)
		if err != nil {
			j.log(err.Error())
			j.finish(false, "key log parse failed")
			return
		}
	}
	script, err := ftpreplay.BuildScript(control, keylog)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "FTP script failed")
		return
	}
	data, err := ftpreplay.MatchDataSessions(trace, control, script)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "data mapping failed")
		return
	}
	var tlsConfig *tls.Config
	if script.Explicit || script.Implicit || script.ProtectData {
		var caPEM []byte
		if caPath != "" {
			caPEM, err = s.readRootedBytes(caPath, 4<<20)
			if err != nil {
				j.log(err.Error())
				j.finish(false, "CA read failed")
				return
			}
		}
		tlsConfig, err = webFTPTLSConfig(req.Target, req.ServerName, caPEM, req.InsecureSkipVerify)
		if err != nil {
			j.log(err.Error())
			j.finish(false, "TLS configuration failed")
			return
		}
	}
	verify, _ := parseWebFTPVerify(req.Verify)
	result, runErr := ftpreplay.RunContext(j.ctx, ftpreplay.Config{
		Control: control, Data: data, Address: req.Target, Script: script,
		Variables: req.Variables, TLSConfig: tlsConfig, Timeout: time.Duration(req.TimeoutSeconds) * time.Second,
		Verify: verify, Progress: j.log,
	})
	reportName := "ftp-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".report.json"
	doc := map[string]any{
		"tool": "livewire", "version": s.version, "kind": "ftp", "when": time.Now().UTC(),
		"target": req.Target, "adapterVersions": adapters.Versions(), "variables": runvars.Redacted(req.Variables),
		"controlSession": control.ID, "dataSessions": sessionIDs(data), "result": result,
		"limitations": []string{"packet payloads and supplied TLS secrets are excluded from this report"},
	}
	if req.InsecureSkipVerify {
		doc["limitations"] = append(doc["limitations"].([]string), "FTPS peer identity verification was explicitly disabled")
	}
	if runErr != nil {
		doc["error"] = runErr.Error()
	}
	if err := writeRedactedJSON(filepath.Join(s.dir, reportName), doc, req.Variables); err != nil {
		j.log(err.Error())
		j.finish(false, "report failed")
		return
	}
	j.artifact(reportName)
	if runErr != nil {
		j.log(runErr.Error())
		j.finish(false, "FTP replay failed")
		return
	}
	j.finish(result.Completed, fmt.Sprintf("FTP complete: %d command(s), %d transfer(s)", result.Commands, len(result.Transfers)))
}

func selectWebFTPControl(trace *replay.Trace) (*replay.Session, error) {
	var selected *replay.Session
	for _, session := range trace.Sessions {
		if session.Transport != replay.TransportTCP {
			continue
		}
		client, _, err := replay.TCPPayloadStreams(session)
		if err != nil {
			continue
		}
		if (adapters.FTP{}).Detect(*session) < 100 && !(session.Server.Port == 990 && dissect.DetectTLS(client).IsTLS) {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("capture contains more than one FTP control session")
		}
		selected = session
	}
	if selected == nil {
		return nil, fmt.Errorf("no FTP or FTPS control session found")
	}
	return selected, nil
}

func parseWebFTPVerify(value string) (replay.VerifyMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "lenient":
		return replay.VerifyLenient, nil
	case "off":
		return replay.VerifyOff, nil
	case "strict":
		return replay.VerifyStrict, nil
	default:
		return "", fmt.Errorf("verify must be off, lenient, or strict")
	}
}

func webFTPTLSConfig(target, serverName string, caPEM []byte, insecure bool) (*tls.Config, error) {
	host, _, _ := net.SplitHostPort(target)
	if serverName == "" {
		serverName = strings.Trim(host, "[]")
	}
	config := &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure} // #nosec G402 -- explicit lab flag
	if len(caPEM) == 0 {
		return config, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA file contains no certificates")
	}
	config.RootCAs = roots
	return config, nil
}

func sessionIDs(sessions []*replay.Session) []string {
	out := make([]string, len(sessions))
	for i, session := range sessions {
		out[i] = session.ID
	}
	return out
}
