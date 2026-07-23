package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

func cmdTLSReplay(args []string) error {
	fs := flag.NewFlagSet("tls-replay", flag.ContinueOnError)
	inPath := fs.String("in", "", "capture containing one TLS session (required)")
	keylogPath := fs.String("keylog", "", "NSS SSLKEYLOGFILE matching the capture (required; never logged)")
	target := fs.String("target", "", "fresh TLS target host:port (required)")
	serverName := fs.String("server-name", "", "certificate DNS name (default: target host)")
	caPath := fs.String("ca", "", "optional PEM CA bundle")
	insecure := fs.Bool("insecure-skip-verify", false, "explicitly disable certificate verification (lab only)")
	strict := fs.Bool("strict", false, "require live plaintext responses to byte-match the capture")
	timeout := fs.Duration("timeout", 10*time.Second, "fresh connection timeout")
	reportPath := fs.String("report", "", "output redacted JSON report (default: <capture>.tls.report.json)")
	var variables setFlags
	fs.Var(&variables, "set", "set an inner-protocol variable (repeatable name=value)")
	var rulePacks fileFlags
	fs.Var(&rulePacks, "rules", "JSON inner-protocol adapter rule pack (repeatable)")
	fs.Usage = func() {
		fmt.Println("usage: livewire tls-replay -in trace.pcap -keylog sslkeys.log -target host:port [-server-name name] [-set name=value]")
		fmt.Println("\nDecrypts supported TLS 1.2/1.3 AEAD records with the supplied key log, opens a fresh verified TLS connection, and replays plaintext through the detected inner adapter.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *keylogPath == "" || *target == "" {
		fs.Usage()
		return fmt.Errorf("-in, -keylog, and -target are required")
	}
	records, _, err := loadRecords(*inPath)
	if err != nil {
		return err
	}
	trace := replay.ExtractTrace(records, replay.ExtractOptions{})
	var session *replay.Session
	for _, s := range trace.Sessions {
		if s.Transport == replay.TransportTCP && isTLSSession(s) {
			if session != nil {
				return fmt.Errorf("capture contains more than one TLS session; isolate the intended session first")
			}
			session = s
		}
	}
	if session == nil {
		return fmt.Errorf("no TLS session found in capture")
	}
	clientTimeline, serverTimeline, err := replay.TCPPayloadTimelines(session)
	if err != nil {
		return fmt.Errorf("TLS TCP stream reconstruction: %w", err)
	}
	kf, err := os.Open(*keylogPath)
	if err != nil {
		return err
	}
	keylog, err := tlsreplay.ParseKeyLog(kf)
	_ = kf.Close()
	if err != nil {
		return err
	}
	messages, err := tlsreplay.NewDecryptor(keylog).DecryptFlowTimed(
		clientTimeline.Data, serverTimeline.Data,
		clientTimeline.CompletionPoint, serverTimeline.CompletionPoint,
	)
	if err != nil {
		return err
	}
	registry, err := registryWithRulePacks(rulePacks)
	if err != nil {
		return err
	}
	innerSession := replay.Session{Transport: replay.TransportTCP, Client: session.Client, Server: session.Server}
	for i, m := range messages {
		dir := replay.ClientToServer
		if m.Role == tlsreplay.FromServer {
			dir = replay.ServerToClient
		}
		innerSession.Events = append(innerSession.Events, replay.Event{PacketIndex: i, Direction: dir, Payload: m.Data})
	}
	inner, confidence := registry.Best(innerSession)
	if confidence == 0 || inner == nil || inner.Name() == "tls-reterminate" || inner.Name() == "ssh-reterminate" {
		inner = nil
	}
	state := &replay.RuntimeState{Variables: copyStringMap(variables), Learned: map[string][]byte{}}
	script := tlsreplay.ConversationOrder(messages)
	if inner != nil {
		script, err = buildTLSAdapterScript(messages, inner, state)
		if err != nil {
			return err
		}
	}
	plan := buildReterminationPlan(trace, session, "tls-reterminate", "tls-reterminate")
	if err := plan.ValidateCoverage(); err != nil {
		return fmt.Errorf("TLS replay plan coverage: %w", err)
	}
	printCoverage(plan)
	if *reportPath == "" {
		*reportPath = strings.TrimSuffix(*inPath, filepath.Ext(*inPath)) + ".tls.report.json"
	}
	digest, err := sha256File(*inPath)
	if err != nil {
		return fmt.Errorf("capture digest: %w", err)
	}
	host, _, err := net.SplitHostPort(*target)
	if err != nil {
		return fmt.Errorf("invalid -target: %w", err)
	}
	if *serverName == "" {
		*serverName = strings.Trim(host, "[]")
	}
	tlsCfg := &tls.Config{ServerName: *serverName, InsecureSkipVerify: *insecure} // #nosec G402 -- explicit lab flag
	if *caPath != "" {
		pem, err := os.ReadFile(*caPath)
		if err != nil {
			return err
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("-ca contains no parseable certificates")
		}
		tlsCfg.RootCAs = roots
	}
	verifyMode := replay.VerifyLenient
	if *strict {
		verifyMode = replay.VerifyStrict
	}
	innerName := "opaque plaintext"
	if inner != nil {
		innerName = inner.Name()
	}
	report := newReterminationReport("tls", digest, *target, plan, registry, variables)
	report.Transformations = []string{
		"captured TLS records decrypted with operator-supplied session secrets (secrets excluded from this report)",
		"fresh TLS connection established to the live target",
		"decrypted application chronology replayed through " + innerName,
	}
	if *insecure {
		report.Limitations = append(report.Limitations, "TLS peer identity verification was explicitly disabled")
	}
	report.Outcome.Adapter = innerName
	report.Outcome.Requests = countTLSRole(script, tlsreplay.FromClient)
	report.Outcome.Verified = *strict || inner != nil

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, runErr := tlsreplay.ReTerminateContext(ctx, tlsreplay.ReTermConfig{Address: *target, TLSConfig: tlsCfg, Script: script, Timeout: *timeout, Verify: *strict, Adapter: inner, State: state, VerifyMode: verifyMode})
	if res != nil {
		report.Outcome.ProtocolVersion = tlsVersionName(res.HandshakeState.Version)
		report.Outcome.CipherSuite = tls.CipherSuiteName(res.HandshakeState.CipherSuite)
		report.Outcome.ALPN = res.HandshakeState.NegotiatedProtocol
		report.Outcome.Responses = len(res.Responses)
		report.Outcome.Mismatches = res.Mismatches
		report.Outcome.Differences = res.Differences
		report.Outcome.Matched = report.Outcome.Verified && res.Mismatches == 0
		report.Outcome.PeerIdentityChecked = !*insecure
	}
	if runErr != nil {
		report.Outcome.Error = runErr.Error()
	} else {
		report.Outcome.Completed = true
	}
	if err := report.write(*reportPath); err != nil {
		if runErr != nil {
			return fmt.Errorf("%w (also could not write TLS report: %v)", runErr, err)
		}
		return fmt.Errorf("write TLS report: %w", err)
	}
	if runErr != nil {
		return fmt.Errorf("%w (report: %s)", runErr, *reportPath)
	}
	fmt.Printf("TLS retermination complete: version=0x%04x cipher=0x%04x inner=%s responses=%d mismatches=%d certificateVerified=%v\n",
		res.HandshakeState.Version, res.HandshakeState.CipherSuite, innerName, len(res.Responses), res.Mismatches, !*insecure)
	fmt.Printf("Report: %s\n", *reportPath)
	if *strict && res.Mismatches > 0 {
		return fmt.Errorf("strict TLS verification found %d mismatched response(s)", res.Mismatches)
	}
	return nil
}

func countTLSRole(script []tlsreplay.AppMessage, role tlsreplay.AppRole) int {
	n := 0
	for _, message := range script {
		if message.Role == role {
			n++
		}
	}
	return n
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func buildTLSAdapterScript(messages []tlsreplay.AppMessage, adapter replay.Adapter, state *replay.RuntimeState) ([]tlsreplay.AppMessage, error) {
	var clientStream, serverStream []byte
	for _, msg := range messages {
		if msg.Role == tlsreplay.FromClient {
			clientStream = append(clientStream, msg.Data...)
		} else {
			serverStream = append(serverStream, msg.Data...)
		}
	}
	clientMessages, err := adapter.Decode(replay.ClientToServer, clientStream)
	if err != nil {
		return nil, fmt.Errorf("inner %s client stream: %w", adapter.Name(), err)
	}
	serverMessages, err := replay.DecodeWithContext(adapter, replay.ServerToClient, serverStream, clientMessages)
	if err != nil {
		return nil, fmt.Errorf("inner %s server stream: %w", adapter.Name(), err)
	}
	prepared := make([][]byte, len(clientMessages))
	for i, msg := range clientMessages {
		prepared[i], err = adapter.Prepare(replay.ClientToServer, msg, state)
		if err != nil {
			return nil, fmt.Errorf("inner %s prepare message %d: %w", adapter.Name(), i, err)
		}
	}
	clientPoints, err := applicationMessageCapturePoints(messages, tlsreplay.FromClient, clientMessages)
	if err != nil {
		return nil, fmt.Errorf("inner %s client chronology: %w", adapter.Name(), err)
	}
	serverPoints, err := applicationMessageCapturePoints(messages, tlsreplay.FromServer, serverMessages)
	if err != nil {
		return nil, fmt.Errorf("inner %s server chronology: %w", adapter.Name(), err)
	}
	type item struct {
		role  tlsreplay.AppRole
		index int
		point replay.CapturePoint
	}
	items := make([]item, 0, len(clientMessages)+len(serverMessages))
	for i, point := range clientPoints {
		items = append(items, item{role: tlsreplay.FromClient, index: i, point: point})
	}
	for i, point := range serverPoints {
		items = append(items, item{role: tlsreplay.FromServer, index: i, point: point})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].point.At != items[j].point.At {
			return items[i].point.At < items[j].point.At
		}
		return items[i].point.PacketIndex < items[j].point.PacketIndex
	})
	var script []tlsreplay.AppMessage
	var pendingPeers []replay.Message
	for i := 0; i < len(items); {
		item := items[i]
		if item.role == tlsreplay.FromClient {
			script = append(script, tlsreplay.AppMessage{Role: tlsreplay.FromClient, Data: prepared[item.index], CapturedAt: item.point.At, CapturedPacket: item.point.PacketIndex, HasCaptureTime: true})
			pendingPeers = append(pendingPeers, clientMessages[item.index])
			i++
			continue
		}
		var expected []replay.Message
		var raw []byte
		lastPoint := item.point
		for i < len(items) && items[i].role == tlsreplay.FromServer {
			message := serverMessages[items[i].index]
			expected = append(expected, message)
			raw = append(raw, message.Raw...)
			lastPoint = items[i].point
			i++
		}
		peers := append([]replay.Message(nil), pendingPeers...)
		script = append(script, tlsreplay.AppMessage{Role: tlsreplay.FromServer, Data: raw, Expected: expected, Peers: peers, CapturedAt: lastPoint.At, CapturedPacket: lastPoint.PacketIndex, HasCaptureTime: true})
		consumed := replay.ConsumePeers(adapter, replay.ServerToClient, expected, len(pendingPeers))
		pendingPeers = pendingPeers[consumed:]
	}
	return script, nil
}

func applicationMessageCapturePoints(records []tlsreplay.AppMessage, role tlsreplay.AppRole, messages []replay.Message) ([]replay.CapturePoint, error) {
	type boundary struct {
		end   int
		point replay.CapturePoint
	}
	var boundaries []boundary
	total := 0
	for _, record := range records {
		if record.Role != role {
			continue
		}
		if !record.HasCaptureTime {
			return nil, fmt.Errorf("decrypted record has no capture timeline")
		}
		total += len(record.Data)
		boundaries = append(boundaries, boundary{end: total, point: replay.CapturePoint{At: record.CapturedAt, PacketIndex: record.CapturedPacket}})
	}
	points := make([]replay.CapturePoint, len(messages))
	consumed := 0
	boundaryIndex := 0
	for i, message := range messages {
		if len(message.Raw) == 0 {
			return nil, fmt.Errorf("message %d has no raw framing bytes", i)
		}
		consumed += len(message.Raw)
		for boundaryIndex < len(boundaries) && boundaries[boundaryIndex].end < consumed {
			boundaryIndex++
		}
		if boundaryIndex >= len(boundaries) {
			return nil, fmt.Errorf("message framing consumes %d bytes but decrypted records contain %d", consumed, total)
		}
		points[i] = boundaries[boundaryIndex].point
	}
	if consumed != total {
		return nil, fmt.Errorf("adapter consumed %d of %d decrypted plaintext bytes", consumed, total)
	}
	return points, nil
}

func copyStringMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func isTLSSession(s *replay.Session) bool {
	for _, e := range s.Events {
		if e.Direction == replay.ClientToServer && len(e.Payload) > 0 {
			return adapters.TLS{}.Detect(*s) > 0
		}
	}
	return false
}
