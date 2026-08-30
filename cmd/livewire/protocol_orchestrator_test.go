package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func writeProtocolStub(t *testing.T, dir, name string, port uint16, payload []byte) string {
	t.Helper()
	path := filepath.Join(dir, name+".pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapio.NewWriter(f, wire.LinkEthernet, true)
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	frames := [][]byte{
		ethTCP("192.0.2.10", "192.0.2.20", 41000, port, 100, 0, wire.FlagSYN, nil),
		ethTCP("192.0.2.20", "192.0.2.10", port, 41000, 900, 101, wire.FlagSYN|wire.FlagACK, nil),
		ethTCP("192.0.2.10", "192.0.2.20", 41000, port, 101, 901, wire.FlagACK, nil),
		ethTCP("192.0.2.10", "192.0.2.20", 41000, port, 101, 901, wire.FlagACK|wire.FlagPSH, payload),
	}
	base := time.Unix(1_700_000_000, 0)
	for i, frame := range frames {
		if err := w.Write(&pcapio.Record{Time: base.Add(time.Duration(i) * time.Millisecond), Data: frame}); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func routeForCapture(t *testing.T, path string) protocolRoute {
	t.Helper()
	records, _, err := loadRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	return detectProtocolRoute(records)
}

func TestProtocolOrchestratorRoutesCaptures(t *testing.T) {
	dir := t.TempDir()
	opaque := make([]byte, 1024)
	state := uint32(0x12345678)
	for i := range opaque {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		opaque[i] = byte(state)
	}
	cases := []struct {
		name    string
		port    uint16
		payload []byte
		want    protocolKind
	}{
		{name: "http", port: 80, payload: []byte("GET / HTTP/1.1\r\nHost: device\r\n\r\n"), want: protocolGeneric},
		{name: "plaintext-on-443", port: 443, payload: []byte("GET / HTTP/1.1\r\nHost: device\r\n\r\n"), want: protocolGeneric},
		{name: "tls", port: 443, payload: []byte{22, 3, 3, 0, 1, 0}, want: protocolTLS},
		{name: "ssh", port: 22, payload: []byte("SSH-2.0-device\r\n"), want: protocolSSH},
		{name: "ftp", port: 21, payload: []byte("USER capture\r\n"), want: protocolFTP},
		{name: "implicit-ftps", port: 990, payload: []byte{22, 3, 3, 0, 1, 0}, want: protocolFTP},
		{name: "unknown-opaque", port: 44444, payload: opaque, want: protocolOpaque},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeProtocolStub(t, dir, tc.name, tc.port, tc.payload)
			if got := routeForCapture(t, path).kind; got != tc.want {
				t.Fatalf("route = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUnifiedTLSNamesMissingKeyLogWithoutSending(t *testing.T) {
	path := writeProtocolStub(t, t.TempDir(), "tls", 443, []byte{22, 3, 3, 0, 1, 0})
	bin := buildBinary(t)
	withoutTarget, err := runBinary(t, bin, "reproduce", path, "-keylog", "keys.log")
	if err == nil || !strings.Contains(withoutTarget, "-t <host:port>") {
		t.Fatalf("TLS missing target should name the exact flag; err=%v\n%s", err, withoutTarget)
	}
	for _, command := range []string{"reproduce", "live"} {
		out, err := runBinary(t, bin, command, path, "-t", "127.0.0.1:443")
		if err == nil {
			t.Fatalf("%s unexpectedly succeeded:\n%s", command, out)
		}
		if !strings.Contains(out, "-keylog <file>") {
			t.Errorf("%s did not name the exact missing input:\n%s", command, out)
		}
	}
}

func TestUnifiedFTPSNamesMissingKeyLogWithoutSending(t *testing.T) {
	path := writeProtocolStub(t, t.TempDir(), "ftps", 990, []byte{22, 3, 3, 0, 1, 0})
	bin := buildBinary(t)
	out, err := runBinary(t, bin, "reproduce", path, "-t", "127.0.0.1:990")
	if err == nil || !strings.Contains(out, "FTPS needs the matching NSS key log") {
		t.Fatalf("FTPS missing-input error was not actionable; err=%v\n%s", err, out)
	}
}

func TestUnifiedSSHRequiresExplicitOperationsAndPinnedHost(t *testing.T) {
	path := writeProtocolStub(t, t.TempDir(), "ssh", 22, []byte("SSH-2.0-device\r\n"))
	bin := buildBinary(t)
	out, err := runBinary(t, bin, "reproduce", path, "-t", "127.0.0.1:22", "-user", "operator", "-pass", "secret", "-cmd", "show status")
	if err == nil {
		t.Fatalf("SSH without host pin unexpectedly succeeded:\n%s", out)
	}
	if !strings.Contains(out, "-host-key") {
		t.Fatalf("unified SSH did not require peer verification:\n%s", out)
	}
	if strings.Contains(out, "secret") {
		t.Fatalf("SSH password leaked into output:\n%s", out)
	}
}

func TestNonInteractiveSSHNamesEachMissingRequirement(t *testing.T) {
	path := writeProtocolStub(t, t.TempDir(), "ssh-requirements", 22, []byte("SSH-2.0-device\r\n"))
	bin := buildBinary(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "username", want: "-user <name>"},
		{name: "credentials", args: []string{"-user", "operator"}, want: "-pass <password>"},
		{name: "host key", args: []string{"-user", "operator", "-pass", "secret"}, want: "-host-key"},
		{name: "commands", args: []string{"-user", "operator", "-pass", "secret", "-host-key", "device.pub"}, want: "-cmd <command>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"reproduce", path, "-t", "127.0.0.1:22"}, tc.args...)
			out, err := runBinary(t, bin, args...)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("missing requirement should name %q; err=%v\n%s", tc.want, err, out)
			}
			if strings.Contains(out, "secret") {
				t.Fatalf("credential leaked into error output:\n%s", out)
			}
		})
	}
}

func TestDiscoveredKeyLogIsSuggestedNotConsumed(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "trace.pcap")
	candidate := filepath.Join(dir, "trace.keylog")
	if err := os.WriteFile(candidate, []byte("CLIENT_RANDOM deadbeef cafe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	os.Stdin = readEnd
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = readEnd.Close()
		_ = writeEnd.Close()
	})
	_, err = resolveKeyLog(capture, "", "TLS")
	if err == nil || !strings.Contains(err.Error(), "not read automatically") {
		t.Fatalf("discovered key log should require affirmative selection, got %v", err)
	}
}

func TestInteractiveKeyLogCandidateIsUsedOnlyAfterPrompt(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "trace.pcap")
	candidate := filepath.Join(dir, "trace.keylog")
	if err := os.WriteFile(candidate, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	prompts := 0
	got, err := resolveKeyLogWithPrompt(capture, "", "TLS", true, func(question string) string {
		prompts++
		if !strings.Contains(question, candidate) {
			t.Errorf("prompt did not show candidate %q: %s", candidate, question)
		}
		return "" // accepting the displayed default is the affirmative selection
	})
	if err != nil {
		t.Fatal(err)
	}
	if prompts != 1 || got != candidate {
		t.Fatalf("prompt count=%d selected=%q, want one prompt and %q", prompts, got, candidate)
	}
}

func TestWireModeMustBeExplicitAndNamesInterfaceRequirement(t *testing.T) {
	path := writeHandshakePcap(t, t.TempDir())
	records, _, err := loadRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	handled, err := orchestrateProtocolCapture(records, orchestratorOptions{capture: path, wire: true, times: 1})
	if !handled || err == nil || !strings.Contains(err.Error(), "-i <connection>") {
		t.Fatalf("wire guard = handled %v, err %v", handled, err)
	}
}

func TestUnknownOpaqueSessionDoesNotFallbackToTCPOrWire(t *testing.T) {
	opaque := make([]byte, 1024)
	state := uint32(0x9e3779b9)
	for i := range opaque {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		opaque[i] = byte(state)
	}
	path := writeProtocolStub(t, t.TempDir(), "opaque", 44444, opaque)
	bin := buildBinary(t)
	out, err := runBinary(t, bin, "reproduce", path, "-t", "127.0.0.1")
	if err == nil {
		t.Fatalf("unknown opaque capture unexpectedly ran:\n%s", out)
	}
	for _, want := range []string{"appears encrypted or opaque", "No ciphertext was sent", "explicit --wire"} {
		if !strings.Contains(out, want) {
			t.Errorf("opaque-session error missing %q:\n%s", want, out)
		}
	}
}

func TestDNP3SecureAuthenticationBlocksBeforeInterfaceSelection(t *testing.T) {
	frame := dissect.DNP3{
		Control: 0x44, Dest: 4, Source: 1,
		HasTransport: true, TransportFIN: true, TransportFIR: true, TransportSeq: 1,
		HasApp: true, AppControl: 0xc1, AppFIN: true, AppFIR: true, AppSeq: 1, AppFunc: 0x83,
		UserData: []byte{0xc1, 0xc1, 0x83, 120, 1, 0},
	}.Encode()
	path := writeProtocolStub(t, t.TempDir(), "dnp3-sa", 20000, frame)
	bin := buildBinary(t)
	out, err := runBinary(t, bin, "reproduce", path, "-t", "127.0.0.1")
	if err == nil {
		t.Fatalf("DNP3 Secure Authentication unexpectedly ran:\n%s", out)
	}
	for _, want := range []string{"DNP3 Secure Authentication", "no safely executable session", "no packets were sent"} {
		if !strings.Contains(out, want) {
			t.Errorf("DNP3 blocker missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Which network connection") {
		t.Errorf("blocked security should stop before interface selection:\n%s", out)
	}
}

func TestSecureAttemptReportsAreUnique(t *testing.T) {
	opts := orchestratorOptions{capture: "trace.pcap", target: "device:443", keylog: "keys.log", timeout: time.Second, times: 3, report: "result.json"}
	first := protocolRunnerArgs(protocolTLS, opts, 1)
	second := protocolRunnerArgs(protocolTLS, opts, 2)
	if strings.Join(first, "\x00") == strings.Join(second, "\x00") {
		t.Fatalf("repeated secure attempts would overwrite the same report: %v", first)
	}
	if got := attemptReportPath(opts.report, 2, opts.times); got != "result.attempt-2.json" {
		t.Fatalf("attempt report path = %q", got)
	}
}

func TestProtocolErrorsRedactPasswordsAndSecretVariables(t *testing.T) {
	opts := orchestratorOptions{password: "ssh-secret", variables: map[string]string{"ftp.password": "ftp-secret"}}
	err := redactProtocolError(errors.New("failed with ssh-secret and ftp-secret"), opts)
	if strings.Contains(err.Error(), "ssh-secret") || strings.Contains(err.Error(), "ftp-secret") {
		t.Fatalf("protocol error leaked a secret: %v", err)
	}
	if strings.Count(err.Error(), "[REDACTED]") != 2 {
		t.Fatalf("protocol error did not mark both redactions: %v", err)
	}
}

func TestBlankSSHExpectationsDoNotClaimVerification(t *testing.T) {
	if got := normalizeSSHExpects([]string{"", "  "}); got != nil {
		t.Fatalf("blank expectations should disable comparison, got %#v", got)
	}
	want := []string{"", "ready"}
	got := normalizeSSHExpects(want)
	if len(got) != len(want) || got[1] != "ready" {
		t.Fatalf("aligned nonblank expectations changed: %#v", got)
	}
}
