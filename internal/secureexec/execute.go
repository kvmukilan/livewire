// Package secureexec prepares secure replay offline and executes it through the
// same drivers for the command line and dashboard. No credentials are serialized.
package secureexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/ftpreplay"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/replayintent"
	"github.com/kvmukilan/livewire/internal/sshreplay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	Inspection                      *replayintent.Inspection
	Registry                        *replay.Registry
	Target, ServerName              string
	KeyLog, CA, PrivateKey, HostKey []byte
	User, Password                  string
	Commands, Expects               []string
	Variables                       map[string]string
	Insecure                        bool
	Verify                          replay.VerifyMode
	Timeout                         time.Duration
	Progress                        func(string)
}

type Prepared struct {
	run func(context.Context) (Outcome, error)
}

func (p *Prepared) Run(ctx context.Context) (Outcome, error) { return p.run(ctx) }

func Prepare(c Config) (*Prepared, error) {
	if c.Inspection == nil || !c.Inspection.Readiness.Supported {
		return nil, fmt.Errorf("replay inspection is blocked or missing")
	}
	host, portText, e := net.SplitHostPort(c.Target)
	if e != nil || host == "" {
		return nil, fmt.Errorf("target must be host:port")
	}
	port, e := strconv.Atoi(portText)
	if e != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("target port must be between 1 and 65535")
	}
	if c.Timeout <= 0 || c.Timeout > 10*time.Minute {
		return nil, fmt.Errorf("timeout must be greater than zero and at most 10m")
	}
	if c.Verify == "" {
		c.Verify = replay.VerifyLenient
	}
	if c.Verify != replay.VerifyOff && c.Verify != replay.VerifyStrict && c.Verify != replay.VerifyLenient {
		return nil, fmt.Errorf("verify must be off, lenient, or strict")
	}
	route := c.Inspection.Route
	s := route.Session
	if s == nil {
		return nil, fmt.Errorf("no secure session selected")
	}
	if route.Kind == replayintent.SSH {
		return prepareSSH(c)
	}
	var keys *tlsreplay.KeyLog
	if route.Kind == replayintent.TLS || replayintent.NeedsKeyLog(s) {
		if len(c.KeyLog) == 0 {
			return nil, fmt.Errorf("matching NSS key log is required (-keylog)")
		}
		keys, e = tlsreplay.ParseKeyLog(bytes.NewReader(c.KeyLog))
		if e != nil {
			return nil, e
		}
	}
	var tc *tls.Config
	if route.Kind == replayintent.TLS || replayintent.NeedsKeyLog(s) {
		name := c.ServerName
		if name == "" {
			name = host
		}
		tc = &tls.Config{ServerName: name, InsecureSkipVerify: c.Insecure} // #nosec G402 -- explicit operator lab override
		if len(c.CA) > 0 {
			roots, err := x509.SystemCertPool()
			if err != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM(c.CA) {
				return nil, fmt.Errorf("CA contains no parseable certificates")
			}
			tc.RootCAs = roots
		}
	}
	if route.Kind == replayintent.FTP {
		script, e := ftpreplay.BuildScript(s, keys)
		if e != nil {
			return nil, e
		}
		data, e := ftpreplay.MatchDataSessions(c.Inspection.Trace, s, script)
		if e != nil {
			return nil, e
		}
		return &Prepared{run: func(ctx context.Context) (Outcome, error) {
			r, err := ftpreplay.RunContext(ctx, ftpreplay.Config{Control: s, Data: data, Address: c.Target, Script: script, Variables: c.Variables, TLSConfig: tc, Timeout: c.Timeout, Verify: c.Verify, Progress: c.Progress})
			o := Outcome{Completed: r.Completed, Verified: r.Verified, Adapter: "ftp", Requests: r.Commands, Responses: r.Replies, Differences: r.Differences, Transfers: r.Transfers, PeerIdentityChecked: r.TLS && !c.Insecure}
			o.Matched = o.Completed && o.Verified && len(r.Differences) == 0
			for _, t := range r.Transfers {
				o.Matched = o.Matched && t.Matched
			}
			return o, err
		}}, nil
	}
	if route.Kind != replayintent.TLS {
		return nil, fmt.Errorf("unsupported fresh-session driver %s", route.Kind)
	}
	client, server, e := replay.TCPPayloadTimelines(s)
	if e != nil {
		return nil, e
	}
	messages, e := tlsreplay.NewDecryptor(keys).DecryptFlowTimed(client.Data, server.Data, client.CompletionPoint, server.CompletionPoint)
	if e != nil {
		return nil, e
	}
	innerSession := replay.Session{Transport: replay.TransportTCP, Client: s.Client, Server: s.Server}
	for i, m := range messages {
		d := replay.ClientToServer
		if m.Role == tlsreplay.FromServer {
			d = replay.ServerToClient
		}
		innerSession.Events = append(innerSession.Events, replay.Event{PacketIndex: i, Direction: d, Payload: m.Data})
	}
	var adapter replay.Adapter
	if c.Registry != nil {
		a, score := c.Registry.Best(innerSession)
		if a != nil && score > 0 && a.Name() != "tls-reterminate" && a.Name() != "ssh-reterminate" {
			adapter = a
		}
	}
	// Each attempt needs new learned state and newly prepared dynamic values.
	makeScript := func() ([]tlsreplay.AppMessage, *replay.RuntimeState, error) {
		vars := map[string]string{}
		for k, v := range c.Variables {
			vars[k] = v
		}
		state := &replay.RuntimeState{Variables: vars, Learned: map[string][]byte{}}
		if adapter == nil {
			return tlsreplay.ConversationOrder(messages), state, nil
		}
		script, e := BuildTLSAdapterScript(messages, adapter, state)
		return script, state, e
	}
	if _, _, e = makeScript(); e != nil {
		return nil, e
	}
	return &Prepared{run: func(ctx context.Context) (Outcome, error) {
		script, state, err := makeScript()
		if err != nil {
			return Outcome{}, err
		}
		verified := c.Verify != replay.VerifyOff && (c.Verify == replay.VerifyStrict || adapter != nil)
		r, err := tlsreplay.ReTerminateContext(ctx, tlsreplay.ReTermConfig{Address: c.Target, TLSConfig: tc, Script: script, Timeout: c.Timeout, Verify: c.Verify == replay.VerifyStrict, Adapter: adapter, State: state, VerifyMode: c.Verify})
		o := Outcome{Completed: err == nil, Adapter: "opaque plaintext"}
		if adapter != nil {
			o.Adapter = adapter.Name()
		}
		for _, m := range script {
			if m.Role == tlsreplay.FromClient {
				o.Requests++
			}
		}
		if r != nil {
			o.Verified = verified && len(r.Responses) > 0
			o.Responses = len(r.Responses)
			o.Mismatches = r.Mismatches
			o.Differences = r.Differences
			o.Matched = o.Completed && o.Verified && r.Mismatches == 0
			o.PeerIdentityChecked = r.HandshakeState.HandshakeComplete && !c.Insecure
			o.ProtocolVersion = tls.VersionName(r.HandshakeState.Version)
			o.CipherSuite = tls.CipherSuiteName(r.HandshakeState.CipherSuite)
			o.ALPN = r.HandshakeState.NegotiatedProtocol
		}
		return o, err
	}}, nil
}

func prepareSSH(c Config) (*Prepared, error) {
	if c.User == "" {
		return nil, fmt.Errorf("SSH username is required (-user)")
	}
	if (c.Password == "") == (len(c.PrivateKey) == 0) {
		return nil, fmt.Errorf("provide exactly one SSH password or private key")
	}
	if len(c.HostKey) == 0 {
		return nil, fmt.Errorf("pinned SSH host key is required (-host-key)")
	}
	key, _, _, rest, e := ssh.ParseAuthorizedKey(c.HostKey)
	if e != nil {
		return nil, e
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("host key must contain exactly one OpenSSH public key")
	}
	if len(c.PrivateKey) > 0 {
		if _, e := ssh.ParsePrivateKey(c.PrivateKey); e != nil {
			return nil, fmt.Errorf("parse private key: %w", e)
		}
	}
	if len(c.Commands) == 0 {
		return nil, fmt.Errorf("at least one explicit SSH command is required (-cmd)")
	}
	if len(c.Expects) != 0 && len(c.Expects) != len(c.Commands) {
		return nil, fmt.Errorf("provide one expectation per command")
	}
	commands := make([]sshreplay.Command, len(c.Commands))
	verify := false
	allExpected := len(c.Expects) == len(c.Commands)
	for i, v := range c.Commands {
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("SSH commands cannot be blank")
		}
		commands[i].Run = v
		if len(c.Expects) > 0 {
			commands[i].Expect = c.Expects[i]
			verify = verify || strings.TrimSpace(c.Expects[i]) != ""
			allExpected = allExpected && strings.TrimSpace(c.Expects[i]) != ""
		}
	}
	verify = verify && c.Verify != replay.VerifyOff
	return &Prepared{run: func(ctx context.Context) (Outcome, error) {
		r, err := sshreplay.ReTerminateContext(ctx, sshreplay.Config{Address: c.Target, Auth: sshreplay.Auth{User: c.User, Password: c.Password, PrivateKey: c.PrivateKey}, Commands: commands, Timeout: c.Timeout, Verify: verify, HostKey: key})
		o := Outcome{Completed: err == nil, Verified: verify && allExpected, Adapter: "ssh-reterminate", ProtocolVersion: "SSHv2", Requests: len(commands)}
		if r != nil {
			o.Responses = len(r.Outputs)
			o.Mismatches = r.Mismatches
			o.Matched = o.Completed && o.Verified && r.Mismatches == 0
			o.PeerIdentityChecked = r.HostKey != nil && err == nil
			for i, b := range r.Outputs {
				sum := sha256.Sum256(b)
				matched := verify && strings.TrimSpace(commands[i].Expect) != "" && bytes.Contains(b, []byte(commands[i].Expect))
				o.Commands = append(o.Commands, CommandEvidence{Index: i, OutputBytes: len(b), OutputSHA256: fmt.Sprintf("sha256:%x", sum), Matched: matched})
			}
		}
		return o, err
	}}, nil
}
