// Package replayintent provides the same offline replay decisions to every front end.
package replayintent

import (
	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
	"math"
	"strings"
)

type Kind string

const (
	Generic Kind = "generic"
	TLS     Kind = "tls"
	FTP     Kind = "ftp"
	SSH     Kind = "ssh"
	Opaque  Kind = "opaque"
)

type Route struct {
	Kind    Kind
	Session *replay.Session
	Trace   *replay.Trace
	Reason  string
}

func IsTLS(s *replay.Session) bool {
	c, v, e := replay.TCPPayloadStreams(s)
	return e == nil && (dissect.DetectTLS(c).IsTLS || dissect.DetectTLS(v).IsTLS)
}
func NeedsKeyLog(s *replay.Session) bool {
	if s == nil {
		return false
	}
	c, _, _ := replay.TCPPayloadStreams(s)
	return s.Server.Port == 990 || strings.Contains(strings.ToUpper(string(c)), "AUTH TLS\r\n")
}

// A positive port hint alone is not enough to override opaque classification.
func recognizedPlaintext(s *replay.Session, r *replay.Registry) bool {
	a, score := r.Best(*s)
	if a == nil || score <= 0 || a.Name() == "tls-reterminate" || a.Name() == "ssh-reterminate" {
		return false
	}
	c, v, e := replay.TCPPayloadStreams(s)
	if e != nil {
		return false
	}
	messages, e := a.Decode(replay.ClientToServer, c)
	if e != nil || len(messages) == 0 {
		return false
	}
	if len(v) > 0 {
		_, e = replay.DecodeWithContext(a, replay.ServerToClient, v, messages)
	}
	return e == nil
}
func Detect(trace *replay.Trace, registry *replay.Registry) Route {
	if registry == nil {
		registry = adapters.DefaultRegistry()
	}
	// FTP must win before generic TLS: implicit FTPS control and protected data
	// lanes are TLS sessions, but they must be coordinated as one FTP exchange.
	var ftp, tlsSessions, sshSessions, opaqueSessions []*replay.Session
	for _, session := range trace.Sessions {
		if session.Transport != replay.TransportTCP {
			continue
		}
		client, server, err := replay.TCPPayloadStreams(session)
		if err != nil {
			continue
		}
		if (adapters.FTP{}).Detect(*session) >= 100 || session.Server.Port == 990 && dissect.DetectTLS(client).IsTLS {
			ftp = append(ftp, session)
			continue
		}
		switch {
		case dissect.DetectSSH(client) || dissect.DetectSSH(server):
			sshSessions = append(sshSessions, session)
		case IsTLS(session):
			tlsSessions = append(tlsSessions, session)
		case !recognizedPlaintext(session, registry) && (looksOpaqueEncrypted(client) || looksOpaqueEncrypted(server)):
			opaqueSessions = append(opaqueSessions, session)
		}
	}
	if len(ftp) > 0 {
		if len(ftp) > 1 {
			return Route{Kind: Opaque, Trace: trace, Reason: "capture contains more than one FTP/FTPS control session; isolate the intended exchange first so no session is selected by guesswork. No packets were sent"}
		}
		if len(sshSessions) > 0 {
			return Route{Kind: Opaque, Trace: trace, Reason: "capture mixes FTP/FTPS with an SSH session; automatic execution would leave part of the capture unreproduced. Isolate the intended exchange first; no packets were sent"}
		}
		return Route{Kind: FTP, Session: ftp[0], Trace: trace}
	}
	if len(sshSessions) > 0 && len(tlsSessions) > 0 {
		return Route{Kind: Opaque, Trace: trace, Reason: "capture mixes SSH and TLS sessions; each needs different fresh-session requirements. Isolate one secure exchange first; no ciphertext was sent"}
	}
	if len(sshSessions) > 1 {
		return Route{Kind: Opaque, Trace: trace, Reason: "capture contains more than one SSH session; isolate the intended exchange first so credentials and commands cannot be applied to the wrong device. No ciphertext was sent"}
	}
	if len(tlsSessions) > 1 {
		return Route{Kind: Opaque, Trace: trace, Reason: "capture contains more than one TLS session; isolate the intended exchange first so key material is not applied by guesswork. No ciphertext was sent"}
	}
	if len(opaqueSessions) > 0 && len(sshSessions)+len(tlsSessions) > 0 {
		return Route{Kind: Opaque, Trace: trace, Reason: "capture includes a recognized secure session and another opaque session with no safe driver. Isolate the intended exchange first; no ciphertext was sent"}
	}
	if len(sshSessions) > 0 {
		return Route{Kind: SSH, Session: sshSessions[0], Trace: trace}
	}
	if len(tlsSessions) > 0 {
		return Route{Kind: TLS, Session: tlsSessions[0], Trace: trace}
	}
	if len(opaqueSessions) > 0 {
		return Route{Kind: Opaque, Session: opaqueSessions[0], Trace: trace, Reason: "a TCP session appears encrypted or opaque, but Livewire cannot identify a safe fresh-session driver. No ciphertext was sent; inspect with 'livewire check <capture> -details' or use explicit --wire only when raw injection is truly intended"}
	}
	return Route{Kind: Generic, Trace: trace}
}

// looksOpaqueEncrypted is intentionally conservative. It catches sustained,
// high-entropy binary payloads that would otherwise be mislabeled as ordinary
// TCP, while leaving short binary industrial messages to the normal planner.
func looksOpaqueEncrypted(payload []byte) bool {
	if len(payload) < 256 {
		return false
	}
	counts := [256]int{}
	printable := 0
	for _, b := range payload {
		counts[b]++
		if b == '\r' || b == '\n' || b == '\t' || b >= 0x20 && b <= 0x7e {
			printable++
		}
	}
	if float64(printable)/float64(len(payload)) > 0.55 {
		return false
	}
	entropy := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(len(payload))
		entropy -= p * math.Log2(p)
	}
	return entropy >= 7.0
}
