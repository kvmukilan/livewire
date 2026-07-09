package engine

import (
	"fmt"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/wire"
)

// VerifyMode selects how strictly a live server's replies are checked against
// the captured ones. The zero value is VerifyOff so a bare ConvConfig{} keeps
// the original "TCP bytes only" behaviour.
type VerifyMode uint8

const (
	VerifyOff     VerifyMode = iota // don't inspect reply content
	VerifyLenient                   // compare and report; tolerate value drift; never abort
	VerifyStrict                    // any content divergence aborts the flow
)

func (m VerifyMode) String() string {
	switch m {
	case VerifyLenient:
		return "lenient"
	case VerifyStrict:
		return "strict"
	default:
		return "off"
	}
}

// ParseVerifyMode maps a CLI string to a VerifyMode.
func ParseVerifyMode(s string) (VerifyMode, error) {
	switch s {
	case "", "off", "none":
		return VerifyOff, nil
	case "lenient", "on", "warn":
		return VerifyLenient, nil
	case "strict":
		return VerifyStrict, nil
	}
	return VerifyOff, fmt.Errorf("invalid verify mode %q (want off|lenient|strict)", s)
}

// Mismatch is one divergence between a live reply and the capture. Structural
// means the exchange failed to reproduce (wrong function, an exception, a bad id
// echo, or a raw byte difference); a non-structural mismatch is a value drift
// that VerifyLenient reports but tolerates. Offset is the server-stream byte
// position for context.
type Mismatch struct {
	Offset     int
	Structural bool
	Detail     string
}

// maxLiveMargin caps how far past the expected reply length the reassembly
// buffer may grow, so a bogus sequence number can't drive an unbounded alloc.
const maxLiveMargin = 1 << 16

// proto identifies the application protocol a flow carries, for protocol-aware
// reply diagnostics and message framing.
type proto uint8

const (
	protoNone proto = iota
	protoModbus
	protoDNP3
)

// respVerifier reassembles the live server's payload stream (independent of the
// engine's ACK clock) and compares it against the captured server payload.
// Modbus and DNP3 streams are compared message-by-message for meaningful
// diagnostics; anything else falls back to a byte-for-byte compare.
type respVerifier struct {
	mode  VerifyMode
	proto proto

	exp    []byte // expected server payload: captured S2C data, concatenated in order
	live   []byte // reassembled live server payload, indexed from the first data byte
	filled []bool // which live offsets have arrived
	contig int    // length of the contiguous filled prefix

	cmpOff   int // next byte offset to compare (generic path)
	msgDone  int // live messages already compared (framed path)
	diverged bool
	all      []Mismatch
}

// newRespVerifier builds a verifier for a flow's expected server payload. It
// returns nil when verification is off, so callers can cheaply skip it.
func newRespVerifier(f *Flow, mode VerifyMode) *respVerifier {
	if mode == VerifyOff {
		return nil
	}
	exp := expectedServerPayload(f)
	return &respVerifier{
		mode:  mode,
		proto: detectProto(f, exp),
		exp:   exp,
	}
}

// framed reports whether the verifier can count complete application messages in
// the server stream (used for instant adaptive turn completion).
func (v *respVerifier) framed() bool { return v != nil && v.proto != protoNone }

// liveMessagesSince counts complete application messages in the reassembled live
// stream from byte offset baseOff to the contiguous watermark.
func (v *respVerifier) liveMessagesSince(baseOff int) int {
	if v == nil || baseOff < 0 || baseOff > v.contig {
		return 0
	}
	return countMessages(v.proto, v.live[baseOff:v.contig])
}

// countMessages returns how many complete protocol messages sit at the front of
// buf (0 for an unframed protocol or a parse error).
func countMessages(p proto, buf []byte) int {
	switch p {
	case protoModbus:
		adus, _, err := dissect.ParseModbusStream(buf)
		if err != nil {
			return 0
		}
		return len(adus)
	case protoDNP3:
		frames, _, err := dissect.ParseDNP3Stream(buf)
		if err != nil {
			return 0
		}
		return len(frames)
	}
	return 0
}

// deliver folds a live server payload segment into the reassembly buffer at its
// stream offset (distance from the server's first data byte). Out-of-range or
// implausibly far segments are dropped.
func (v *respVerifier) deliver(off int, data []byte) {
	if off < 0 || len(data) == 0 {
		return
	}
	end := off + len(data)
	if end > len(v.exp)+maxLiveMargin {
		return // beyond any plausible reply; ignore rather than grow unbounded
	}
	if end > len(v.live) {
		grownBuf := make([]byte, end)
		copy(grownBuf, v.live)
		v.live = grownBuf
		grownFill := make([]bool, end)
		copy(grownFill, v.filled)
		v.filled = grownFill
	}
	copy(v.live[off:end], data)
	for i := off; i < end; i++ {
		v.filled[i] = true
	}
	for v.contig < len(v.filled) && v.filled[v.contig] {
		v.contig++
	}
}

// check compares whatever contiguous live payload has arrived since the last
// call and returns any newly found mismatches.
func (v *respVerifier) check() []Mismatch {
	switch v.proto {
	case protoModbus:
		return v.checkModbus()
	case protoDNP3:
		return v.checkDNP3()
	}
	return v.checkBytes()
}

// checkBytes compares the contiguous live prefix against the expected payload
// byte-for-byte, recording one mismatch per contiguous differing run.
func (v *respVerifier) checkBytes() []Mismatch {
	limit := v.contig
	if len(v.exp) < limit {
		limit = len(v.exp)
	}
	var out []Mismatch
	for v.cmpOff < limit {
		if v.live[v.cmpOff] == v.exp[v.cmpOff] {
			v.cmpOff++
			continue
		}
		start := v.cmpOff
		for v.cmpOff < limit && v.live[v.cmpOff] != v.exp[v.cmpOff] {
			v.cmpOff++
		}
		m := Mismatch{Offset: start, Structural: true, Detail: fmt.Sprintf(
			"server bytes %d..%d differ from capture (capture [% x], live [% x])",
			start, v.cmpOff, v.exp[start:v.cmpOff], v.live[start:v.cmpOff])}
		v.diverged = true
		v.all = append(v.all, m)
		out = append(out, m)
	}
	return out
}

// checkModbus pairs each newly complete live ADU with the captured ADU it should
// reproduce and reports the semantic differences.
func (v *respVerifier) checkModbus() []Mismatch {
	expADUs, _, err1 := dissect.ParseModbusStream(v.exp)
	liveADUs, _, err2 := dissect.ParseModbusStream(v.live[:v.contig])
	if err1 != nil || err2 != nil {
		return v.checkBytes() // not clean Modbus after all; fall back
	}
	var out []Mismatch
	for v.msgDone < len(liveADUs) {
		i := v.msgDone
		v.msgDone++
		if i >= len(expADUs) {
			m := Mismatch{Offset: -1, Structural: true, Detail: fmt.Sprintf(
				"unexpected extra response: txid 0x%04x function 0x%02x (%s)",
				liveADUs[i].TransactionID, liveADUs[i].Function, dissect.FunctionName(liveADUs[i].Function))}
			v.diverged = true
			v.all = append(v.all, m)
			out = append(out, m)
			continue
		}
		for _, d := range dissect.CompareADU(expADUs[i], liveADUs[i]) {
			m := Mismatch{Structural: d.Structural, Detail: fmt.Sprintf(
				"txid 0x%04x: %s", liveADUs[i].TransactionID, d.Detail)}
			if d.Structural {
				v.diverged = true
			}
			v.all = append(v.all, m)
			out = append(out, m)
		}
	}
	return out
}

// checkDNP3 pairs each newly complete live DNP3 frame with the captured one it
// should reproduce and reports the semantic differences.
func (v *respVerifier) checkDNP3() []Mismatch {
	expF, _, err1 := dissect.ParseDNP3Stream(v.exp)
	liveF, _, err2 := dissect.ParseDNP3Stream(v.live[:v.contig])
	if err1 != nil || err2 != nil {
		return v.checkBytes() // not clean DNP3 after all; fall back
	}
	var out []Mismatch
	for v.msgDone < len(liveF) {
		i := v.msgDone
		v.msgDone++
		if i >= len(expF) {
			m := Mismatch{Offset: -1, Structural: true, Detail: fmt.Sprintf(
				"unexpected extra DNP3 frame: app function 0x%02x (%s)",
				liveF[i].AppFunc, dissect.DNP3FunctionName(liveF[i].AppFunc))}
			v.diverged = true
			v.all = append(v.all, m)
			out = append(out, m)
			continue
		}
		for _, d := range dissect.CompareDNP3(expF[i], liveF[i]) {
			m := Mismatch{Structural: d.Structural, Detail: "dnp3 frame " + fmt.Sprint(i) + ": " + d.Detail}
			if d.Structural {
				v.diverged = true
			}
			v.all = append(v.all, m)
			out = append(out, m)
		}
	}
	return out
}

// expectedServerPayload concatenates every captured server-to-client payload in
// timeline order: the reference stream a live device should reproduce.
func expectedServerPayload(f *Flow) []byte {
	var out []byte
	for i := range f.Packets {
		cp := f.Packets[i]
		if cp.Dir != S2C || cp.PayloadLen <= 0 {
			continue
		}
		out = append(out, payloadOf(cp)...)
	}
	return out
}

// payloadOf extracts a captured packet's transport payload bytes.
func payloadOf(cp CapturedPacket) []byte {
	p, err := wire.Parse(cp.Rec.Data, cp.Rec.LinkType)
	if err != nil {
		return nil
	}
	pl := p.PayloadLen()
	pay := p.Payload()
	if pl < 0 || pl > len(pay) {
		return nil
	}
	return append([]byte(nil), pay[:pl]...)
}

// detectProto picks the application protocol for reply comparison from the
// canonical port on either endpoint, confirmed by the server stream parsing
// cleanly (Modbus/TCP on 502, DNP3 on 20000).
func detectProto(f *Flow, exp []byte) proto {
	onPort := func(p uint16) bool { return f.Server.Port == p || f.Client.Port == p }

	if onPort(502) {
		return protoModbus
	}
	if onPort(20000) {
		return protoDNP3
	}
	if len(exp) == 0 {
		return protoNone
	}
	// No canonical port: fall back to a clean full-stream parse.
	if adus, leftover, err := dissect.ParseModbusStream(exp); err == nil && leftover == 0 && len(adus) > 0 {
		return protoModbus
	}
	if frames, leftover, err := dissect.ParseDNP3Stream(exp); err == nil && leftover == 0 && len(frames) > 0 {
		return protoDNP3
	}
	return protoNone
}
