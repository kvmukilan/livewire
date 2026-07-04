package livereplay

import (
	"fmt"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/wire"
)

// tracer wraps a PacketBackend and logs a one-line decode of every frame sent and received.
type tracer struct {
	inner backend.PacketBackend
	link  wire.LinkType
	log   func(string)
}

func newTracer(inner backend.PacketBackend, log func(string)) backend.PacketBackend {
	return &tracer{inner: inner, link: inner.LinkType(), log: log}
}

func (t *tracer) emit(dir string, frame []byte) {
	p, err := wire.Parse(frame, t.link)
	if err != nil || !p.IsTCP() {
		t.log(fmt.Sprintf("  %s  %d bytes (non-TCP)", dir, len(frame)))
		return
	}
	t.log(fmt.Sprintf("  %s  %s:%d -> %s:%d  %s seq=%d ack=%d len=%d",
		dir, p.SrcIP(), p.SrcPort(), p.DstIP(), p.DstPort(),
		tcpFlags(p.Flags()), p.Seq().Uint32(), p.AckNum().Uint32(), p.PayloadLen()))
}

func tcpFlags(f uint8) string {
	s := ""
	for _, b := range []struct {
		m uint8
		c string
	}{{wire.FlagSYN, "S"}, {wire.FlagACK, "A"}, {wire.FlagPSH, "P"}, {wire.FlagFIN, "F"}, {wire.FlagRST, "R"}} {
		if f&b.m != 0 {
			s += b.c
		}
	}
	if s == "" {
		return "-"
	}
	return s
}

func (t *tracer) Send(frame []byte) error {
	t.emit("TX", frame)
	return t.inner.Send(frame)
}

func (t *tracer) Recv(buf []byte, timeout time.Duration) (int, bool, error) {
	n, ok, err := t.inner.Recv(buf, timeout)
	if ok {
		t.emit("RX", buf[:n])
	}
	return n, ok, err
}

func (t *tracer) Now() time.Time             { return t.inner.Now() }
func (t *tracer) LinkType() wire.LinkType    { return t.link }
func (t *tracer) Caps() backend.Capabilities { return t.inner.Caps() }
func (t *tracer) Close() error               { return t.inner.Close() }
