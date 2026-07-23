package pcapio

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/kvmukilan/livewire/internal/wire"
)

type NgInterface struct {
	Name     string
	LinkType wire.LinkType
	SnapLen  uint32
}

// NgWriter writes nanosecond-resolution pcapng with multiple interfaces.
type NgWriter struct {
	w      *bufio.Writer
	ifaces []NgInterface
}

func NewNgWriter(w io.Writer, ifaces []NgInterface) (*NgWriter, error) {
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("pcapio: pcapng needs at least one interface")
	}
	nw := &NgWriter{w: bufio.NewWriterSize(w, 1<<16), ifaces: append([]NgInterface(nil), ifaces...)}
	if err := nw.writeSHB(); err != nil {
		return nil, err
	}
	for i := range nw.ifaces {
		if nw.ifaces[i].SnapLen == 0 {
			nw.ifaces[i].SnapLen = 65535
		}
		if err := nw.writeIDB(nw.ifaces[i]); err != nil {
			return nil, err
		}
	}
	return nw, nil
}

func (w *NgWriter) writeSHB() error {
	body := make([]byte, 16)
	binary.LittleEndian.PutUint32(body[0:4], ngByteMagic)
	binary.LittleEndian.PutUint16(body[4:6], 1)
	binary.LittleEndian.PutUint16(body[6:8], 0)
	for i := 8; i < 16; i++ {
		body[i] = 0xff // section length unknown (-1)
	}
	return w.writeBlock(ngBlockSHB, body)
}

func (w *NgWriter) writeIDB(iface NgInterface) error {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], uint16(iface.LinkType))
	binary.LittleEndian.PutUint32(body[4:8], iface.SnapLen)
	body = appendNgOption(body, ngOptTSResol, []byte{9})
	if iface.Name != "" {
		body = appendNgOption(body, 2, []byte(iface.Name)) // if_name
	}
	body = appendNgOption(body, 0, nil)
	return w.writeBlock(ngBlockIDB, body)
}

func appendNgOption(dst []byte, code uint16, value []byte) []byte {
	var head [4]byte
	binary.LittleEndian.PutUint16(head[0:2], code)
	binary.LittleEndian.PutUint16(head[2:4], uint16(len(value)))
	dst = append(dst, head[:]...)
	dst = append(dst, value...)
	for len(dst)%4 != 0 {
		dst = append(dst, 0)
	}
	return dst
}

func (w *NgWriter) Write(rec *Record) error {
	if rec == nil || int(rec.InterfaceID) >= len(w.ifaces) {
		return fmt.Errorf("pcapio: invalid pcapng interface %d", rec.InterfaceID)
	}
	capLen := len(rec.Data)
	if rec.CapLen > 0 && rec.CapLen < capLen {
		capLen = rec.CapLen
	}
	origLen := rec.OrigLen
	if origLen == 0 {
		origLen = len(rec.Data)
	}
	ticks := uint64(rec.Time.Unix())*1_000_000_000 + uint64(rec.Time.Nanosecond())
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[0:4], rec.InterfaceID)
	binary.LittleEndian.PutUint32(body[4:8], uint32(ticks>>32))
	binary.LittleEndian.PutUint32(body[8:12], uint32(ticks))
	binary.LittleEndian.PutUint32(body[12:16], uint32(capLen))
	binary.LittleEndian.PutUint32(body[16:20], uint32(origLen))
	body = append(body, rec.Data[:capLen]...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	return w.writeBlock(ngBlockEPB, body)
}

func (w *NgWriter) writeBlock(kind uint32, body []byte) error {
	total := uint32(12 + len(body))
	var head [8]byte
	binary.LittleEndian.PutUint32(head[0:4], kind)
	binary.LittleEndian.PutUint32(head[4:8], total)
	if _, err := w.w.Write(head[:]); err != nil {
		return err
	}
	if _, err := w.w.Write(body); err != nil {
		return err
	}
	var tail [4]byte
	binary.LittleEndian.PutUint32(tail[:], total)
	_, err := w.w.Write(tail[:])
	return err
}

func (w *NgWriter) Flush() error { return w.w.Flush() }
