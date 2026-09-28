package dissect

import (
	"bytes"
	"fmt"
)

const MaxDNP3Assembly = 16 << 20

// DNP3Application is one complete application fragment, after transport
// segmentation has been removed. Raw retains the original CRC-checked frames.
type DNP3Application struct {
	Source, Dest      uint16
	Control, Function byte
	IIN               [2]byte
	Objects, Raw      []byte `json:"-"`
	LinkOnly          bool
	LinkControl       byte
}

func (a DNP3Application) Unsolicited() bool { return a.Control&0x10 != 0 }
func (a DNP3Application) Sequence() uint8   { return a.Control & 15 }

type dnpTransportBuffer struct {
	next      uint8
	data, raw []byte
	last      []byte
}

// DNP3TransportAssembler validates per-link segment order, including sequence
// wrap, and bounds assembly memory. Each instance belongs to one direction.
type DNP3TransportAssembler struct {
	pending map[[2]uint16]*dnpTransportBuffer
	bytes   int
}

func (r *DNP3TransportAssembler) Incomplete() bool { return len(r.pending) != 0 }

func (r *DNP3TransportAssembler) Push(d DNP3) (*DNP3Application, error) {
	if !d.HasTransport {
		return &DNP3Application{Source: d.Source, Dest: d.Dest, Raw: d.Encode(), LinkOnly: true, LinkControl: d.Control}, nil
	}
	if r.pending == nil {
		r.pending = map[[2]uint16]*dnpTransportBuffer{}
	}
	key := [2]uint16{d.Source, d.Dest}
	b := r.pending[key]
	if d.TransportFIR {
		if b != nil {
			return nil, fmt.Errorf("dnp3: first transport segment before previous fragment completed")
		}
		if len(r.pending) >= 128 {
			return nil, fmt.Errorf("dnp3: too many incomplete links")
		}
		b = &dnpTransportBuffer{}
		r.pending[key] = b
	} else if b == nil {
		return nil, fmt.Errorf("dnp3: transport continuation without first segment")
	} else if d.TransportSeq != b.next {
		if d.TransportSeq == (b.next+63)&63 && bytes.Equal(b.last, d.UserData) {
			return nil, nil
		}
		return nil, fmt.Errorf("dnp3: transport fragment sequence gap")
	}
	b.next = (d.TransportSeq + 1) & 63
	encoded := d.Encode()
	if r.bytes+len(encoded) > MaxDNP3Assembly {
		return nil, fmt.Errorf("dnp3: assembled fragment exceeds limit")
	}
	b.data = append(b.data, d.UserData[1:]...)
	b.raw = append(b.raw, encoded...)
	b.last = append(b.last[:0], d.UserData...)
	r.bytes += len(encoded)
	if !d.TransportFIN {
		return nil, nil
	}
	delete(r.pending, key)
	r.bytes -= len(b.raw)
	if len(b.data) < 2 {
		return nil, fmt.Errorf("dnp3: incomplete application header")
	}
	a := &DNP3Application{Source: d.Source, Dest: d.Dest, Control: b.data[0], Function: b.data[1], Raw: b.raw, LinkControl: d.Control}
	off := 2
	if a.Function == 0x81 || a.Function == 0x82 || a.Function == 0x83 {
		if len(b.data) < 4 {
			return nil, fmt.Errorf("dnp3: incomplete response indications")
		}
		a.IIN = [2]byte{b.data[2], b.data[3]}
		off = 4
	}
	a.Objects = append([]byte(nil), b.data[off:]...)
	return a, nil
}

type dnpApplicationBuffer struct {
	first DNP3Application
	next  uint8
	last  DNP3Application
}

// DNP3MessageAssembler joins application fragments into a logical response.
// Application and transport FIR/FIN flags describe distinct layers.
type DNP3MessageAssembler struct {
	pending map[[3]uint16]*dnpApplicationBuffer
	bytes   int
}

func (r *DNP3MessageAssembler) Incomplete() bool { return len(r.pending) != 0 }

func (r *DNP3MessageAssembler) Push(a DNP3Application) (*DNP3Application, error) {
	if a.LinkOnly || a.Function == 0 {
		return &a, nil
	}
	if r.pending == nil {
		r.pending = map[[3]uint16]*dnpApplicationBuffer{}
	}
	uns := uint16(0)
	if a.Unsolicited() {
		uns = 1
	}
	key := [3]uint16{a.Source, a.Dest, uns}
	b := r.pending[key]
	if b != nil && a.Sequence() == b.last.Sequence() && a.Control == b.last.Control && a.Function == b.last.Function && a.IIN == b.last.IIN && bytes.Equal(a.Objects, b.last.Objects) {
		return nil, nil
	}
	if a.Control&0x80 != 0 {
		if b != nil {
			return nil, fmt.Errorf("dnp3: first application fragment before previous response completed")
		}
		if len(r.pending) >= 128 {
			return nil, fmt.Errorf("dnp3: too many incomplete application responses")
		}
		copyA := a
		copyA.Objects = append([]byte(nil), a.Objects...)
		copyA.Raw = append([]byte(nil), a.Raw...)
		b = &dnpApplicationBuffer{first: copyA}
		if r.bytes+len(a.Raw) > MaxDNP3Assembly {
			return nil, fmt.Errorf("dnp3: assembled application responses exceed limit")
		}
		r.pending[key] = b
		r.bytes += len(a.Raw)
	} else {
		if b == nil {
			return nil, fmt.Errorf("dnp3: application continuation without first fragment")
		}
		if a.Sequence() != b.next || a.Function != b.first.Function {
			return nil, fmt.Errorf("dnp3: application fragment sequence or function differs")
		}
		if r.bytes+len(a.Raw) > MaxDNP3Assembly {
			return nil, fmt.Errorf("dnp3: assembled application response exceeds limit")
		}
		b.first.Objects = append(b.first.Objects, a.Objects...)
		b.first.Raw = append(b.first.Raw, a.Raw...)
		r.bytes += len(a.Raw)
		b.first.IIN[0] |= a.IIN[0]
		b.first.IIN[1] |= a.IIN[1]
	}
	b.next = (a.Sequence() + 1) & 15
	b.last = a
	if a.Control&0x40 == 0 {
		return nil, nil
	}
	delete(r.pending, key)
	r.bytes -= len(b.first.Raw)
	result := b.first
	result.Control = 0xc0 | (result.Control & 0x1f)
	return &result, nil
}
