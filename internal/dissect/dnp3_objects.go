package dissect

import (
	"encoding/binary"
	"fmt"
)

// DNP3ObjectBytes returns a canonical, bounded stream of indexed objects.
// Unsupported encodings are errors, so an unknown object width cannot hide a
// following Secure Authentication object from preflight inspection.
func DNP3ObjectBytes(a DNP3Application) ([]byte, bool, error) {
	if a.Function == 0x20 || a.Function == 0x21 || a.Function == 0x83 {
		return nil, true, nil
	}
	data := a.Objects
	var out []byte
	headerOnly := a.Function == 1 || a.Function == 0x14 || a.Function == 0x15 || a.Function == 0x16
	for len(data) > 0 {
		if len(data) < 3 {
			return nil, false, fmt.Errorf("dnp3: incomplete object header")
		}
		group, variation, qualifier := data[0], data[1], data[2]
		data = data[3:]
		if group == 120 {
			return nil, true, nil
		}
		var count, start uint32
		prefix := 0
		read := func(n int) (uint32, bool) {
			if len(data) < n {
				return 0, false
			}
			var v uint32
			switch n {
			case 1:
				v = uint32(data[0])
			case 2:
				v = uint32(binary.LittleEndian.Uint16(data))
			case 4:
				v = binary.LittleEndian.Uint32(data)
			}
			data = data[n:]
			return v, true
		}
		switch qualifier {
		case 6:
			if !headerOnly {
				return nil, false, fmt.Errorf("dnp3: all-objects qualifier in value response")
			}
			out = append(out, group, variation, qualifier)
			continue
		case 0, 1, 2:
			width := 1 << qualifier
			lo, ok := read(width)
			if !ok {
				return nil, false, fmt.Errorf("dnp3: truncated object range")
			}
			hi, ok := read(width)
			if !ok || hi < lo || hi-lo >= 1<<20 {
				return nil, false, fmt.Errorf("dnp3: invalid object range")
			}
			start, count = lo, hi-lo+1
		case 7, 8, 9, 0x17, 0x28, 0x39:
			width := 1 << ((qualifier & 15) - 7)
			v, ok := read(width)
			if !ok || v > 1<<20 {
				return nil, false, fmt.Errorf("dnp3: invalid object count")
			}
			count = v
			if qualifier>>4 != 0 {
				prefix = width
			}
		default:
			return nil, false, fmt.Errorf("dnp3: unsupported object qualifier 0x%02x", qualifier)
		}
		if headerOnly {
			out = append(out, group, variation, qualifier)
			out = binary.LittleEndian.AppendUint32(out, start)
			out = binary.LittleEndian.AppendUint32(out, count)
			if uint64(count)*uint64(prefix) > uint64(len(data)) {
				return nil, false, fmt.Errorf("dnp3: truncated requested indexes")
			}
			n := int(count) * prefix
			out = append(out, data[:n]...)
			data = data[n:]
			continue
		}
		width, bits := dnpObjectWidth(group, variation)
		if width == 0 && bits == 0 {
			return nil, false, fmt.Errorf("dnp3: unsupported object group %d variation %d; security cannot be established", group, variation)
		}
		if bits > 0 {
			if prefix != 0 {
				return nil, false, fmt.Errorf("dnp3: indexed packed objects unsupported")
			}
			n := (uint64(count)*uint64(bits) + 7) / 8
			if n > uint64(len(data)) {
				return nil, false, fmt.Errorf("dnp3: truncated packed objects")
			}
			for i := uint32(0); i < count; i++ {
				v := (data[i*uint32(bits)/8] >> (i * uint32(bits) % 8)) & byte((1<<bits)-1)
				out = append(out, group, variation)
				out = binary.LittleEndian.AppendUint32(out, start+i)
				out = append(out, v)
			}
			data = data[int(n):]
		} else {
			if uint64(count)*uint64(prefix+width) > uint64(len(data)) {
				return nil, false, fmt.Errorf("dnp3: truncated object values")
			}
			for i := uint32(0); i < count; i++ {
				index := start + i
				if prefix > 0 {
					index, _ = read(prefix)
				}
				out = append(out, group, variation)
				out = binary.LittleEndian.AppendUint32(out, index)
				out = append(out, data[:width]...)
				data = data[width:]
			}
		}
		if len(out) > MaxDNP3Assembly {
			return nil, false, fmt.Errorf("dnp3: canonical objects exceed limit")
		}
	}
	return out, false, nil
}

func dnpObjectWidth(group, variation byte) (int, int) {
	if (group == 1 || group == 10 || group == 80) && variation == 1 {
		return 0, 1
	}
	if group == 3 && variation == 1 {
		return 0, 2
	}
	if (group == 1 || group == 3 || group == 10) && variation == 2 {
		return 1, 0
	}
	if group == 2 || group == 4 {
		switch variation {
		case 1:
			return 1, 0
		case 2:
			return 7, 0
		case 3:
			return 3, 0
		}
	}
	if group == 11 || group == 13 {
		switch variation {
		case 1:
			return 1, 0
		case 2:
			return 7, 0
		}
	}
	if group == 12 && variation == 1 {
		return 11, 0
	}
	if group == 20 {
		switch variation {
		case 1:
			return 5, 0
		case 2:
			return 3, 0
		case 5:
			return 4, 0
		case 6:
			return 2, 0
		}
	}
	if group == 21 || group == 22 || group == 23 {
		switch variation {
		case 1:
			return 5, 0
		case 2:
			return 3, 0
		case 5:
			return 11, 0
		case 6:
			return 9, 0
		}
		if group == 21 {
			switch variation {
			case 9:
				return 4, 0
			case 10:
				return 2, 0
			}
		}
	}
	if group == 30 {
		switch variation {
		case 1, 5:
			return 5, 0
		case 2:
			return 3, 0
		case 3:
			return 4, 0
		case 4:
			return 2, 0
		case 6:
			return 9, 0
		}
	}
	if group == 32 || group == 33 || group == 42 || group == 43 {
		switch variation {
		case 1, 5:
			return 5, 0
		case 2:
			return 3, 0
		case 3, 7:
			return 11, 0
		case 4, 6:
			return 9, 0
		case 8:
			return 15, 0
		}
	}
	if group == 40 || group == 41 {
		switch variation {
		case 1, 3:
			return 5, 0
		case 2:
			return 3, 0
		case 4:
			return 9, 0
		}
	}
	if group == 50 {
		switch variation {
		case 1, 3:
			return 6, 0
		case 2:
			return 10, 0
		case 4:
			return 11, 0
		}
	}
	if group == 51 && (variation == 1 || variation == 2) {
		return 6, 0
	}
	if group == 52 && (variation == 1 || variation == 2) {
		return 2, 0
	}
	if (group == 110 || group == 111) && variation > 0 {
		return int(variation), 0
	}
	return 0, 0
}

// DNP3ObjectLayout separates object identity from point values in the canonical
// response representation. Reframing must not hide a changed group, variation,
// index, count, or ordering even when value drift is allowed by comparison policy.
func DNP3ObjectLayout(canonical []byte) ([]byte, error) {
	var layout []byte
	for len(canonical) > 0 {
		if len(canonical) < 6 {
			return nil, fmt.Errorf("dnp3: invalid canonical object")
		}
		width, bits := dnpObjectWidth(canonical[0], canonical[1])
		if bits > 0 {
			width = 1
		}
		if width <= 0 || len(canonical) < 6+width {
			return nil, fmt.Errorf("dnp3: invalid canonical object width")
		}
		layout = append(layout, canonical[:6]...)
		canonical = canonical[6+width:]
	}
	return layout, nil
}

// InspectDNP3Stream inspects complete transport-reassembled application
// fragments. A recognized but incomplete/unsupported stream is an error and
// must be blocked before transmission; false never proves an unknown layout safe.
func InspectDNP3Stream(data []byte) (recognized, secure bool, err error) {
	if len(data) < 2 || data[0] != 5 || data[1] != 0x64 {
		return false, false, nil
	}
	frames, rest, err := ParseDNP3Stream(data)
	if err != nil {
		return true, false, err
	}
	if rest != 0 {
		return true, false, fmt.Errorf("dnp3: incomplete link frame during security inspection")
	}
	var assembler DNP3TransportAssembler
	var applications DNP3MessageAssembler
	for _, f := range frames {
		if f.UsesSecureAuth() {
			return true, true, nil
		}
		a, e := assembler.Push(f)
		if e != nil {
			return true, false, e
		}
		if a == nil || a.LinkOnly {
			continue
		}
		_, sa, e := DNP3ObjectBytes(*a)
		if sa {
			return true, true, nil
		}
		if e != nil {
			return true, false, e
		}
		if _, e = applications.Push(*a); e != nil {
			return true, false, e
		}
	}
	if assembler.Incomplete() {
		return true, false, fmt.Errorf("dnp3: incomplete transport fragment during security inspection")
	}
	if applications.Incomplete() {
		return true, false, fmt.Errorf("dnp3: incomplete application response during security inspection")
	}
	return true, false, nil
}
