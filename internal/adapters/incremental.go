package adapters

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
)

func partial(eof bool) ([]replay.Message, int, error) {
	if eof {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return nil, 0, nil
}

func decodeFrame(a replay.Adapter, dir replay.Direction, data []byte, n int, eof bool) ([]replay.Message, int, error) {
	if n <= 0 || n > maxRuleFrame {
		return nil, 0, fmt.Errorf("%s: invalid frame length %d", a.Name(), n)
	}
	if n > len(data) {
		return partial(eof)
	}
	m, err := a.Decode(dir, data[:n])
	return m, n, err
}

func (a HTTP) DecodeAvailable(dir replay.Direction, data []byte, peers []replay.Message, eof bool) ([]replay.Message, int, error) {
	method := ""
	if len(peers) > 0 {
		method = stringField(peers[0], "method")
	}
	n, fields, err := httpMessageLen(data, dir, method)
	if err != nil {
		return nil, 0, err
	}
	if n == 0 {
		return partial(eof)
	}
	if closeDelimited, _ := fields["closeDelimited"].(bool); closeDelimited && !eof {
		return nil, 0, nil
	}
	m, err := a.DecodeExchange(dir, data[:n], peers)
	return m, n, err
}

func (a MQTT) DecodeAvailable(dir replay.Direction, data []byte, _ []replay.Message, eof bool) ([]replay.Message, int, error) {
	if len(data) < 2 {
		return partial(eof)
	}
	n, used, ok := mqttRemaining(data[1:])
	if !ok {
		if len(data) >= 5 {
			return nil, 0, fmt.Errorf("mqtt: malformed remaining length")
		}
		return partial(eof)
	}
	return decodeFrame(a, dir, data, 1+used+n, eof)
}

func (a DNS) DecodeAvailable(dir replay.Direction, data []byte, _ []replay.Message, eof bool) ([]replay.Message, int, error) {
	if a.Transport != replay.TransportTCP {
		return decodeFrame(a, dir, data, len(data), eof)
	}
	if len(data) < 2 {
		return partial(eof)
	}
	n := int(binary.BigEndian.Uint16(data[:2]))
	if n < 12 {
		return nil, 0, fmt.Errorf("dns/tcp: invalid message length")
	}
	return decodeFrame(a, dir, data, n+2, eof)
}

func (a Modbus) DecodeAvailable(dir replay.Direction, data []byte, _ []replay.Message, eof bool) ([]replay.Message, int, error) {
	if len(data) < 6 {
		return partial(eof)
	}
	if binary.BigEndian.Uint16(data[2:4]) != 0 || binary.BigEndian.Uint16(data[4:6]) < 2 {
		return nil, 0, fmt.Errorf("modbus: invalid MBAP header")
	}
	return decodeFrame(a, dir, data, 6+int(binary.BigEndian.Uint16(data[4:6])), eof)
}

func (a DNP3) DecodeAvailable(dir replay.Direction, data []byte, _ []replay.Message, eof bool) ([]replay.Message, int, error) {
	var decoder dnpMessageDecoder
	for off := 0; off < len(data); {
		f, n, err := dissect.ParseDNP3(data[off:])
		if err != nil {
			if errors.Is(err, dissect.ErrDNP3Short) || errors.Is(err, dissect.ErrDNP3Truncated) {
				return partial(eof)
			}
			return nil, 0, err
		}
		off += n
		_, m, err := decoder.push(f)
		if err != nil {
			return nil, 0, err
		}
		if m != nil {
			return []replay.Message{dnpApplicationMessage(*m)}, off, nil
		}
	}
	return partial(eof)
}

func (a *RuleAdapter) DecodeAvailable(dir replay.Direction, data []byte, _ []replay.Message, eof bool) ([]replay.Message, int, error) {
	f := a.pack.Framing
	n := len(data)
	switch f.Type {
	case "fixed":
		n = f.Size
	case "delimited":
		i := bytes.Index(data, a.delimiter)
		if i < 0 {
			return partial(eof)
		}
		n = i + len(a.delimiter)
	case "length-field":
		if len(data) < f.LengthOffset+f.LengthSize {
			return partial(eof)
		}
		v := readRuleUint(data[f.LengthOffset:f.LengthOffset+f.LengthSize], f.Endian)
		if v > maxRuleFrame {
			return nil, 0, fmt.Errorf("%s: declared frame too large", a.Name())
		}
		n = int(v)
		if !f.LengthIncludesHeader {
			h := f.HeaderSize
			if h == 0 {
				h = f.LengthOffset + f.LengthSize
			}
			n += h
		}
	}
	return decodeFrame(a, dir, data, n, eof)
}
