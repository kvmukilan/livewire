// Package classify sorts packets onto the client (primary) or server (secondary)
// side and reads/writes the 2-bit-per-packet cache dual-NIC replay consumes.
// Mirrors tcpprep's auto/port/CIDR modes.
package classify

import (
	"encoding/binary"
	"errors"
	"io"
)

// Send is the per-packet routing decision stored in the cache (2 bits each).
type Send uint8

const (
	// SendNone drops the packet (no interface).
	SendNone Send = 0
	// SendPrimary routes client->server packets out the primary interface.
	SendPrimary Send = 1
	// SendSecondary routes server->client packets out the secondary interface.
	SendSecondary Send = 2
)

const (
	cacheMagic          = "tcpprep\x00" // 8 bytes
	cacheVersion        = "04\x00\x00"  // 4 bytes
	cachePacketsPerByte = 4
)

// ErrBadCache indicates an unrecognized or corrupt cache file.
var ErrBadCache = errors.New("classify: bad cache file")

// Cache is an ordered list of per-packet Send decisions.
type Cache struct {
	entries []Send
}

// NewCache returns an empty cache.
func NewCache() *Cache { return &Cache{} }

// Append records the decision for the next packet in file order.
func (c *Cache) Append(s Send) { c.entries = append(c.entries, s) }

// Len returns the number of packets recorded.
func (c *Cache) Len() int { return len(c.entries) }

// At returns the decision for packet i (0-based).
func (c *Cache) At(i int) Send {
	if i < 0 || i >= len(c.entries) {
		return SendNone
	}
	return c.entries[i]
}

// Counts returns how many packets were assigned to each side.
func (c *Cache) Counts() (primary, secondary, none int) {
	for _, s := range c.entries {
		switch s {
		case SendPrimary:
			primary++
		case SendSecondary:
			secondary++
		default:
			none++
		}
	}
	return
}

// WriteCache serializes the cache: tcpprep-style header, then 4 packets per byte
// (2 bits each, MSB-first).
func WriteCache(w io.Writer, c *Cache, comment string) error {
	hdr := make([]byte, 8+4+4+2+2)
	copy(hdr[0:8], cacheMagic)
	copy(hdr[8:12], cacheVersion)
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(c.entries)))
	binary.BigEndian.PutUint16(hdr[16:18], cachePacketsPerByte)
	binary.BigEndian.PutUint16(hdr[18:20], uint16(len(comment)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(comment) > 0 {
		if _, err := io.WriteString(w, comment); err != nil {
			return err
		}
	}
	data := make([]byte, (len(c.entries)+cachePacketsPerByte-1)/cachePacketsPerByte)
	for i, s := range c.entries {
		shift := uint((cachePacketsPerByte - 1 - (i % cachePacketsPerByte)) * 2)
		data[i/cachePacketsPerByte] |= byte(s&0x3) << shift
	}
	_, err := w.Write(data)
	return err
}

// ReadCache deserializes a cache written by WriteCache.
func ReadCache(r io.Reader) (*Cache, string, error) {
	hdr := make([]byte, 20)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, "", err
	}
	if string(hdr[0:8]) != cacheMagic {
		return nil, "", ErrBadCache
	}
	num := int(binary.BigEndian.Uint32(hdr[12:16]))
	commentLen := int(binary.BigEndian.Uint16(hdr[18:20]))
	comment := make([]byte, commentLen)
	if _, err := io.ReadFull(r, comment); err != nil {
		return nil, "", ErrBadCache
	}
	data := make([]byte, (num+cachePacketsPerByte-1)/cachePacketsPerByte)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, "", ErrBadCache
	}
	c := &Cache{entries: make([]Send, num)}
	for i := 0; i < num; i++ {
		shift := uint((cachePacketsPerByte - 1 - (i % cachePacketsPerByte)) * 2)
		c.entries[i] = Send((data[i/cachePacketsPerByte] >> shift) & 0x3)
	}
	return c, string(comment), nil
}
