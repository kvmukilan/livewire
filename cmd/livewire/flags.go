package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/kvmukilan/livewire/internal/edit"
)

// stringSlice is a repeatable string flag.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// parseMAC parses "aa:bb:cc:dd:ee:ff" into a 6-byte array.
func parseMAC(s string) ([6]byte, error) {
	var mac [6]byte
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return mac, fmt.Errorf("invalid MAC %q", s)
	}
	for i, p := range parts {
		b, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return mac, fmt.Errorf("invalid MAC octet %q: %w", p, err)
		}
		mac[i] = byte(b)
	}
	return mac, nil
}

// parseIPMap parses "MATCH_PREFIX:REWRITE_PREFIX", e.g. "10.0.0.0/8:192.168.0.0/16".
func parseIPMap(s string) (edit.IPMap, error) {
	// Split on comma, not colon, so IPv6 prefixes parse.
	i := strings.LastIndex(s, ",")
	if i < 0 {
		return edit.IPMap{}, fmt.Errorf("ipmap must be MATCH,REWRITE (comma-separated CIDRs): %q", s)
	}
	match, err := netip.ParsePrefix(s[:i])
	if err != nil {
		return edit.IPMap{}, fmt.Errorf("ipmap match: %w", err)
	}
	rewrite, err := netip.ParsePrefix(s[i+1:])
	if err != nil {
		return edit.IPMap{}, fmt.Errorf("ipmap rewrite: %w", err)
	}
	return edit.IPMap{Match: match, Rewrite: rewrite}, nil
}

// parsePortMap parses "80:8080" into a from/to pair.
func parsePortMap(s string) (from, to uint16, err error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("portmap must be FROM:TO: %q", s)
	}
	f, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("portmap from: %w", err)
	}
	t, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("portmap to: %w", err)
	}
	return uint16(f), uint16(t), nil
}
