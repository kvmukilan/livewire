package wire

// Internet checksum primitives (RFC 1071) plus TCP/UDP pseudo-header sums for
// IPv4 and IPv6. Checksums are recomputed from scratch since captured ones are
// often zeroed or wrong from NIC offload.

// sumBytes adds the 16-bit ones-complement sum of b into the running 32-bit
// accumulator carry. Pass 0 first, then thread the result through to sum across
// non-contiguous regions.
func sumBytes(b []byte, carry uint32) uint32 {
	sum := carry
	n := len(b)
	i := 0
	for ; i+1 < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if i < n { // odd trailing byte is padded on the right with zero
		sum += uint32(b[i]) << 8
	}
	return sum
}

// fold reduces an unfolded 32-bit accumulator to the final 16-bit checksum.
func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ipv4HeaderChecksum computes the checksum over an IPv4 header. Zero the
// checksum field (bytes 10..11) first.
func ipv4HeaderChecksum(hdr []byte) uint16 {
	return fold(sumBytes(hdr, 0))
}

// pseudoSumV4 returns the unfolded pseudo-header sum for an IPv4 L4 segment.
func pseudoSumV4(srcIP, dstIP []byte, proto uint8, l4Len int) uint32 {
	var sum uint32
	sum = sumBytes(srcIP, sum)
	sum = sumBytes(dstIP, sum)
	sum += uint32(proto)
	sum += uint32(l4Len)
	return sum
}

// pseudoSumV6 returns the unfolded pseudo-header sum for an IPv6 L4 segment
// (RFC 8200 8.1).
func pseudoSumV6(srcIP, dstIP []byte, nextHdr uint8, l4Len int) uint32 {
	var sum uint32
	sum = sumBytes(srcIP, sum)
	sum = sumBytes(dstIP, sum)
	sum += uint32(l4Len) & 0xffff
	sum += (uint32(l4Len) >> 16) & 0xffff
	sum += uint32(nextHdr)
	return sum
}

// l4Checksum folds a pseudo-header sum with the L4 segment. Zero the segment's
// checksum field first.
func l4Checksum(pseudo uint32, segment []byte) uint16 {
	return fold(sumBytes(segment, pseudo))
}
