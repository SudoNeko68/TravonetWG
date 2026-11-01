/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"strings"
)

// Protocol mimicry payload sizes.
const (
	stunPacketSize = 20
	quicPacketSize = 1200
)

// randRead fills b with cryptographically secure random bytes. On the
// (practically impossible) failure of crypto/rand it degrades to zeros, which
// is harmless for decoy packets.
func randRead(b []byte) {
	if _, err := cryptorand.Read(b); err != nil {
		for i := range b {
			b[i] = 0
		}
	}
}

// buildSTUNRequest builds a RFC 5389 STUN Binding Request.
func buildSTUNRequest() []byte {
	pkt := make([]byte, stunPacketSize)
	pkt[0] = 0x00
	pkt[1] = 0x01 // Binding Request
	pkt[2] = 0x00
	pkt[3] = 0x00 // Attribute length = 0
	pkt[4] = 0x21 // Magic Cookie
	pkt[5] = 0x12
	pkt[6] = 0xA4
	pkt[7] = 0x42
	randRead(pkt[8:20]) // 96-bit transaction ID
	return pkt
}

// buildQUICInitial builds a syntactically plausible RFC 9000 QUIC v1 Initial
// packet padded to 1200 bytes. The payload is random noise; DPI only needs to
// see a valid QUIC long header.
func buildQUICInitial() []byte {
	pkt := make([]byte, quicPacketSize)
	randRead(pkt)
	// Long Header (0x80) + Fixed Bit (0x40) + type Initial (0x00) + reserved
	// bits 0 + packet number length 1 (0x00).
	pkt[0] = 0xC0
	pkt[1] = 0x00 // Version 1
	pkt[2] = 0x00
	pkt[3] = 0x00
	pkt[4] = 0x01
	pkt[5] = 0x08  // DCID length
	pkt[14] = 0x08 // SCID length
	pkt[23] = 0x00 // Token length
	// Length varint: everything after this field (1200 - 26 = 1174), encoded as
	// a two-byte QUIC varint (0x4000 | 1174 = 0x4496).
	pkt[24] = 0x44
	pkt[25] = 0x96
	return pkt
}

// buildDNSQuery builds a valid DNS A query for cloudflare.com.
func buildDNSQuery() []byte {
	qname := []byte{10, 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e', 3, 'c', 'o', 'm', 0}
	pkt := make([]byte, 12+len(qname)+4)
	randRead(pkt[0:2])                           // transaction ID
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100) // standard query, RD
	binary.BigEndian.PutUint16(pkt[4:6], 1)      // QDCOUNT
	copy(pkt[12:], qname)
	off := 12 + len(qname)
	binary.BigEndian.PutUint16(pkt[off:off+2], 1) // QTYPE A
	binary.BigEndian.PutUint16(pkt[off+2:off+4], 1)
	return pkt
}

// buildMimicPacket returns a protocol mimicry decoy packet.
func buildMimicPacket(proto string) []byte {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "quic":
		return buildQUICInitial()
	case "dns":
		return buildDNSQuery()
	case "stun", "":
		return buildSTUNRequest()
	default:
		return buildSTUNRequest()
	}
}

// buildFakeHandshakePayload builds a decoy 148-byte WireGuard-like packet. When
// corruptHeader is true the message type is 0x00/0xFF instead of 0x01 so that
// per-packet stateless DPI signatures are not triggered.
func buildFakeHandshakePayload(size int, corruptHeader bool) []byte {
	if size <= 0 {
		size = WGHandshakeInitiationSize
	}
	pkt := make([]byte, size)
	randRead(pkt)
	if size >= 4 {
		if corruptHeader {
			if pkt[0]&1 == 0 {
				pkt[0] = 0x00
			} else {
				pkt[0] = 0xFF
			}
			pkt[1], pkt[2], pkt[3] = 0x00, 0x00, 0x00
		} else {
			pkt[0] = 0x01
			pkt[1], pkt[2], pkt[3] = 0x00, 0x00, 0x00
		}
	}
	return pkt
}

// buildJumboFakePayload builds the oversized decoy datagram used to trigger
// kernel-side IPv4 fragmentation without root.
func buildJumboFakePayload(size int) []byte {
	if size < 1500 {
		size = 1500
	}
	pkt := make([]byte, size)
	randRead(pkt)
	pkt[0], pkt[1], pkt[2], pkt[3] = 0x01, 0x00, 0x00, 0x00
	return pkt
}

// ipOptionsForMode returns an IPv4 options blob. The returned slice always has a
// length that is a multiple of 4 (required by the IPv4 header).
func ipOptionsForMode(mode string, size int) []byte {
	switch strings.ToLower(mode) {
	case "ts":
		// Timestamp option (type 68), length 8, pointer 5, overflow/flag 0.
		return []byte{0x44, 0x08, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00}
	case "rr":
		// Record Route (type 7), length 7, pointer 4, padded to 8 bytes with EOL.
		return []byte{0x07, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	case "nop", "":
		if size <= 0 {
			return nil
		}
		if size > 40 {
			size = 40
		}
		size = (size / 4) * 4
		opts := make([]byte, size)
		for i := range opts {
			opts[i] = 0x01 // IPOPT_NOP
		}
		return opts
	default:
		return nil
	}
}
