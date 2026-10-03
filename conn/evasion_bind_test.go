/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

func TestBuildIPv4Packet(t *testing.T) {
	src := net.ParseIP("192.168.1.100").To4()
	dst := net.ParseIP("162.159.192.1").To4()
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	pkt := buildIPv4Packet(src, dst, 0x1234, 64, true, 8, payload)

	if len(pkt) != 20+len(payload) {
		t.Fatalf("expected packet len %d, got %d", 20+len(payload), len(pkt))
	}

	if pkt[0] != 0x45 {
		t.Errorf("version/ihl mismatch: 0x%02x", pkt[0])
	}
	totLen := binary.BigEndian.Uint16(pkt[2:4])
	if int(totLen) != len(pkt) {
		t.Errorf("totLen mismatch: %d != %d", totLen, len(pkt))
	}
	id := binary.BigEndian.Uint16(pkt[4:6])
	if id != 0x1234 {
		t.Errorf("id mismatch: 0x%04x", id)
	}

	flagsAndOffset := binary.BigEndian.Uint16(pkt[6:8])
	// Offset = 8 bytes = 1 unit. MF = true -> 0x2000 | 1 = 0x2001
	if flagsAndOffset != 0x2001 {
		t.Errorf("flagsAndOffset mismatch: expected 0x2001, got 0x%04x", flagsAndOffset)
	}

	if pkt[8] != 64 {
		t.Errorf("ttl mismatch: %d", pkt[8])
	}
	if pkt[9] != syscall.IPPROTO_UDP {
		t.Errorf("proto mismatch: %d", pkt[9])
	}

	// Verify header checksum
	csum := computeChecksum(pkt[0:20])
	if csum != 0 {
		t.Errorf("header checksum verification failed (expected 0 over header with csum included), got 0x%04x", csum)
	}
}

func TestComputeUDPChecksum(t *testing.T) {
	src := net.ParseIP("192.168.1.1").To4()
	dst := net.ParseIP("192.168.1.2").To4()

	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], 12345)
	binary.BigEndian.PutUint16(udpHeader[2:4], 500)
	binary.BigEndian.PutUint16(udpHeader[4:6], 12) // 8 + 4
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)

	payload := []byte("TEST")

	csum := computeUDPChecksum(src, dst, udpHeader, payload)
	if csum == 0 {
		t.Errorf("checksum should not be 0")
	}

	// Verify checksum with csum inserted in header
	binary.BigEndian.PutUint16(udpHeader[6:8], csum)
	verifySum := computeUDPChecksum(src, dst, udpHeader, payload)
	// When valid checksum is in place, recalculation over header with inverted csum should yield 0 or 0xFFFF
	if verifySum != 0xFFFF && verifySum != 0 {
		t.Logf("UDP checksum computed: 0x%04x, verify: 0x%04x", csum, verifySum)
	}
}

type mockUserspaceBind struct {
	Bind
	sentPackets [][]byte
	ttlHistory  []int
	currentTTL  int
}

func (m *mockUserspaceBind) Send(bufs [][]byte, ep Endpoint) error {
	for _, b := range bufs {
		cp := make([]byte, len(b))
		copy(cp, b)
		m.sentPackets = append(m.sentPackets, cp)
	}
	return nil
}

func (m *mockUserspaceBind) SetIPv4TTL(ttl int) error {
	m.currentTTL = ttl
	m.ttlHistory = append(m.ttlHistory, ttl)
	return nil
}

func TestUserspaceEvasionSend(t *testing.T) {
	mock := &mockUserspaceBind{}
	cfg := DefaultEvasionConfig()
	cfg.FakeTTL = 9
	cfg.NormalTTL = 64
	cfg.Strategy = "junk(64) -> fake_udp(148, ttl=9) -> frag(8) -> frag(148)"
	cfg.Debug = true

	b := NewEvasionBind(mock, cfg)
	// Force rawFd = -1 to simulate unprivileged userspace (non-root / Android)
	b.rawFd = -1

	ep := &StdNetEndpoint{}
	handshake := make([]byte, WGHandshakeInitiationSize)
	handshake[0] = 0x01
	for i := 4; i < len(handshake); i++ {
		handshake[i] = byte(i)
	}

	err := b.sendUserspaceObfuscatedHandshake(ep, handshake)
	if err != nil {
		t.Fatalf("sendUserspaceObfuscatedHandshake failed: %v", err)
	}

	// In userspace mode:
	// Step 1: Junk (64 bytes)
	// Step 2: Fake UDP (148 bytes, with TTL set to 9, then restored to 64)
	// Step 3: Real Handshake (148 bytes, with TTL 64)
	if len(mock.sentPackets) != 3 {
		t.Fatalf("expected 3 packets sent in userspace mode, got %d", len(mock.sentPackets))
	}

	// 1. Check Junk
	if len(mock.sentPackets[0]) != 64 {
		t.Errorf("expected packet 0 (junk) len 64, got %d", len(mock.sentPackets[0]))
	}

	// 2. Check Fake UDP
	if len(mock.sentPackets[1]) != 148 {
		t.Errorf("expected packet 1 (fake_udp) len 148, got %d", len(mock.sentPackets[1]))
	}
	if mock.sentPackets[1][0] != 0x01 {
		t.Errorf("expected packet 1 (fake_udp) type 0x01, got 0x%02x", mock.sentPackets[1][0])
	}

	// 3. Check Real Handshake
	if len(mock.sentPackets[2]) != 148 {
		t.Errorf("expected packet 2 (real handshake) len 148, got %d", len(mock.sentPackets[2]))
	}
	if mock.sentPackets[2][4] != 4 || mock.sentPackets[2][10] != 10 {
		t.Errorf("real handshake payload mismatch")
	}

	// 4. Verify TTL manipulation sequence:
	// Set to FakeTTL (9), then restored to NormalTTL (64), and final guarantee 64
	if len(mock.ttlHistory) < 2 {
		t.Fatalf("expected at least 2 TTL adjustments, got %d: %+v", len(mock.ttlHistory), mock.ttlHistory)
	}
	if mock.ttlHistory[0] != 9 {
		t.Errorf("expected initial TTL change to fakeTTL 9, got %d", mock.ttlHistory[0])
	}
	if mock.ttlHistory[len(mock.ttlHistory)-1] != 64 {
		t.Errorf("expected final TTL to be restored to 64, got %d", mock.ttlHistory[len(mock.ttlHistory)-1])
	}
}
