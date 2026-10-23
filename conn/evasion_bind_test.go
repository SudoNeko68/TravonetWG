/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

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
	cfg.Strategy = "junk(64) -> fake_udp(148, ttl=9) -> ipopt_shift(8, mode=nop)"
	cfg.Debug = true

	b := NewEvasionBind(mock, cfg)

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

// TestUserspaceMimicAndPreJunk verifies that protocol mimicry packets, the
// configured PreJunk and the oversized jumbo decoy are emitted before the fake
// handshake and the real handshake, without any raw socket privileges.
func TestUserspaceMimicAndPreJunk(t *testing.T) {
	mock := &mockUserspaceBind{}
	cfg := DefaultEvasionConfig()
	cfg.FakeTTL = 5
	cfg.NormalTTL = 64
	cfg.PreJunkSize = 64
	cfg.Strategy = "mimic(quic) -> mimic(stun) -> jumbo_fake(size=1600) -> fake_udp(size=148)"
	cfg.Debug = false

	b := NewEvasionBind(mock, cfg)

	ep := &StdNetEndpoint{}
	handshake := make([]byte, WGHandshakeInitiationSize)
	handshake[0] = 0x01

	if err := b.sendUserspaceObfuscatedHandshake(ep, handshake); err != nil {
		t.Fatalf("sendUserspaceObfuscatedHandshake failed: %v", err)
	}

	sizes := make([]int, len(mock.sentPackets))
	for i, p := range mock.sentPackets {
		sizes[i] = len(p)
	}

	// Expected order: PreJunk(64) -> QUIC(1200) -> STUN(20) -> jumbo(1600)
	// -> fake_udp(148) -> real handshake(148).
	want := []int{64, 1200, 20, 1600, 148, 148}
	if len(sizes) != len(want) {
		t.Fatalf("expected %d packets %v, got %d %v", len(want), want, len(sizes), sizes)
	}
	for i := range want {
		if sizes[i] != want[i] {
			t.Errorf("packet %d: expected size %d, got %d (all sizes: %v)", i, want[i], sizes[i], sizes)
		}
	}

	quic := mock.sentPackets[1]
	if quic[0]&0xC0 != 0xC0 {
		t.Errorf("QUIC long header bits not set: 0x%02x", quic[0])
	}
	if quic[1] != 0x00 || quic[2] != 0x00 || quic[3] != 0x00 || quic[4] != 0x01 {
		t.Errorf("QUIC version is not v1: %x", quic[1:5])
	}

	stun := mock.sentPackets[2]
	if stun[0] != 0x00 || stun[1] != 0x01 || stun[4] != 0x21 || stun[5] != 0x12 || stun[6] != 0xA4 || stun[7] != 0x42 {
		t.Errorf("STUN binding request header is invalid: %x", stun[:8])
	}

	if mock.sentPackets[5][4] != 0 {
		t.Errorf("last packet should be the real handshake, got %x", mock.sentPackets[5][:8])
	}
}

// TestLegacyProtectGate verifies that Send blocks until the application has had
// a chance to call vpnService.protect(fd) (or the 300ms timeout expires).
func TestLegacyProtectGate(t *testing.T) {
	mock := &mockUserspaceBind{}
	cfg := DefaultEvasionConfig()
	cfg.Debug = false
	cfg.Enabled = false

	b := NewEvasionBind(mock, cfg)
	b.RequireLegacySocketProtect()

	ep := &StdNetEndpoint{}
	done := make(chan error, 1)
	go func() {
		done <- b.Send([][]byte{make([]byte, 32)}, ep)
	}()

	select {
	case err := <-done:
		t.Fatalf("Send returned before protect notification: %v", err)
	case <-time.After(60 * time.Millisecond):
		// Still waiting, as expected.
	}

	b.NotifySocketProtected()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Send failed after protect notification: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Send did not resume after NotifySocketProtected")
	}

	if len(mock.sentPackets) != 1 || len(mock.sentPackets[0]) != 32 {
		t.Fatalf("expected exactly one 32-byte packet, got %d", len(mock.sentPackets))
	}
}

// TestSendUDPWithTTLAndIPOptions exercises the per-packet cmsg send path and
// the IP_OPTIONS helper without requiring root.
func TestSendUDPWithTTLAndIPOptions(t *testing.T) {
	if !userspaceRawSendAvailable() {
		t.Skip("per-packet cmsg send is not supported on this platform")
	}

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to open UDP listener: %v", err)
	}
	defer listener.Close()

	port := listener.LocalAddr().(*net.UDPAddr).Port
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("failed to open UDP socket: %v", err)
	}
	defer unix.Close(fd)

	dst := [4]byte{127, 0, 0, 1}

	if err := sendUDPWithTTL(fd, dst, port, []byte("ttl-probe"), 42); err != nil {
		t.Fatalf("sendUDPWithTTL failed: %v", err)
	}
	buf := make([]byte, 64)
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("listener read failed: %v", err)
	}
	if string(buf[:n]) != "ttl-probe" {
		t.Fatalf("unexpected payload: %q", buf[:n])
	}

	opts := ipOptionsForMode("ts", 0)
	if len(opts)%4 != 0 {
		t.Fatalf("IP options length must be a multiple of 4, got %d", len(opts))
	}
	if err := sendUDPWithTTLAndOptions(fd, dst, port, []byte("ipopt-probe"), 64, opts); err != nil {
		t.Fatalf("sendUDPWithTTLAndOptions failed: %v", err)
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("listener read (ipopt) failed: %v", err)
	}
	if string(buf[:n]) != "ipopt-probe" {
		t.Fatalf("unexpected ipopt payload: %q", buf[:n])
	}
}

// TestMimicDNSQuery verifies that the DNS mimic packet contains a correctly
// encoded QNAME (label length 10 for "cloudflare") and a complete question.
func TestMimicDNSQuery(t *testing.T) {
	pkt := buildDNSQuery()
	if len(pkt) < 12 {
		t.Fatalf("DNS packet is too short: %d", len(pkt))
	}
	if pkt[12] != 10 {
		t.Fatalf("expected first label length 10, got %d", pkt[12])
	}
	if string(pkt[13:23]) != "cloudflare" {
		t.Fatalf("unexpected first label: %q", pkt[13:23])
	}
	if pkt[23] != 3 || string(pkt[24:27]) != "com" || pkt[27] != 0 {
		t.Fatalf("unexpected second label: %q", pkt[23:28])
	}
	if len(pkt) != 12+16+4 {
		t.Fatalf("unexpected DNS query length: %d", len(pkt))
	}
}

// mockOpenBind simulates a bind that picks an ephemeral port when 0 is// requested and keeps an explicitly requested port otherwise.
type mockOpenBind struct {
	Bind
	ephemeralPort uint16
}

func (m *mockOpenBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	if port == 0 {
		return nil, m.ephemeralPort, nil
	}
	return nil, port, nil
}

// TestIsAutoPort verifies that dynamic-port tracking survives internal rebinds
// (used for port hopping) but is disabled by an explicit listen_port.
func TestIsAutoPort(t *testing.T) {
	base := &mockOpenBind{ephemeralPort: 40000}
	cfg := DefaultEvasionConfig()
	cfg.Enabled = false
	b := NewEvasionBind(base, cfg)

	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open(0) failed: %v", err)
	}
	if !b.IsAutoPort() {
		t.Fatal("expected dynamic port after Open(0)")
	}

	// BindUpdate re-opens the socket with the previously selected port; this
	// must not disable rotation.
	if _, _, err := b.Open(40000); err != nil {
		t.Fatalf("Open(40000) failed: %v", err)
	}
	if !b.IsAutoPort() {
		t.Fatal("expected dynamic port to survive an internal rebind")
	}

	// An explicit listen_port must disable rotation.
	if _, _, err := b.Open(51820); err != nil {
		t.Fatalf("Open(51820) failed: %v", err)
	}
	if b.IsAutoPort() {
		t.Fatal("expected fixed port after explicit listen_port")
	}

	// Returning to port 0 re-enables rotation.
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open(0) failed: %v", err)
	}
	if !b.IsAutoPort() {
		t.Fatal("expected dynamic port after returning to Open(0)")
	}
}
