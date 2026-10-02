/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"syscall"
)

const (
	// IP_NODEFRAG is socket option 22 on Linux IPPROTO_IP
	// It prevents the Linux kernel from reassembling outgoing raw IP fragments
	IP_NODEFRAG = 22

	WGHandshakeInitiationSize = 148
	UDPHeaderSize             = 8
	DefaultPart1WGSize        = 80
)

// EvasionConfig configures the 5-packet evasion mechanism
type EvasionConfig struct {
	Enabled       bool // Enable L3 fragmentation and fake TTL
	FakeTTL       int  // TTL for the fake MF=0 terminating fragment (default: 3)
	PreJunkSize   int  // Size in bytes of pre-junk UDP datagram (default: 64, 0 to disable)
	PreJunkBadsum bool // If true, uses corrupted UDP checksum on pre-junk
	NormalTTL     int  // TTL for legitimate fragments (default: 64)
	Debug         bool // Enable verbose evasion debugging logs
	VerbosePacket bool // Log every data packet
}

func DefaultEvasionConfig() EvasionConfig {
	return EvasionConfig{
		Enabled:       true,
		FakeTTL:       3,
		PreJunkSize:   64,
		PreJunkBadsum: false,
		NormalTTL:     64,
		Debug:         true,
		VerbosePacket: false,
	}
}

// EvasionBind wraps a standard Bind and intercepts Handshake Initiation packets
type EvasionBind struct {
	Bind
	cfg        EvasionConfig
	mu         sync.RWMutex
	rawFd      int
	actualPort uint16
	closed     bool
}

// NewEvasionBind wraps any Bind with our L3 early-termination desync engine
func NewEvasionBind(base Bind, cfg EvasionConfig) *EvasionBind {
	b := &EvasionBind{
		Bind:  base,
		cfg:   cfg,
		rawFd: -1,
	}

	if cfg.Enabled {
		rawFd, err := initRawSocket()
		if err != nil {
			if cfg.Debug {
				log.Printf("[TRAVONET-WG] ⚠️ Notice: Raw socket initialization: %v (requires root/CAP_NET_RAW)", err)
				log.Printf("[TRAVONET-WG] ⚠️ L3 evasion will be skipped unless granted CAP_NET_RAW")
			}
		} else {
			b.rawFd = rawFd
			if cfg.Debug {
				log.Printf("[TRAVONET-WG] 🛡️ L3 Evasion Raw Socket initialized (IP_NODEFRAG=1, IP_HDRINCL=1)")
			}
		}
	}

	return b
}

func initRawSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return -1, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_NODEFRAG, 1); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("setsockopt IP_NODEFRAG: %w", err)
	}
	return fd, nil
}

func (b *EvasionBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}

	b.mu.Lock()
	b.actualPort = actualPort
	b.mu.Unlock()

	if b.cfg.Debug {
		log.Printf("[TRAVONET-WG] 🔌 Socket bound to local port %d", actualPort)
	}

	// Wrap each ReceiveFunc to monitor incoming packets in debug mode
	wrappedFns := make([]ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrappedFns[i] = b.wrapReceiveFunc(fn)
	}

	return wrappedFns, actualPort, nil
}

func (b *EvasionBind) wrapReceiveFunc(fn ReceiveFunc) ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		if err == nil && b.cfg.Debug {
			for j := 0; j < n; j++ {
				sz := sizes[j]
				if sz >= 4 && len(packets[j]) >= 4 {
					msgType := packets[j][0]
					switch msgType {
					case 2: // Handshake Response (92 bytes)
						log.Printf("[TRAVONET-WG DEBUG] 🟢 <<< RECEIVED HANDSHAKE RESPONSE (Type 2, %d bytes) from %s! Handshake succeeded, tunnel is UP!", sz, eps[j].DstToString())
					case 3: // Cookie Reply
						log.Printf("[TRAVONET-WG DEBUG] 🍪 <<< Received Cookie Reply from %s", eps[j].DstToString())
					case 4: // Transport Data
						if b.cfg.VerbosePacket {
							log.Printf("[TRAVONET-WG DEBUG] 📥 <<< Transport Data (%d bytes) from %s", sz, eps[j].DstToString())
						}
					}
				}
			}
		}
		return n, err
	}
}

func (b *EvasionBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.rawFd >= 0 {
		syscall.Close(b.rawFd)
		b.rawFd = -1
	}
	return b.Bind.Close()
}

func (b *EvasionBind) Send(bufs [][]byte, ep Endpoint) error {
	b.mu.RLock()
	rawFd := b.rawFd
	actualPort := b.actualPort
	b.mu.RUnlock()

	// If raw socket is not available or evasion disabled, standard send
	if !b.cfg.Enabled || rawFd < 0 || ep.DstIP().Is6() {
		return b.Bind.Send(bufs, ep)
	}

	var standardBufs [][]byte
	for _, buf := range bufs {
		// WireGuard Handshake Initiation is strictly 148 bytes with Type = 0x01
		if len(buf) == WGHandshakeInitiationSize && buf[0] == 0x01 {
			if b.cfg.Debug {
				log.Printf("[TRAVONET-WG DEBUG] 🚀 >>> Handshake Initiation detected (148 bytes) to %s", ep.DstToString())
			}

			err := b.sendObfuscatedHandshake(rawFd, int(actualPort), ep, buf)
			if err != nil {
				if b.cfg.Debug {
					log.Printf("[TRAVONET-WG DEBUG] ❌ Evasion send failed: %v (falling back to standard send)", err)
				}
				standardBufs = append(standardBufs, buf)
			} else {
				if b.cfg.Debug {
					log.Printf("[TRAVONET-WG DEBUG] ✅ 5-packet evasion sequence sent successfully to %s!", ep.DstToString())
				}
			}
		} else {
			// Type 4 transport data or keepalives: fast path!
			standardBufs = append(standardBufs, buf)
		}
	}

	if len(standardBufs) > 0 {
		return b.Bind.Send(standardBufs, ep)
	}
	return nil
}

// sendObfuscatedHandshake implements the 5-packet evasion sequence
func (b *EvasionBind) sendObfuscatedHandshake(rawFd int, localPort int, ep Endpoint, wgPayload []byte) error {
	dstAddrPort, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return fmt.Errorf("failed to parse destination addr: %w", err)
	}

	dstIP := dstAddrPort.Addr().AsSlice()
	dstPort := int(dstAddrPort.Port())

	// Resolve local source IP
	var srcIP net.IP
	if ep.SrcIP().IsValid() {
		srcIP = net.IP(ep.SrcIP().AsSlice()).To4()
	}
	if srcIP == nil {
		conn, err := net.Dial("udp", ep.DstToString())
		if err == nil {
			srcIP = conn.LocalAddr().(*net.UDPAddr).IP.To4()
			conn.Close()
		}
	}
	if srcIP == nil {
		srcIP = net.ParseIP("127.0.0.1").To4()
	}

	srcPort := localPort
	if srcPort == 0 {
		srcPort = 51820
	}

	// Generate random IP ID
	var ipIDBuf [2]byte
	rand.Read(ipIDBuf[:])
	ipID := binary.BigEndian.Uint16(ipIDBuf[:])

	// Build UDP header with full length (8 + 148 = 156) and computed checksum
	fullUDPDatagramLen := UDPHeaderSize + len(wgPayload)
	udpHeader := make([]byte, UDPHeaderSize)
	binary.BigEndian.PutUint16(udpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udpHeader[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(fullUDPDatagramLen))
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)

	udpChecksum := computeUDPChecksum(srcIP, dstIP, udpHeader, wgPayload)
	binary.BigEndian.PutUint16(udpHeader[6:8], udpChecksum)

	// 1. Packet 1: Pre-junk UDP packet
	if b.cfg.PreJunkSize > 0 {
		junkPayload := make([]byte, b.cfg.PreJunkSize)
		rand.Read(junkPayload)

		junkUDPHeader := make([]byte, UDPHeaderSize)
		binary.BigEndian.PutUint16(junkUDPHeader[0:2], uint16(srcPort))
		binary.BigEndian.PutUint16(junkUDPHeader[2:4], uint16(dstPort))
		binary.BigEndian.PutUint16(junkUDPHeader[4:6], uint16(UDPHeaderSize+len(junkPayload)))

		if b.cfg.PreJunkBadsum {
			binary.BigEndian.PutUint16(junkUDPHeader[6:8], 0xBADC)
		} else {
			junkCsum := computeUDPChecksum(srcIP, dstIP, junkUDPHeader, junkPayload)
			binary.BigEndian.PutUint16(junkUDPHeader[6:8], junkCsum)
		}

		var junkIDBuf [2]byte
		rand.Read(junkIDBuf[:])
		junkID := binary.BigEndian.Uint16(junkIDBuf[:])

		junkPkt := buildIPv4Packet(srcIP, dstIP, junkID, b.cfg.NormalTTL, false, 0, append(junkUDPHeader, junkPayload...))
		if err := sendRawPacket(rawFd, dstIP, junkPkt); err != nil {
			return fmt.Errorf("pre-junk send: %w", err)
		}
	}

	// 2. Packet 2: Fragment 1 (UDP Header only, Offset 0, MF=1, TTL=normal)
	frag1Pkt := buildIPv4Packet(srcIP, dstIP, ipID, b.cfg.NormalTTL, true, 0, udpHeader)
	if err := sendRawPacket(rawFd, dstIP, frag1Pkt); err != nil {
		return fmt.Errorf("fragment 1 send: %w", err)
	}

	// 3. Packet 3: Fragment 2 (First 80 bytes of WG, Offset 8B (1), MF=1, TTL=normal)
	part1 := wgPayload[:DefaultPart1WGSize]
	frag2Pkt := buildIPv4Packet(srcIP, dstIP, ipID, b.cfg.NormalTTL, true, UDPHeaderSize, part1)
	if err := sendRawPacket(rawFd, dstIP, frag2Pkt); err != nil {
		return fmt.Errorf("fragment 2 send: %w", err)
	}

	// 4. Packet 4: Fake Fragment (MF=0 Early Termination, low TTL=fakeTTL, 32B noise)
	fakePayload := make([]byte, 32)
	rand.Read(fakePayload)

	fakePkt := buildIPv4Packet(
		srcIP, dstIP,
		ipID,
		b.cfg.FakeTTL,
		false,                            // MF = 0 (Crucial for DPI cache poisoning)
		UDPHeaderSize+DefaultPart1WGSize, // Offset = 88B (11)
		fakePayload,
	)
	if err := sendRawPacket(rawFd, dstIP, fakePkt); err != nil {
		return fmt.Errorf("fake fragment send: %w", err)
	}

	// 5. Packet 5: Fragment 3 (Final 68 bytes of WG, Offset 88B (11), MF=0, TTL=normal)
	part2 := wgPayload[DefaultPart1WGSize:]
	frag3Pkt := buildIPv4Packet(
		srcIP, dstIP,
		ipID,
		b.cfg.NormalTTL,
		false,                            // MF = 0 (Real termination for WG server)
		UDPHeaderSize+DefaultPart1WGSize, // Offset = 88B (11)
		part2,
	)
	if err := sendRawPacket(rawFd, dstIP, frag3Pkt); err != nil {
		return fmt.Errorf("fragment 3 send: %w", err)
	}

	return nil
}

func sendRawPacket(rawFd int, dstIP []byte, packet []byte) error {
	addr := syscall.SockaddrInet4{
		Port: 0,
	}
	copy(addr.Addr[:], dstIP[:4])
	return syscall.Sendto(rawFd, packet, 0, &addr)
}

func buildIPv4Packet(srcIP, dstIP []byte, id uint16, ttl int, mf bool, offsetBytes int, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45 // Version 4, IHL 5
	pkt[1] = 0x00 // ToS
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], id)

	offsetUnits := uint16(offsetBytes / 8)
	flagsAndOffset := offsetUnits & 0x1FFF
	if mf {
		flagsAndOffset |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:8], flagsAndOffset)

	pkt[8] = byte(ttl)
	pkt[9] = syscall.IPPROTO_UDP
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	copy(pkt[12:16], srcIP[:4])
	copy(pkt[16:20], dstIP[:4])

	csum := computeChecksum(pkt[0:20])
	binary.BigEndian.PutUint16(pkt[10:12], csum)

	copy(pkt[20:], payload)
	return pkt
}

func computeChecksum(data []byte) uint16 {
	var sum uint32
	n := len(data)
	for i := 0; i < n-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if n%2 == 1 {
		sum += uint32(data[n-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func computeUDPChecksum(srcIP, dstIP []byte, udpHeader, payload []byte) uint16 {
	var sum uint32

	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(syscall.IPPROTO_UDP)
	totalUDPLen := uint16(len(udpHeader) + len(payload))
	sum += uint32(totalUDPLen)

	for i := 0; i < len(udpHeader); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpHeader[i : i+2]))
	}

	n := len(payload)
	for i := 0; i < n-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if n%2 == 1 {
		sum += uint32(payload[n-1]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	res := ^uint16(sum)
	if res == 0 {
		return 0xFFFF
	}
	return res
}
