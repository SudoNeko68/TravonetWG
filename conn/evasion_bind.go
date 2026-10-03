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
	"time"
)

const (
	// IP_NODEFRAG is socket option 22 on Linux IPPROTO_IP
	// It prevents the Linux kernel from reassembling outgoing raw IP fragments
	IP_NODEFRAG = 22

	WGHandshakeInitiationSize = 148
	UDPHeaderSize             = 8
	DefaultPart1WGSize        = 80
)

// EvasionConfig configures the evasion mechanism
type EvasionConfig struct {
	Enabled       bool   // Enable L3 fragmentation and fake TTL
	FakeTTL       int    // TTL for the fake MF=0 terminating fragment (default: 3)
	PreJunkSize   int    // Size in bytes of pre-junk UDP datagram (default: 64, 0 to disable)
	PreJunkBadsum bool   // If true, uses corrupted UDP checksum on pre-junk
	NormalTTL     int    // TTL for legitimate fragments (default: 64)
	Strategy      string // DSL strategy pipeline (e.g. "junk(64) -> frag(8) -> ...")
	Debug         bool   // Enable verbose evasion debugging logs
	VerbosePacket bool   // Log every data packet

	compiledStrategy *Strategy
}

func DefaultEvasionConfig() EvasionConfig {
	return EvasionConfig{
		Enabled:       true,
		FakeTTL:       3,
		PreJunkSize:   64,
		PreJunkBadsum: false,
		NormalTTL:     64,
		Strategy:      "default",
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
	strat, err := ParseStrategy(cfg.Strategy, cfg.FakeTTL, cfg.NormalTTL)
	if err != nil {
		if cfg.Debug {
			log.Printf("[TRAVONET-WG] ⚠️ Invalid strategy '%s': %v (falling back to default)", cfg.Strategy, err)
		}
		strat = DefaultStrategy(cfg.FakeTTL, cfg.NormalTTL)
	}
	cfg.compiledStrategy = strat

	b := &EvasionBind{
		Bind:  base,
		cfg:   cfg,
		rawFd: -1,
	}

	if cfg.Enabled {
		b.mu.Lock()
		_, _ = b.ensureRawSocketLocked()
		b.mu.Unlock()
		if cfg.Debug {
			fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] 📜 Active Evasion Strategy: %s\n", strat.String())
		}
	}

	return b
}

func initRawSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return -1, fmt.Errorf("syscall.Socket(AF_INET, SOCK_RAW, IPPROTO_RAW): %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
	}
	// IP_NODEFRAG tells kernel not to reassemble fragments on outgoing raw socket.
	// We ignore errors here in case specific kernels or container namespaces don't permit it.
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_NODEFRAG, 1)

	// IP_FREEBIND (15) allows binding/sending with non-local source addresses if needed.
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, 15, 1)

	return fd, nil
}

func (b *EvasionBind) ensureRawSocketLocked() (int, error) {
	if b.rawFd >= 0 {
		return b.rawFd, nil
	}
	fd, err := initRawSocket()
	if err != nil {
		if b.cfg.Debug {
			fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] ⚠️ Notice: Raw socket initialization failed: %v (requires root/CAP_NET_RAW)\n", err)
			fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] ⚠️ L3 evasion will be skipped unless granted CAP_NET_RAW\n")
		}
		return -1, err
	}
	b.rawFd = fd
	if b.cfg.Debug {
		fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] 🛡️ L3 Evasion Raw Socket initialized (fd=%d, IP_NODEFRAG=1, IP_HDRINCL=1)\n", fd)
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
	b.closed = false
	if b.cfg.Enabled {
		_, _ = b.ensureRawSocketLocked()
	}
	b.mu.Unlock()

	if b.cfg.Debug {
		fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] 🔌 Socket bound to local port %d\n", actualPort)
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
						fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] 🟢 <<< RECEIVED HANDSHAKE RESPONSE (Type 2, %d bytes) from %s! Handshake succeeded, tunnel is UP!\n", sz, eps[j].DstToString())
					case 3: // Cookie Reply
						fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] 🍪 <<< Received Cookie Reply from %s\n", eps[j].DstToString())
					case 4: // Transport Data
						if b.cfg.VerbosePacket {
							fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] 📥 <<< Transport Data (%d bytes) from %s\n", sz, eps[j].DstToString())
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
	b.mu.Lock()
	if b.cfg.Enabled && b.rawFd < 0 {
		_, _ = b.ensureRawSocketLocked()
	}
	rawFd := b.rawFd
	actualPort := b.actualPort
	b.mu.Unlock()

	// If raw socket is not available or evasion disabled, standard send
	if !b.cfg.Enabled || rawFd < 0 || ep.DstIP().Is6() {
		if b.cfg.Debug && len(bufs) > 0 && len(bufs[0]) == WGHandshakeInitiationSize && bufs[0][0] == 0x01 {
			fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] ⚠️ Evasion skipped (enabled=%v, rawFd=%d, isIPv6=%v), sending standard packet\n", b.cfg.Enabled, rawFd, ep.DstIP().Is6())
		}
		return b.Bind.Send(bufs, ep)
	}

	var standardBufs [][]byte
	for _, buf := range bufs {
		// WireGuard Handshake Initiation is strictly 148 bytes with Type = 0x01
		if len(buf) == WGHandshakeInitiationSize && buf[0] == 0x01 {
			if b.cfg.Debug {
				fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] 🚀 >>> Handshake Initiation detected (148 bytes) to %s\n", ep.DstToString())
			}

			err := b.sendObfuscatedHandshake(rawFd, int(actualPort), ep, buf)
			if err != nil {
				if b.cfg.Debug {
					fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] ❌ Evasion send failed: %v (falling back to standard send)\n", err)
				}
				standardBufs = append(standardBufs, buf)
			} else {
				if b.cfg.Debug {
					fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] ✅ 5-packet evasion sequence sent successfully to %s!\n", ep.DstToString())
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
		conn, err := net.Dial("udp4", ep.DstToString())
		if err == nil {
			if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
				srcIP = udpAddr.IP.To4()
			}
			conn.Close()
		}
	}
	if srcIP == nil {
		srcIP = net.ParseIP("127.0.0.1").To4()
	}

	srcPort := localPort
	if srcPort == 0 {
		b.mu.RLock()
		srcPort = int(b.actualPort)
		b.mu.RUnlock()
	}
	if srcPort == 0 {
		srcPort = 51820
	}

	// Generate random IP ID
	var ipIDBuf [2]byte
	rand.Read(ipIDBuf[:])
	ipID := binary.BigEndian.Uint16(ipIDBuf[:])

	if b.cfg.Debug {
		fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] 🛰️ Flow: %s:%d -> %s:%d (IP ID: 0x%04x)\n",
			srcIP.String(), srcPort, dstAddrPort.Addr().String(), dstPort, ipID)
	}

	// Build UDP header with full length (8 + 148 = 156) and computed checksum
	fullUDPDatagramLen := UDPHeaderSize + len(wgPayload)
	udpHeader := make([]byte, UDPHeaderSize)
	binary.BigEndian.PutUint16(udpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udpHeader[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(fullUDPDatagramLen))
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)

	udpChecksum := computeUDPChecksum(srcIP, dstIP, udpHeader, wgPayload)
	binary.BigEndian.PutUint16(udpHeader[6:8], udpChecksum)

	// Assemble unfragmented UDP datagram: 8B UDP header + 148B WG handshake = 156B
	fullDatagram := append(udpHeader, wgPayload...)
	currentOffset := 0

	strategy := b.cfg.compiledStrategy
	if strategy == nil {
		strategy = DefaultStrategy(b.cfg.FakeTTL, b.cfg.NormalTTL)
	}

	for i, step := range strategy.Steps {
		switch step.Action {
		case ActionJunk:
			junkPayload := make([]byte, step.Length)
			rand.Read(junkPayload)

			junkUDPHeader := make([]byte, UDPHeaderSize)
			binary.BigEndian.PutUint16(junkUDPHeader[0:2], uint16(srcPort))
			binary.BigEndian.PutUint16(junkUDPHeader[2:4], uint16(dstPort))
			binary.BigEndian.PutUint16(junkUDPHeader[4:6], uint16(UDPHeaderSize+len(junkPayload)))

			if step.Badsum {
				binary.BigEndian.PutUint16(junkUDPHeader[6:8], 0xBADC)
			} else {
				junkCsum := computeUDPChecksum(srcIP, dstIP, junkUDPHeader, junkPayload)
				binary.BigEndian.PutUint16(junkUDPHeader[6:8], junkCsum)
			}

			var junkIDBuf [2]byte
			rand.Read(junkIDBuf[:])
			junkID := binary.BigEndian.Uint16(junkIDBuf[:])

			ttl := step.TTL
			if ttl <= 0 {
				ttl = b.cfg.NormalTTL
			}

			junkPkt := buildIPv4Packet(srcIP, dstIP, junkID, ttl, false, 0, append(junkUDPHeader, junkPayload...))
			if err := sendRawPacket(rawFd, dstIP, junkPkt); err != nil {
				return fmt.Errorf("step %d (junk) send: %w", i+1, err)
			}
			if b.cfg.Debug {
				fmt.Printf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] 📦 Sent Pre-Junk UDP packet (%d bytes payload, TTL=%d, Badsum=%v)\n",
					i+1, len(strategy.Steps), len(junkPayload), ttl, step.Badsum)
			}

		case ActionFrag:
			offset := step.Offset
			if offset < 0 {
				offset = currentOffset
			}
			length := step.Length
			if offset+length > len(fullDatagram) {
				length = len(fullDatagram) - offset
			}
			if length <= 0 {
				continue
			}

			slice := fullDatagram[offset : offset+length]
			mf := step.MF
			if step.AutoMF {
				mf = (offset+length < len(fullDatagram))
			}

			ttl := step.TTL
			if ttl <= 0 {
				ttl = b.cfg.NormalTTL
			}

			fragPkt := buildIPv4Packet(srcIP, dstIP, ipID, ttl, mf, offset, slice)
			if err := sendRawPacket(rawFd, dstIP, fragPkt); err != nil {
				return fmt.Errorf("step %d (frag) send: %w", i+1, err)
			}
			if b.cfg.Debug {
				fmt.Printf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] 🧩 Sent Frag (offset=%d, len=%d, MF=%v, TTL=%d)\n",
					i+1, len(strategy.Steps), offset, length, mf, ttl)
			}
			currentOffset = offset + length

		case ActionFakeFrag:
			offset := step.Offset
			if offset < 0 {
				offset = currentOffset
			}
			fakePayload := make([]byte, step.Length)
			rand.Read(fakePayload)

			ttl := step.TTL
			if ttl <= 0 {
				ttl = b.cfg.FakeTTL
			}

			fakePkt := buildIPv4Packet(srcIP, dstIP, ipID, ttl, step.MF, offset, fakePayload)
			if err := sendRawPacket(rawFd, dstIP, fakePkt); err != nil {
				return fmt.Errorf("step %d (fake_frag) send: %w", i+1, err)
			}
			if b.cfg.Debug {
				fmt.Printf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] ☠️ Sent FAKE Frag (offset=%d, len=%d, MF=%v, TTL=%d) [DPI Early-Termination]\n",
					i+1, len(strategy.Steps), offset, len(fakePayload), step.MF, ttl)
			}

		case ActionFakeUDP:
			fakePayload := make([]byte, step.Length)
			rand.Read(fakePayload)

			fakeUDPHeader := make([]byte, UDPHeaderSize)
			binary.BigEndian.PutUint16(fakeUDPHeader[0:2], uint16(srcPort))
			binary.BigEndian.PutUint16(fakeUDPHeader[2:4], uint16(dstPort))
			binary.BigEndian.PutUint16(fakeUDPHeader[4:6], uint16(UDPHeaderSize+len(fakePayload)))

			if step.Badsum {
				binary.BigEndian.PutUint16(fakeUDPHeader[6:8], 0xBADC)
			} else {
				csum := computeUDPChecksum(srcIP, dstIP, fakeUDPHeader, fakePayload)
				binary.BigEndian.PutUint16(fakeUDPHeader[6:8], csum)
			}

			var fakeIDBuf [2]byte
			rand.Read(fakeIDBuf[:])
			fakeID := binary.BigEndian.Uint16(fakeIDBuf[:])

			ttl := step.TTL
			if ttl <= 0 {
				ttl = b.cfg.FakeTTL
			}

			pkt := buildIPv4Packet(srcIP, dstIP, fakeID, ttl, false, 0, append(fakeUDPHeader, fakePayload...))
			if err := sendRawPacket(rawFd, dstIP, pkt); err != nil {
				return fmt.Errorf("step %d (fake_udp) send: %w", i+1, err)
			}
			if b.cfg.Debug {
				fmt.Printf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] 🎭 Sent FAKE UDP packet (%d bytes payload, TTL=%d, Badsum=%v)\n",
					i+1, len(strategy.Steps), len(fakePayload), ttl, step.Badsum)
			}

		case ActionSleep:
			if step.SleepDur > 0 {
				if b.cfg.Debug {
					fmt.Printf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] ⏱️ Sleeping %v\n", i+1, len(strategy.Steps), step.SleepDur)
				}
				time.Sleep(step.SleepDur)
			}
		}
	}

	return nil
}

func sendRawPacket(rawFd int, dstIP []byte, packet []byte) error {
	var addr syscall.SockaddrInet4
	if len(dstIP) >= 4 {
		copy(addr.Addr[:], dstIP[:4])
	} else {
		return fmt.Errorf("invalid IPv4 address length: %d", len(dstIP))
	}
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
