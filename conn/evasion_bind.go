/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// IP_NODEFRAG is socket option 22 on Linux IPPROTO_IP
	IP_NODEFRAG = 22

	// WGHandshakeInitiationSize is the fixed size of a WireGuard handshake
	// initiation message (type 0x01).
	WGHandshakeInitiationSize = 148
	UDPHeaderSize             = 8
	DefaultPart1WGSize        = 80
	ipProtoUDP                = 17
)

// EvasionConfig configures the DPI evasion engine.
type EvasionConfig struct {
	Enabled       bool                         // Enable DPI evasion
	FakeTTL       int                          // TTL for decoy handshake packets (-1 = auto)
	PreJunkSize   int                          // Size in bytes of the pre-junk UDP datagram (0 to disable)
	PreJunkBadsum bool                         // If true, uses corrupted UDP checksum on pre-junk (raw socket only)
	NormalTTL     int                          // TTL for the legitimate handshake and transport packets
	Strategy      string                       // DSL pipeline (e.g. "junk(64) -> fake_udp(148)")
	Debug         bool                         // Enable verbose evasion debugging logs
	VerbosePacket bool                         // Log every data packet
	LogFunc       func(string, ...interface{}) // Optional custom logger (e.g. Android logcat)

	compiledStrategy *Strategy
}

func DefaultEvasionConfig() EvasionConfig {
	return EvasionConfig{
		Enabled:       true,
		FakeTTL:       -1, // -1 = auto-detect if endpoint is known
		PreJunkSize:   64,
		PreJunkBadsum: false,
		NormalTTL:     64,
		Strategy:      "default",
		Debug:         true,
		VerbosePacket: false,
	}
}

// EvasionBind wraps a standard Bind and intercepts Handshake Initiation packets.
// It supports both privileged raw socket L3 fragmentation (Linux with CAP_NET_RAW / root
// and Windows) and unprivileged userspace UDP desync (Android, non-root Linux, standard Windows).
type EvasionBind struct {
	Bind
	cfg        EvasionConfig
	mu         sync.RWMutex
	sendMu     sync.Mutex
	fakeTTL    atomic.Int32
	actualPort uint16
	autoPort   bool // last Open() used a kernel-assigned (dynamic) port

	protectMu   sync.Mutex
	protectWait chan struct{}

	handshakeSeq atomic.Uint32

	rawFd              int
	rawSocketAttempted bool
	srcIPCache         sync.Map
	closed             bool
}

func (b *EvasionBind) logf(format string, args ...interface{}) {
	if b.cfg.LogFunc != nil {
		b.cfg.LogFunc(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func defaultFakeTTLForPlatform() int {
	return 8
}

// RequireLegacySocketProtect arms the protection barrier for Android VpnService.
func (b *EvasionBind) RequireLegacySocketProtect() {
	b.protectMu.Lock()
	if b.protectWait == nil {
		b.protectWait = make(chan struct{})
	}
	b.protectMu.Unlock()
}

// NotifySocketProtected releases the protection barrier.
func (b *EvasionBind) NotifySocketProtected() {
	b.protectMu.Lock()
	ch := b.protectWait
	b.protectWait = nil
	b.protectMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (b *EvasionBind) waitIfLegacyProtectPending() {
	b.protectMu.Lock()
	ch := b.protectWait
	b.protectMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	case <-time.After(300 * time.Millisecond):
		b.protectMu.Lock()
		if b.protectWait == ch {
			b.protectWait = nil
		}
		b.protectMu.Unlock()
	}
}

var (
	_ Bind               = (*EvasionBind)(nil)
	_ PeekLookAtSocketFd = (*EvasionBind)(nil)
)

func (b *EvasionBind) PeekLookAtSocketFd4() (int, error) {
	if peeker, ok := b.Bind.(PeekLookAtSocketFd); ok {
		return peeker.PeekLookAtSocketFd4()
	}
	return -1, errors.New("underlying bind does not support PeekLookAtSocketFd4")
}

func (b *EvasionBind) PeekLookAtSocketFd6() (int, error) {
	if peeker, ok := b.Bind.(PeekLookAtSocketFd); ok {
		return peeker.PeekLookAtSocketFd6()
	}
	return -1, errors.New("underlying bind does not support PeekLookAtSocketFd6")
}

func (b *EvasionBind) SetIPv4TTL(ttl int) error {
	if ctrl, ok := b.Bind.(SocketTTLController); ok {
		return ctrl.SetIPv4TTL(ttl)
	}
	return errors.New("underlying bind does not support setting TTL")
}

func (b *EvasionBind) SetIPv6HopLimit(hops int) error {
	if ctrl, ok := b.Bind.(SocketTTLController); ok {
		return ctrl.SetIPv6HopLimit(hops)
	}
	return errors.New("underlying bind does not support setting hop limit")
}

// IsAutoPort reports whether the current UDP socket uses a kernel-assigned port.
func (b *EvasionBind) IsAutoPort() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.autoPort
}

// SetFakeTTL updates the TTL used by decoy packets.
func (b *EvasionBind) SetFakeTTL(ttl int) {
	if ttl <= 0 {
		ttl = defaultFakeTTLForPlatform()
	}
	b.fakeTTL.Store(int32(ttl))
}

// FakeTTL returns the TTL currently used for decoy packets.
func (b *EvasionBind) FakeTTL() int {
	return int(b.fakeTTL.Load())
}

func (b *EvasionBind) resolveFakeTTL(stepTTL int) int {
	if stepTTL > 0 {
		return stepTTL
	}
	if ttl := b.FakeTTL(); ttl > 0 {
		return ttl
	}
	return defaultFakeTTLForPlatform()
}

func strategyRequiresRaw(strat *Strategy) bool {
	if strat == nil {
		return false
	}
	for _, step := range strat.Steps {
		if step.Action == ActionFrag || step.Action == ActionFakeFrag || step.Badsum {
			return true
		}
	}
	return false
}

// NewEvasionBind wraps any Bind with the unified DPI desync engine.
func NewEvasionBind(base Bind, cfg EvasionConfig) *EvasionBind {
	fakeTTL := cfg.FakeTTL
	if fakeTTL <= 0 {
		fakeTTL = defaultFakeTTLForPlatform()
	}
	if cfg.NormalTTL <= 0 {
		cfg.NormalTTL = 64
	}
	if cfg.PreJunkSize < 0 {
		cfg.PreJunkSize = 0
	}

	strat, err := ParseStrategy(cfg.Strategy, fakeTTL, cfg.NormalTTL)
	if err != nil {
		if cfg.Debug {
			log.Printf("[TRAVONET-WG] Invalid strategy '%s': %v (falling back to default)", cfg.Strategy, err)
		}
		strat = DefaultUserspaceStrategy()
	}

	b := &EvasionBind{
		Bind:  base,
		cfg:   cfg,
		rawFd: -1,
	}
	b.cfg.compiledStrategy = strat
	b.cfg.FakeTTL = fakeTTL
	b.fakeTTL.Store(int32(fakeTTL))

	if cfg.Enabled {
		b.mu.Lock()
		_, _ = b.ensureRawSocketLocked()
		b.mu.Unlock()

		if cfg.Debug {
			b.logf("DEBUG: (evasion) [TRAVONET-WG] Active evasion strategy: %s\n", strat.String())
			for _, w := range strat.Warnings {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] Strategy warning: %s\n", w)
			}
		}
	} else if cfg.Debug {
		b.logf("DEBUG: (evasion) [TRAVONET-WG] Evasion disabled (NoEvasion), using plain WireGuard\n")
	}

	return b
}

func (b *EvasionBind) ensureRawSocketLocked() (int, error) {
	if b.rawFd >= 0 {
		return b.rawFd, nil
	}
	if b.rawSocketAttempted {
		return -1, errors.New("permission denied for raw socket")
	}
	b.rawSocketAttempted = true
	fd, err := initRawSocket()
	if err != nil {
		if b.cfg.Debug {
			b.logf("DEBUG: (evasion) [TRAVONET-WG] Unprivileged userspace environment detected (raw socket: %v)\n", err)
			b.logf("DEBUG: (evasion) [TRAVONET-WG] Activating Userspace UDP Desync Engine (IP_TTL + Decoys without root)\n")
		}
		return -1, err
	}
	b.rawFd = fd
	if b.cfg.Debug {
		b.logf("DEBUG: (evasion) [TRAVONET-WG] Privileged L3 Evasion Raw Socket initialized (fd=%d)\n", fd)
	}
	return fd, nil
}

func (b *EvasionBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}

	b.mu.Lock()
	if port == 0 {
		b.autoPort = true
	} else if port != b.actualPort {
		b.autoPort = false
	}
	b.actualPort = actualPort
	b.closed = false
	if b.cfg.Enabled {
		_, _ = b.ensureRawSocketLocked()
	}
	b.mu.Unlock()

	if b.cfg.Debug {
		b.logf("DEBUG: (evasion) [TRAVONET-WG] Socket bound to local port %d\n", actualPort)
	}

	wrappedFns := make([]ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrappedFns[i] = b.wrapReceiveFunc(fn)
	}

	return wrappedFns, actualPort, nil
}

func (b *EvasionBind) wrapReceiveFunc(fn ReceiveFunc) ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		n, err = fn(packets, sizes, eps)
		if err == nil && b.cfg.Debug {
			for j := 0; j < n; j++ {
				sz := sizes[j]
				if sz > 0 && len(packets[j]) > 0 {
					msgType := packets[j][0]
					switch msgType {
					case 2: // Handshake Response
						b.logf("DEBUG: (evasion) [TRAVONET-WG] <<< HANDSHAKE RESPONSE (Type 2, %d bytes) from %s! Tunnel is UP!\n", sz, eps[j].DstToString())
					case 3: // Cookie Reply
						b.logf("DEBUG: (evasion) [TRAVONET-WG] <<< Cookie Reply from %s\n", eps[j].DstToString())
					case 4: // Transport Data
						if b.cfg.VerbosePacket {
							b.logf("DEBUG: (evasion) [TRAVONET-WG] <<< Transport Data (%d bytes) from %s\n", sz, eps[j].DstToString())
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
		_ = closeRawSocket(b.rawFd)
		b.rawFd = -1
	}
	b.rawSocketAttempted = false
	return b.Bind.Close()
}

func (b *EvasionBind) Send(bufs [][]byte, ep Endpoint) error {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()

	b.waitIfLegacyProtectPending()

	if !b.cfg.Enabled {
		return b.Bind.Send(bufs, ep)
	}

	b.mu.RLock()
	rawFd := b.rawFd
	actualPort := b.actualPort
	attempted := b.rawSocketAttempted
	b.mu.RUnlock()

	if rawFd < 0 && !attempted {
		b.mu.Lock()
		if b.rawFd < 0 && !b.rawSocketAttempted {
			_, _ = b.ensureRawSocketLocked()
		}
		rawFd = b.rawFd
		actualPort = b.actualPort
		b.mu.Unlock()
	}

	var standardBufs [][]byte
	for _, buf := range bufs {
		if len(buf) == WGHandshakeInitiationSize && buf[0] == 0x01 {
			if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] >>> Handshake Initiation detected (148 bytes) to %s\n", ep.DstToString())
			}

			strategy := b.cfg.compiledStrategy
			needsRaw := strategyRequiresRaw(strategy)

			var sendErr error
			if needsRaw && rawFd >= 0 {
				sendErr = b.sendObfuscatedHandshake(rawFd, int(actualPort), ep, buf)
			} else {
				if needsRaw && rawFd < 0 && b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG] L3 strategy requested but raw socket unavailable; executing userspace pipeline fallback\n")
				}
				sendErr = b.sendUserspaceObfuscatedHandshake(ep, buf)
			}

			if sendErr != nil {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG] Evasion send failed: %v (falling back to standard send)\n", sendErr)
				}
				standardBufs = append(standardBufs, buf)
			} else if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] Evasion sequence sent successfully to %s\n", ep.DstToString())
			}
		} else {
			if b.cfg.VerbosePacket && len(buf) > 0 {
				if len(buf) == 32 {
					b.logf("DEBUG: (evasion) [TRAVONET-WG] >>> Transport Keepalive (32 bytes) to %s\n", ep.DstToString())
				} else {
					b.logf("DEBUG: (evasion) [TRAVONET-WG] >>> Transport Data (%d bytes) to %s\n", len(buf), ep.DstToString())
				}
			}
			standardBufs = append(standardBufs, buf)
		}
	}

	if len(standardBufs) > 0 {
		return b.Bind.Send(standardBufs, ep)
	}
	return nil
}

// sendUserspaceObfuscatedHandshake executes the unprivileged UDP desync pipeline.
func (b *EvasionBind) sendUserspaceObfuscatedHandshake(ep Endpoint, wgPayload []byte) error {
	strategy := b.userspaceStrategy()
	if strategy == nil || len(strategy.Steps) == 0 {
		return b.Bind.Send([][]byte{wgPayload}, ep)
	}

	target, _ := b.userspaceTarget(ep)
	seq := b.handshakeSeq.Add(1)

	if b.cfg.Debug {
		b.logf("DEBUG: (evasion) [TRAVONET-WG] Executing userspace UDP desync (%d steps, seq=%d, cmsg=%v, is6=%v) to %s\n",
			len(strategy.Steps), seq, target.fd >= 0, target.is6, ep.DstToString())
	}

	ipOptShift := 0
	ipOptMode := "nop"
	for _, step := range strategy.Steps {
		if step.Action == ActionIPOptShift {
			ipOptShift = step.Length
			if step.IPOptMode != "" {
				ipOptMode = step.IPOptMode
			}
		}
	}

	// PreJunk always precedes the strategy pipeline
	if b.cfg.PreJunkSize > 0 {
		junk := make([]byte, b.cfg.PreJunkSize)
		rand.Read(junk)
		if err := b.sendUserspacePacket(ep, target, junk, b.cfg.NormalTTL, ""); err != nil {
			if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] Userspace PreJunk send error: %v\n", err)
			}
		} else if b.cfg.Debug {
			b.logf("DEBUG: (evasion) [TRAVONET-WG] Sent Userspace Pre-Junk UDP packet (%d bytes)\n", len(junk))
		}
	}

	for i, step := range strategy.Steps {
		switch step.Action {
		case ActionJunk:
			junkSize := step.Length
			if junkSize < 0 {
				junkSize = 0
			}
			junkPayload := make([]byte, junkSize)
			rand.Read(junkPayload)
			ttl := step.TTL
			if ttl <= 0 {
				ttl = b.cfg.NormalTTL
			}
			if err := b.sendUserspacePacket(ep, target, junkPayload, ttl, ""); err != nil {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG] [%d/%d] Userspace junk send error: %v\n", i+1, len(strategy.Steps), err)
				}
			} else if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] [%d/%d] Sent Userspace Junk UDP packet (%d bytes)\n",
					i+1, len(strategy.Steps), len(junkPayload))
			}

		case ActionMimic:
			mimicPayload := buildMimicPacket(step.MimicProto)
			ttl := step.TTL
			if ttl <= 0 {
				ttl = b.cfg.NormalTTL
			}
			if err := b.sendUserspacePacket(ep, target, mimicPayload, ttl, ""); err != nil {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG] [%d/%d] mimic(%s) send error: %v\n", i+1, len(strategy.Steps), step.MimicProto, err)
				}
			} else if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] [%d/%d] Sent mimic(%s) packet (%d bytes, TTL=%d)\n",
					i+1, len(strategy.Steps), step.MimicProto, len(mimicPayload), ttl)
			}

		case ActionJumboFake:
			jumboPayload := buildJumboFakePayload(step.Length)
			ttl := b.resolveFakeTTL(step.TTL)
			if err := b.sendUserspacePacket(ep, target, jumboPayload, ttl, ""); err != nil {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG] [%d/%d] jumbo_fake send error: %v\n", i+1, len(strategy.Steps), err)
				}
			} else if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] [%d/%d] Sent JUMBO FAKE (%d bytes, TTL=%d)\n",
					i+1, len(strategy.Steps), len(jumboPayload), ttl)
			}

		case ActionFakeUDP:
			fakePayload := buildFakeHandshakePayload(step.Length, step.CorruptHeader)
			ttl := b.resolveFakeTTL(step.TTL)
			ipMode := step.IPOptMode
			if target.is6 {
				ipMode = ""
			}
			if err := b.sendUserspacePacket(ep, target, fakePayload, ttl, ipMode); err != nil {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG] [%d/%d] fake_udp send error: %v\n", i+1, len(strategy.Steps), err)
				}
			} else if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] [%d/%d] Sent Userspace FAKE UDP packet (%d bytes, TTL=%d, corrupt=%v, ipopt=%s)\n",
					i+1, len(strategy.Steps), len(fakePayload), ttl, step.CorruptHeader, ipMode)
			}

		case ActionIPOptShift:
			if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] [%d/%d] ipopt_shift(%d, mode=%s) armed for handshake\n",
					i+1, len(strategy.Steps), step.Length, ipOptMode)
			}

		case ActionSleep:
			if step.SleepDur > 0 {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG] [%d/%d] Sleeping %v\n", i+1, len(strategy.Steps), step.SleepDur)
				}
				time.Sleep(step.SleepDur)
			}

		case ActionFrag, ActionFakeFrag:
			if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] [%d/%d] Action '%s' skipped in userspace mode\n", i+1, len(strategy.Steps), step.Action)
			}
		}
	}

	// Send legitimate WireGuard Handshake Initiation with NormalTTL.
	if !target.is6 && ipOptShift > 0 && seq%2 == 1 && target.fd >= 0 {
		opts := ipOptionsForMode(ipOptMode, ipOptShift)
		if err := sendUDPWithTTLAndOptions(target.fd, target.dstIP4, target.dstPort, wgPayload, b.cfg.NormalTTL, opts); err == nil {
			if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] Sent Legitimate WireGuard Handshake (%d bytes, TTL=%d, ipopt_shift=%d) to %s\n",
					len(wgPayload), b.cfg.NormalTTL, ipOptShift, ep.DstToString())
			}
			return nil
		} else if b.cfg.Debug {
			b.logf("DEBUG: (evasion) [TRAVONET-WG] ipopt_shift handshake send failed: %v (retrying plain)\n", err)
		}
	}

	if err := b.sendUserspacePacket(ep, target, wgPayload, b.cfg.NormalTTL, ""); err != nil {
		return fmt.Errorf("legitimate handshake send failed: %w", err)
	}

	if b.cfg.Debug {
		b.logf("DEBUG: (evasion) [TRAVONET-WG] Sent Legitimate WireGuard Handshake (%d bytes, TTL=%d) to %s\n",
			len(wgPayload), b.cfg.NormalTTL, ep.DstToString())
	}

	return nil
}

func (b *EvasionBind) userspaceStrategy() *Strategy {
	strat := b.cfg.compiledStrategy
	if strat == nil || len(strat.Steps) == 0 {
		return DefaultUserspaceStrategy()
	}
	return strat
}

type userspaceTarget struct {
	fd      int
	is6     bool
	dstIP4  [4]byte
	dstIP6  [16]byte
	dstPort int
}

func (b *EvasionBind) userspaceTarget(ep Endpoint) (target userspaceTarget, ok bool) {
	if ep == nil {
		return target, false
	}
	se, isStd := ep.(*StdNetEndpoint)
	if !isStd {
		return target, false
	}
	port := int(se.Port())
	if port <= 0 || port > 65535 {
		return target, false
	}
	target.dstPort = port

	if ep.DstIP().Is4() {
		target.dstIP4 = ep.DstIP().As4()
		fd, err := b.PeekLookAtSocketFd4()
		if err != nil || fd < 0 {
			target.fd = -1
		} else {
			target.fd = fd
		}
		return target, true
	} else if ep.DstIP().Is6() {
		target.is6 = true
		target.dstIP6 = ep.DstIP().As16()
		fd, err := b.PeekLookAtSocketFd6()
		if err != nil || fd < 0 {
			target.fd = -1
		} else {
			target.fd = fd
		}
		return target, true
	}
	return target, false
}

func (b *EvasionBind) sendUserspacePacket(ep Endpoint, target userspaceTarget, payload []byte, ttl int, ipOptMode string) error {
	if ttl <= 0 {
		ttl = b.cfg.NormalTTL
	}

	if target.fd >= 0 {
		var err error
		if target.is6 {
			err = sendUDP6WithControl(target.fd, target.dstIP6, target.dstPort, payload, ttl)
		} else if payloadIsJumbo(payload) {
			err = sendUDPJumbo(target.fd, target.dstIP4, target.dstPort, payload, ttl)
		} else {
			var opts []byte
			if ipOptMode != "" && ipOptMode != "none" {
				opts = ipOptionsForMode(ipOptMode, 0)
			}
			err = sendUDPWithTTLAndOptions(target.fd, target.dstIP4, target.dstPort, payload, ttl, opts)
		}
		if err == nil {
			return nil
		}
		if b.cfg.Debug {
			b.logf("DEBUG: (evasion) [TRAVONET-WG] cmsg send failed: %v (falling back to bind send)\n", err)
		}
	}

	if target.is6 {
		if ttl != b.cfg.NormalTTL {
			_ = b.SetIPv6HopLimit(ttl)
		}
		err := b.Bind.Send([][]byte{payload}, ep)
		if ttl != b.cfg.NormalTTL {
			_ = b.SetIPv6HopLimit(b.cfg.NormalTTL)
		}
		return err
	}

	if ttl != b.cfg.NormalTTL {
		_ = b.SetIPv4TTL(ttl)
	}
	err := b.Bind.Send([][]byte{payload}, ep)
	if ttl != b.cfg.NormalTTL {
		_ = b.SetIPv4TTL(b.cfg.NormalTTL)
	}
	return err
}

const jumboFragmentationThreshold = 1200

func payloadIsJumbo(payload []byte) bool {
	return len(payload) > jumboFragmentationThreshold
}

// sendObfuscatedHandshake implements the evasion sequence using privileged raw sockets
func (b *EvasionBind) sendObfuscatedHandshake(rawFd int, localPort int, ep Endpoint, wgPayload []byte) error {
	dstAddrPort, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return fmt.Errorf("failed to parse destination addr: %w", err)
	}

	dstIP := dstAddrPort.Addr().AsSlice()
	dstPort := int(dstAddrPort.Port())

	// Resolve local source IP with caching
	var srcIP net.IP
	if ep.SrcIP().IsValid() {
		srcIP = net.IP(ep.SrcIP().AsSlice()).To4()
	}
	dstKey := ep.DstToString()
	if srcIP == nil {
		if cached, ok := b.srcIPCache.Load(dstKey); ok {
			srcIP = cached.(net.IP)
		}
	}
	if srcIP == nil {
		conn, err := net.Dial("udp4", dstKey)
		if err == nil {
			if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
				srcIP = udpAddr.IP.To4()
				if srcIP != nil {
					b.srcIPCache.Store(dstKey, srcIP)
				}
			}
			conn.Close()
		}
	}
	if srcIP == nil {
		return fmt.Errorf("cannot resolve valid outbound source IP for %s (fallback to standard send)", dstKey)
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

	var ipIDBuf [2]byte
	rand.Read(ipIDBuf[:])
	ipID := binary.BigEndian.Uint16(ipIDBuf[:])

	if b.cfg.Debug {
		b.logf("DEBUG: (evasion) [TRAVONET-WG] Flow: %s:%d -> %s:%d (IP ID: 0x%04x)\n",
			srcIP.String(), srcPort, dstAddrPort.Addr().String(), dstPort, ipID)
	}

	fullUDPDatagramLen := UDPHeaderSize + len(wgPayload)
	udpHeader := make([]byte, UDPHeaderSize)
	binary.BigEndian.PutUint16(udpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udpHeader[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(fullUDPDatagramLen))
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)

	udpChecksum := computeUDPChecksum(srcIP, dstIP, udpHeader, wgPayload)
	binary.BigEndian.PutUint16(udpHeader[6:8], udpChecksum)

	fullDatagram := append(udpHeader, wgPayload...)
	currentOffset := 0

	strategy := b.cfg.compiledStrategy
	if strategy == nil {
		strategy = DefaultStrategy(b.cfg.FakeTTL, b.cfg.NormalTTL)
	}

	hasFrag := false
	for _, s := range strategy.Steps {
		if s.Action == ActionFrag {
			hasFrag = true
			break
		}
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
				b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] Sent Pre-Junk UDP packet (%d bytes, Badsum=%v)\n",
					i+1, len(strategy.Steps), len(junkPayload), step.Badsum)
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

			fragPayload := fullDatagram[offset : offset+length]
			mf := step.MF
			if step.AutoMF {
				mf = (offset + length) < len(fullDatagram)
			}

			ttl := step.TTL
			if ttl <= 0 {
				ttl = b.cfg.NormalTTL
			}

			fragPkt := buildIPv4Packet(srcIP, dstIP, ipID, ttl, mf, offset, fragPayload)
			if err := sendRawPacket(rawFd, dstIP, fragPkt); err != nil {
				return fmt.Errorf("step %d (frag) send: %w", i+1, err)
			}
			if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] Sent FRAG [%d..%d] (MF=%v, TTL=%d)\n",
					i+1, len(strategy.Steps), offset, offset+length, mf, ttl)
			}
			currentOffset = offset + length

		case ActionFakeFrag:
			var fakePayload []byte
			switch strings.ToLower(step.Payload) {
			case "zeros":
				fakePayload = make([]byte, step.Length)
			case "random", "":
				fakePayload = make([]byte, step.Length)
				rand.Read(fakePayload)
			default:
				fakePayload = make([]byte, step.Length)
				rand.Read(fakePayload)
			}

			ttl := step.TTL
			if ttl <= 0 {
				ttl = b.cfg.FakeTTL
			}

			fakePkt := buildIPv4Packet(srcIP, dstIP, ipID, ttl, step.MF, step.Offset, fakePayload)
			if err := sendRawPacket(rawFd, dstIP, fakePkt); err != nil {
				return fmt.Errorf("step %d (fake_frag) send: %w", i+1, err)
			}
			if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] Sent FAKE FRAG [%d..%d] (MF=%v, TTL=%d) [DPI Desync]\n",
					i+1, len(strategy.Steps), step.Offset, step.Offset+step.Length, step.MF, ttl)
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
				b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] Sent FAKE UDP packet (%d bytes payload, TTL=%d, Badsum=%v)\n",
					i+1, len(strategy.Steps), len(fakePayload), ttl, step.Badsum)
			}

		case ActionSleep:
			if step.SleepDur > 0 {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] Sleeping %v\n", i+1, len(strategy.Steps), step.SleepDur)
				}
				time.Sleep(step.SleepDur)
			}
		}
	}

	if !hasFrag {
		fullPkt := buildIPv4Packet(srcIP, dstIP, ipID, b.cfg.NormalTTL, false, 0, fullDatagram)
		if err := sendRawPacket(rawFd, dstIP, fullPkt); err != nil {
			return fmt.Errorf("legitimate handshake send failed: %w", err)
		}
		if b.cfg.Debug {
			b.logf("DEBUG: (evasion) [TRAVONET-WG] Sent Full Legitimate Handshake packet (%d bytes, TTL=%d) to %s\n",
				len(fullDatagram), b.cfg.NormalTTL, ep.DstToString())
		}
	}

	return nil
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
	pkt[9] = ipProtoUDP
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
	sum += uint32(ipProtoUDP)
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
