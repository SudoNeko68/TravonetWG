/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// WGHandshakeInitiationSize is the fixed size of a WireGuard handshake
	// initiation message (type 0x01).
	WGHandshakeInitiationSize = 148
)

// EvasionConfig configures the unprivileged userspace DPI evasion engine.
type EvasionConfig struct {
	Enabled       bool                         // Enable userspace DPI evasion
	FakeTTL       int                          // TTL for decoy handshake packets (default: auto/5)
	PreJunkSize   int                          // Size in bytes of the pre-junk UDP datagram (0 to disable)
	NormalTTL     int                          // TTL for the legitimate handshake and transport packets
	Strategy      string                       // People DSL pipeline (e.g. "junk(64) -> fake_udp(148)")
	Debug         bool                         // Enable verbose evasion debugging logs
	VerbosePacket bool                         // Log every data packet
	LogFunc       func(string, ...interface{}) // Optional custom logger (e.g. Android logcat)

	compiledStrategy *Strategy
}

func DefaultEvasionConfig() EvasionConfig {
	return EvasionConfig{
		Enabled:       true,
		FakeTTL:       -1, // -1 = auto (kernel probe) with a safe fallback
		PreJunkSize:   64,
		NormalTTL:     64,
		Strategy:      "default",
		Debug:         true,
		VerbosePacket: false,
	}
}

// EvasionBind wraps a standard Bind and intercepts Handshake Initiation packets.
// It only uses ordinary unprivileged UDP sockets, so it works inside an Android
// VpnService without CAP_NET_RAW.
type EvasionBind struct {
	Bind
	cfg        EvasionConfig
	mu         sync.RWMutex
	actualPort uint16
	autoPort   bool // last Open() used a kernel-assigned (dynamic) port

	// sendMu serializes all sends on the underlying socket. IP_OPTIONS has to
	// be applied with setsockopt (it is not portable as a cmsg), so two
	// concurrent sends could otherwise leak a decoy's options into a transport
	// packet. It also guarantees that the decoy pipeline is emitted in order.
	sendMu sync.Mutex

	// fakeTTL is the live TTL used for decoy packets. It starts at the
	// configured value and can be updated at runtime once the Android AutoTTL
	// probe (which runs in the background) has a result.
	fakeTTL atomic.Int32

	// Legacy (non-VpnService-aware) clients call vpnService.protect(fd) only
	// after wgTurnOn returns. This gate delays the first send slightly so the
	// socket can be protected before any handshake leaves the device.
	protectMu   sync.Mutex
	protectWait chan struct{}

	// handshakeSeq counts handshake attempts and drives IP option rotation.
	handshakeSeq atomic.Uint32
}

func (b *EvasionBind) logf(format string, args ...interface{}) {
	if b.cfg.LogFunc != nil {
		b.cfg.LogFunc(format, args...)
	} else {
		fmt.Printf(format, args...)
	}
}

// defaultFakeTTLForPlatform returns the safe fallback FakeTTL used on Android
// when the network distance cannot be probed. On cellular networks (LTE/5G),
// the internal routing path through eNodeB -> SGW -> PGW -> Carrier Core to the
// border TSPU is 4-6 hops, so FakeTTL=7 ensures the decoy reaches TSPU while
// still safely expiring before foreign servers (12-20 hops).
func defaultFakeTTLForPlatform() int {
	return 7
}

// RequireLegacySocketProtect arms the protection barrier. It is used when the
// embedding application does not pass its VpnService to the native layer and
// therefore can only call protect(fd) after wgTurnOn returns.
func (b *EvasionBind) RequireLegacySocketProtect() {
	b.protectMu.Lock()
	if b.protectWait == nil {
		b.protectWait = make(chan struct{})
	}
	b.protectMu.Unlock()
}

// NotifySocketProtected releases the protection barrier. It is idempotent and
// safe to call when no barrier is armed.
func (b *EvasionBind) NotifySocketProtected() {
	b.protectMu.Lock()
	ch := b.protectWait
	b.protectWait = nil
	b.protectMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

// waitIfLegacyProtectPending blocks the first send until the application had a
// chance to protect the socket, or until a short timeout expires.
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
		// Disarm after the first timeout so subsequent sends are not stalled
		// repeatedly by an application that never notifies us.
		b.protectMu.Lock()
		if b.protectWait == ch {
			b.protectWait = nil
		}
		b.protectMu.Unlock()
	}
}

var (
	_ Bind                = (*EvasionBind)(nil)
	_ PeekLookAtSocketFd  = (*EvasionBind)(nil)
	_ SocketTTLController = (*EvasionBind)(nil)
)

// PeekLookAtSocketFd4 forwards to the underlying bind if supported.
// Crucial for Android VpnService.protect(socket).
func (b *EvasionBind) PeekLookAtSocketFd4() (int, error) {
	if peeker, ok := b.Bind.(PeekLookAtSocketFd); ok {
		return peeker.PeekLookAtSocketFd4()
	}
	return -1, errors.New("underlying bind does not implement PeekLookAtSocketFd")
}

// PeekLookAtSocketFd6 forwards to the underlying bind if supported.
func (b *EvasionBind) PeekLookAtSocketFd6() (int, error) {
	if peeker, ok := b.Bind.(PeekLookAtSocketFd); ok {
		return peeker.PeekLookAtSocketFd6()
	}
	return -1, errors.New("underlying bind does not implement PeekLookAtSocketFd")
}

// SetIPv4TTL sets the IP_TTL on the underlying socket for userspace evasion.
func (b *EvasionBind) SetIPv4TTL(ttl int) error {
	if ctrl, ok := b.Bind.(SocketTTLController); ok {
		return ctrl.SetIPv4TTL(ttl)
	}
	return errors.New("underlying bind does not support setting TTL")
}

// IsAutoPort reports whether the current UDP socket uses a kernel-assigned
// (dynamic) local port. It is used by the handshake retry logic to decide
// whether the port may be rotated safely to evade a blocked 4-tuple.
func (b *EvasionBind) IsAutoPort() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.autoPort
}

// SetFakeTTL updates the TTL used by decoy packets. It is safe to call while
// the device is running: the value is read for every handshake, so a
// background AutoTTL probe can refine it without restarting the tunnel.
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

// resolveFakeTTL returns the TTL to use for a decoy step. A step TTL of 0 means
// "use the live FakeTTL", which lets the AutoTTL probe take effect without
// recompiling the strategy.
func (b *EvasionBind) resolveFakeTTL(stepTTL int) int {
	if stepTTL > 0 {
		return stepTTL
	}
	if ttl := b.FakeTTL(); ttl > 0 {
		return ttl
	}
	return defaultFakeTTLForPlatform()
}

// NewEvasionBind wraps any Bind with the userspace DPI desync engine.
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

	strat, err := ParseStrategy(cfg.Strategy)
	if err != nil {
		if cfg.Debug {
			log.Printf("[TRAVONET-WG] Invalid strategy '%s': %v (falling back to default-userspace)", cfg.Strategy, err)
		}
		strat = DefaultUserspaceStrategy()
	}

	b := &EvasionBind{
		Bind: base,
		cfg:  cfg,
	}
	b.cfg.compiledStrategy = strat
	b.cfg.FakeTTL = fakeTTL
	b.fakeTTL.Store(int32(fakeTTL))

	if cfg.Debug {
		if cfg.Enabled {
			b.logf("DEBUG: (evasion) [TRAVONET-WG] Active userspace evasion strategy: %s\n", strat.String())
		} else {
			b.logf("DEBUG: (evasion) [TRAVONET-WG] Evasion disabled (NoEvasion), using plain WireGuard\n")
		}
		for _, w := range strat.Warnings {
			b.logf("DEBUG: (evasion) [TRAVONET-WG] Strategy warning: %s\n", w)
		}
	}

	return b
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
		// An explicit listen_port was configured; do not rotate it behind the
		// application's back.
		b.autoPort = false
	}
	b.actualPort = actualPort
	b.mu.Unlock()

	if b.cfg.Debug {
		b.logf("DEBUG: (evasion) [TRAVONET-WG] Socket bound to local port %d\n", actualPort)
	}

	// Wrap each ReceiveFunc to monitor incoming packets in debug mode.
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
				if sz >= 4 && len(packets[j]) >= 4 {
					msgType := packets[j][0]
					switch msgType {
					case 2: // Handshake Response (92 bytes)
						b.logf("DEBUG: (evasion) [TRAVONET-WG] <<< HANDSHAKE RESPONSE (Type 2, %d bytes) from %s\n", sz, eps[j].DstToString())
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
	return b.Bind.Close()
}

func (b *EvasionBind) Send(bufs [][]byte, ep Endpoint) error {
	// Serialize sends on this socket: IP_OPTIONS and the jumbo fallback mutate
	// per-socket state, and decoy packets must never be reordered after the
	// legitimate handshake they are meant to precede.
	b.sendMu.Lock()
	defer b.sendMu.Unlock()

	// Legacy embedders can only protect the socket after wgTurnOn returns.
	b.waitIfLegacyProtectPending()

	// If evasion is disabled or this is an IPv6 endpoint, use the standard
	// send path. The Android userspace engine is IPv4-only.
	if !b.cfg.Enabled || ep.DstIP().Is6() {
		return b.Bind.Send(bufs, ep)
	}

	var standardBufs [][]byte
	for _, buf := range bufs {
		// WireGuard Handshake Initiation is strictly 148 bytes with Type = 0x01.
		if len(buf) == WGHandshakeInitiationSize && buf[0] == 0x01 {
			if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] >>> Handshake Initiation detected (148 bytes) to %s\n", ep.DstToString())
			}

			if err := b.sendUserspaceObfuscatedHandshake(ep, buf); err != nil {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG] Evasion send failed: %v (falling back to standard send)\n", err)
				}
				standardBufs = append(standardBufs, buf)
			} else if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] Evasion sequence sent successfully to %s\n", ep.DstToString())
			}
		} else {
			// Type 4 transport data or keepalives: fast path.
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

// sendUserspaceObfuscatedHandshake executes the unprivileged UDP desync
// pipeline. It uses per-packet cmsg IP_TTL / IP_OPTIONS when the active UDP
// socket descriptor is available (Android/Linux) and falls back to temporary
// setsockopt TTL changes otherwise.
func (b *EvasionBind) sendUserspaceObfuscatedHandshake(ep Endpoint, wgPayload []byte) error {
	strategy := b.userspaceStrategy()
	if strategy == nil || len(strategy.Steps) == 0 {
		return b.Bind.Send([][]byte{wgPayload}, ep)
	}

	fd, dstIP, dstPort, haveFd := b.userspaceSocket(ep)
	seq := b.handshakeSeq.Add(1)

	if b.cfg.Debug {
		b.logf("DEBUG: (evasion) [TRAVONET-WG] Executing userspace UDP desync (%d steps, seq=%d, cmsg=%v) to %s\n",
			len(strategy.Steps), seq, haveFd, ep.DstToString())
	}

	hasJunk := false
	ipOptShift := 0
	ipOptMode := "nop"
	for _, step := range strategy.Steps {
		switch step.Action {
		case ActionJunk:
			hasJunk = true
		case ActionIPOptShift:
			ipOptShift = step.Length
			if step.IPOptMode != "" {
				ipOptMode = step.IPOptMode
			}
		}
	}

	// PreJunk is honored even when the strategy does not contain an explicit
	// junk() step (legacy "default" strategies).
	if !hasJunk && b.cfg.PreJunkSize > 0 {
		junk := make([]byte, b.cfg.PreJunkSize)
		randRead(junk)
		if err := b.sendUserspacePacket(ep, fd, dstIP, dstPort, junk, b.cfg.NormalTTL, ""); err != nil {
			b.logf("DEBUG: (evasion) [TRAVONET-WG]   Userspace PreJunk send error: %v\n", err)
		} else if b.cfg.Debug {
			b.logf("DEBUG: (evasion) [TRAVONET-WG]   Sent Userspace Pre-Junk UDP packet (%d bytes)\n", len(junk))
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
			randRead(junkPayload)
			ttl := step.TTL
			if ttl <= 0 {
				ttl = b.cfg.NormalTTL
			}
			if err := b.sendUserspacePacket(ep, fd, dstIP, dstPort, junkPayload, ttl, ""); err != nil {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] Userspace junk send error: %v\n", i+1, len(strategy.Steps), err)
				}
			} else if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] Sent Userspace Pre-Junk UDP packet (%d bytes)\n",
					i+1, len(strategy.Steps), len(junkPayload))
			}

		case ActionMimic:
			mimicPayload := buildMimicPacket(step.MimicProto)
			ttl := step.TTL
			if ttl <= 0 {
				ttl = b.cfg.NormalTTL
			}
			if err := b.sendUserspacePacket(ep, fd, dstIP, dstPort, mimicPayload, ttl, ""); err != nil {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] mimic(%s) send error: %v\n", i+1, len(strategy.Steps), step.MimicProto, err)
				}
			} else if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] Sent mimic(%s) packet (%d bytes, TTL=%d)\n",
					i+1, len(strategy.Steps), step.MimicProto, len(mimicPayload), ttl)
			}

		case ActionJumboFake:
			jumboPayload := buildJumboFakePayload(step.Length)
			ttl := b.resolveFakeTTL(step.TTL)
			if err := b.sendUserspacePacket(ep, fd, dstIP, dstPort, jumboPayload, ttl, ""); err != nil {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] jumbo_fake send error: %v\n", i+1, len(strategy.Steps), err)
				}
			} else if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] Sent JUMBO FAKE (%d bytes, TTL=%d)\n",
					i+1, len(strategy.Steps), len(jumboPayload), ttl)
			}

		case ActionFakeUDP:
			fakePayload := buildFakeHandshakePayload(step.Length, step.CorruptHeader)
			ttl := b.resolveFakeTTL(step.TTL)
			ipMode := step.IPOptMode
			if err := b.sendUserspacePacket(ep, fd, dstIP, dstPort, fakePayload, ttl, ipMode); err != nil {
				if b.cfg.Debug {
					b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] fake_udp send error: %v\n", i+1, len(strategy.Steps), err)
				}
			} else if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] Sent Userspace FAKE UDP packet (%d bytes, TTL=%d, corrupt=%v, ipopt=%s)\n",
					i+1, len(strategy.Steps), len(fakePayload), ttl, step.CorruptHeader, ipMode)
			}

		case ActionIPOptShift:
			// No packet of its own: the shift is applied to the legitimate
			// handshake on odd attempts only (see below).
			if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG]   [%d/%d] ipopt_shift(%d, mode=%s) armed for handshake\n",
					i+1, len(strategy.Steps), step.Length, ipOptMode)
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

	// Send the legitimate WireGuard Handshake Initiation with NormalTTL.
	// On odd attempts an IP option shift is applied, on even attempts a plain
	// 20-byte IPv4 header is used, in case provider routers drop IP_OPTIONS.
	if ipOptShift > 0 && seq%2 == 1 && haveFd {
		opts := ipOptionsForMode(ipOptMode, ipOptShift)
		if err := sendUDPWithTTLAndOptions(fd, dstIP, dstPort, wgPayload, b.cfg.NormalTTL, opts); err == nil {
			if b.cfg.Debug {
				b.logf("DEBUG: (evasion) [TRAVONET-WG] Sent Legitimate WireGuard Handshake (%d bytes, TTL=%d, ipopt_shift=%d) to %s\n",
					len(wgPayload), b.cfg.NormalTTL, ipOptShift, ep.DstToString())
			}
			return nil
		} else if b.cfg.Debug {
			b.logf("DEBUG: (evasion) [TRAVONET-WG] ipopt_shift handshake send failed: %v (retrying plain)\n", err)
		}
	}

	if err := b.sendUserspacePacket(ep, fd, dstIP, dstPort, wgPayload, b.cfg.NormalTTL, ""); err != nil {
		return fmt.Errorf("legitimate handshake send failed: %w", err)
	}

	if b.cfg.Debug {
		b.logf("DEBUG: (evasion) [TRAVONET-WG] Sent Legitimate WireGuard Handshake (%d bytes, TTL=%d) to %s\n",
			len(wgPayload), b.cfg.NormalTTL, ep.DstToString())
	}

	return nil
}

// userspaceStrategy returns the compiled strategy. The DSL only contains
// actions that can be executed with an ordinary unprivileged UDP socket.
func (b *EvasionBind) userspaceStrategy() *Strategy {
	strat := b.cfg.compiledStrategy
	if strat == nil || len(strat.Steps) == 0 {
		return DefaultUserspaceStrategy()
	}
	return strat
}

// userspaceSocket resolves the IPv4 destination and the active UDP socket
// descriptor used for per-packet cmsg sends.
func (b *EvasionBind) userspaceSocket(ep Endpoint) (fd int, dstIP [4]byte, dstPort int, ok bool) {
	if ep == nil || !ep.DstIP().Is4() {
		return -1, dstIP, 0, false
	}
	dstIP = ep.DstIP().As4()
	se, isStd := ep.(*StdNetEndpoint)
	if !isStd {
		return -1, dstIP, 0, false
	}
	dstPort = int(se.Port())
	if dstPort <= 0 || dstPort > 65535 {
		return -1, dstIP, 0, false
	}
	socketFd, err := b.PeekLookAtSocketFd4()
	if err != nil || socketFd < 0 {
		return -1, dstIP, dstPort, false
	}
	return socketFd, dstIP, dstPort, true
}

// sendUserspacePacket sends a single decoy/legit datagram. It prefers an
// atomic cmsg send with a per-packet TTL, and falls back to the generic Bind
// (with a temporary setsockopt TTL) when no descriptor is available.
func (b *EvasionBind) sendUserspacePacket(ep Endpoint, fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int, ipOptMode string) error {
	if ttl <= 0 {
		ttl = b.cfg.NormalTTL
	}

	if fd >= 0 {
		var err error
		if payloadIsJumbo(payload) {
			err = sendUDPJumbo(fd, dstIP, dstPort, payload, ttl)
		} else {
			var opts []byte
			if ipOptMode != "" && ipOptMode != "none" {
				opts = ipOptionsForMode(ipOptMode, 0)
			}
			err = sendUDPWithTTLAndOptions(fd, dstIP, dstPort, payload, ttl, opts)
		}
		if err == nil {
			return nil
		}
		if b.cfg.Debug {
			b.logf("DEBUG: (evasion) [TRAVONET-WG]   cmsg send failed: %v (falling back to bind send)\n", err)
		}
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

// jumboFragmentationThreshold is the payload size above which the kernel is
// asked to fragment the decoy datagram. Anything above a typical path MTU would
// otherwise fail with EMSGSIZE while PMTU discovery is active.
const jumboFragmentationThreshold = 1200

// payloadIsJumbo reports whether payload should use the oversized-datagram
// send path (kernel-side IPv4 fragmentation). Only jumbo_fake generates such
// payloads, and the threshold is deliberately lower than the smallest
// jumbo_fake size so an explicitly configured smaller payload still works.
func payloadIsJumbo(payload []byte) bool {
	return len(payload) > jumboFragmentationThreshold
}
