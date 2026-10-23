//go:build android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package main

/*
#cgo LDFLAGS: -llog
#include <jni.h>
#include <android/log.h>
#include <stdlib.h>

// Implemented in jni.c. c_has_vpn_service/c_protect_socket are called from Go;
// wgNotifySocketProtected is implemented in Go and called from jni.c.
extern int c_has_vpn_service(void);
extern int c_protect_socket(int fd);
extern void wgNotifySocketProtected(int handle);
*/
import "C"

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conf"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/proxy"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type AndroidLogger struct {
	level C.int
	tag   string
}

func (l AndroidLogger) Printf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	cTag := C.CString(l.tag)
	cMsg := C.CString(msg)
	C.__android_log_write(l.level, cTag, cMsg)
	C.free(unsafe.Pointer(cTag))
	C.free(unsafe.Pointer(cMsg))
}

type TunnelHandle struct {
	device *device.Device
	bind   *conn.EvasionBind
}

type Socks5Handle struct {
	server *proxy.SOCKS5Server
	device *device.Device
}

var (
	tunnelMu         sync.Mutex
	tunnelHandles    = make(map[int32]TunnelHandle)
	nextTunnelHandle int32

	socksMu         sync.Mutex
	socksHandles    = make(map[int32]*Socks5Handle)
	nextSocksHandle int32
)

func init() {
	// Wire VpnService.protect(fd) into the socket creation path. This runs
	// before bind() and before the first datagram is sent, eliminating the
	// routing loop caused by the 0.0.0.0/0 -> tun0 route.
	conn.SetSocketProtector(func(fd int) error {
		if C.c_protect_socket(C.int(fd)) != 0 {
			return fmt.Errorf("VpnService.protect(%d) failed", fd)
		}
		return nil
	})

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for range signals {
			n := runtime.Stack(buf, true)
			if n == len(buf) {
				n--
			}
			buf[n] = 0
			cTag := C.CString("TravonetWG/Stacktrace")
			cMsg := C.CString(string(buf[:n]))
			C.__android_log_write(C.ANDROID_LOG_ERROR, cTag, cMsg)
			C.free(unsafe.Pointer(cTag))
			C.free(unsafe.Pointer(cMsg))
		}
	}()
}

// parseSettings parses incoming configuration (either a standard WireGuard
// .conf or a UAPI blob) and extracts the evasion options without breaking the
// WireGuard UAPI parser.
//
// PersistentKeepalive is a peer-level UAPI key, so it is kept inside the peer
// section it belongs to; hoisting a single value to the end of the stream would
// silently drop the keepalives of all but the last peer.
func parseSettings(settings string, logger *device.Logger) (cleanUapi string, evasionCfg conn.EvasionConfig, endpoint string, mtu int, err error) {
	evasionCfg = conn.DefaultEvasionConfig()
	evasionCfg.LogFunc = logger.Verbosef
	mtu = 1280

	if strings.Contains(strings.ToLower(settings), "[interface]") {
		parsed, parseErr := conf.ParseConfigString(settings)
		if parseErr != nil {
			return "", evasionCfg, "", 0, fmt.Errorf("failed to parse WireGuard .conf: %w", parseErr)
		}
		if parsed.Strategy != "" {
			evasionCfg.Strategy = parsed.Strategy
		}
		if parsed.FakeTTL != 0 {
			evasionCfg.FakeTTL = parsed.FakeTTL
		}
		if parsed.NormalTTL > 0 {
			evasionCfg.NormalTTL = parsed.NormalTTL
		}
		if parsed.PreJunkSize > 0 {
			evasionCfg.PreJunkSize = parsed.PreJunkSize
		}
		if parsed.NoEvasion {
			evasionCfg.Enabled = false
		}
		if parsed.DebugSet {
			evasionCfg.Debug = parsed.Debug
		}
		if parsed.MTU > 0 {
			mtu = parsed.MTU
		}

		uapi, genErr := parsed.ToUAPI()
		if genErr != nil {
			return "", evasionCfg, "", 0, fmt.Errorf("failed to generate UAPI: %w", genErr)
		}
		logger.Verbosef("Parsed .conf settings (strategy=%q, fake_ttl=%d, normal_ttl=%d, pre_junk=%d, evasion=%v, mtu=%d)",
			evasionCfg.Strategy, evasionCfg.FakeTTL, evasionCfg.NormalTTL, evasionCfg.PreJunkSize, evasionCfg.Enabled, mtu)
		return uapi, evasionCfg, parsed.Endpoint, mtu, nil
	}

	// UAPI format: filter custom evasion parameters and AmneziaWG keys while
	// preserving per-peer keepalives.
	cleanUapi, ev := conf.FilterUAPI(settings)

	if ev.HasStrategy {
		evasionCfg.Strategy = ev.Strategy
	}
	if ev.HasFakeTTL {
		evasionCfg.FakeTTL = ev.FakeTTL
	}
	if ev.HasNormalTTL {
		evasionCfg.NormalTTL = ev.NormalTTL
	}
	if ev.HasPreJunkSize {
		evasionCfg.PreJunkSize = ev.PreJunkSize
	}
	if ev.HasEnabled {
		evasionCfg.Enabled = ev.Enabled
	}
	if ev.HasDebug {
		evasionCfg.Debug = ev.Debug
	}
	if ev.HasMTU {
		mtu = ev.MTU
	}

	logger.Verbosef("Parsed UAPI settings (strategy=%q, fake_ttl=%d, normal_ttl=%d, pre_junk=%d, evasion=%v, keepalive=%ds, mtu=%d)",
		evasionCfg.Strategy, evasionCfg.FakeTTL, evasionCfg.NormalTTL, evasionCfg.PreJunkSize, evasionCfg.Enabled, ev.PersistentKeepalive, mtu)

	return cleanUapi, evasionCfg, ev.Endpoint, mtu, nil
}

// startAutoFakeTTLProbe resolves FakeTTL=auto in the background.
//
// The kernel-assisted probe can take up to ~0.7s and performs a DNS lookup.
// Blocking wgTurnOn on it would freeze the Java caller thread (ANR) and delay
// the whole tunnel, so decoys start with the safe platform fallback and are
// refined as soon as the probe finishes: the compiled strategy resolves its
// decoy TTL at send time, so no restart is needed.
func startAutoFakeTTLProbe(bind *conn.EvasionBind, endpoint string, logger *device.Logger) {
	if bind == nil || endpoint == "" {
		return
	}
	go func() {
		hops, recommended, probeErr := conn.MeasureTargetTTL(endpoint)
		if recommended > 0 {
			bind.SetFakeTTL(recommended)
		}
		if probeErr != nil {
			logger.Verbosef("AutoTTL probe failed (%v), keeping safe FakeTTL=%d", probeErr, bind.FakeTTL())
			return
		}
		logger.Verbosef("AutoTTL: measured %d hops, using FakeTTL=%d", hops, bind.FakeTTL())
	}()
}

// isLoopbackListenAddr reports whether a listen address is only reachable from
// the device itself. An empty host means "all interfaces" and is not loopback.
func isLoopbackListenAddr(addr string) bool {
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return false
	}
	if host == "" {
		return false
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}

//export wgTurnOn
func wgTurnOn(interfaceName string, tunFd int32, settings string) int32 {
	tag := "TravonetWG/" + interfaceName
	logger := &device.Logger{
		Verbosef: AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: tag}.Printf,
		Errorf:   AndroidLogger{level: C.ANDROID_LOG_ERROR, tag: tag}.Printf,
	}

	cleanUapi, evasionCfg, endpoint, mtu, err := parseSettings(settings, logger)
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("parseSettings error: %v", err)
		return -1
	}
	autoFakeTTL := evasionCfg.FakeTTL < 0

	tunDev, name, err := tun.CreateUnmonitoredTUNFromFD(int(tunFd))
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("CreateUnmonitoredTUNFromFD: %v", err)
		return -1
	}

	if actualMTU, mtuErr := tunDev.MTU(); mtuErr == nil && actualMTU > 0 {
		mtu = actualMTU
	}

	// On Android, cellular networks (LTE/5G) often have path MTUs of 1280-1380 bytes
	// due to carrier GTP-U encapsulation. An MTU above 1280 causes silent packet
	// drops (PMTU black hole) on mobile data. Enforce 1280 for mobile carrier safety.
	if mtu > 1280 {
		logger.Verbosef("Clamping MTU from %d to 1280 for mobile network compatibility", mtu)
		mtu = 1280
	}

	logger.Verbosef("Attaching to interface %v (strategy=%s, fake_ttl=%d, mtu=%d, evasion=%v)",
		name, evasionCfg.Strategy, evasionCfg.FakeTTL, mtu, evasionCfg.Enabled)

	evasionBind := conn.NewEvasionBind(conn.NewStdNetBind(), evasionCfg)
	dev := device.NewDevice(tunDev, evasionBind, logger)
	dev.SetMTU(mtu)

	// Legacy embedders (unmodified WireGuard/AmneziaWG clients) call
	// wgGetSocketV4() + vpnService.protect(fd) only after wgTurnOn returns.
	// Arm the barrier so the first handshake cannot race the routing loop.
	if C.c_has_vpn_service() == 0 {
		evasionBind.RequireLegacySocketProtect()
	}

	// Bring the device up first: this opens and protects the UDP sockets before
	// any peer (and therefore any handshake) exists.
	if err = dev.Up(); err != nil {
		logger.Errorf("Unable to bring up device: %v", err)
		dev.Close()
		return -1
	}

	if err = dev.IpcSet(cleanUapi); err != nil {
		logger.Errorf("IpcSet: %v", err)
		dev.Close()
		return -1
	}
	// Roaming must remain enabled on Android so that peers can dynamically update
	// their endpoints when cellular radio handovers, NAT port-shifts, or Wi-Fi <->
	// mobile data switches happen. Do NOT disable roaming.

	if autoFakeTTL {
		startAutoFakeTTLProbe(evasionBind, endpoint, logger)
	}

	logger.Verbosef("TravonetWG device started")

	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	for attempts := 0; attempts < math.MaxInt32; attempts++ {
		nextTunnelHandle++
		if nextTunnelHandle <= 0 {
			nextTunnelHandle = 1
		}
		if _, exists := tunnelHandles[nextTunnelHandle]; !exists {
			tunnelHandles[nextTunnelHandle] = TunnelHandle{device: dev, bind: evasionBind}
			return nextTunnelHandle
		}
	}
	logger.Errorf("Unable to find empty handle")
	dev.Close()
	return -1
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	tunnelMu.Lock()
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		tunnelMu.Unlock()
		return
	}
	delete(tunnelHandles, tunnelHandle)
	tunnelMu.Unlock()

	handle.device.Close()
}

//export wgGetSocketV4
func wgGetSocketV4(tunnelHandle int32) int32 {
	tunnelMu.Lock()
	handle, ok := tunnelHandles[tunnelHandle]
	tunnelMu.Unlock()
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	// Give the Java thread time to finish vpnService.protect(fd), then release
	// the legacy protection barrier so a waiting handshake can proceed.
	if handle.bind != nil {
		go func() {
			time.Sleep(50 * time.Millisecond)
			handle.bind.NotifySocketProtected()
		}()
	}
	return int32(fd)
}

//export wgGetSocketV6
func wgGetSocketV6(tunnelHandle int32) int32 {
	tunnelMu.Lock()
	handle, ok := tunnelHandles[tunnelHandle]
	tunnelMu.Unlock()
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	if handle.bind != nil {
		go func() {
			time.Sleep(50 * time.Millisecond)
			handle.bind.NotifySocketProtected()
		}()
	}
	return int32(fd)
}

//export wgNotifySocketProtected
func wgNotifySocketProtected(tunnelHandle int32) {
	tunnelMu.Lock()
	handle, ok := tunnelHandles[tunnelHandle]
	tunnelMu.Unlock()
	if ok && handle.bind != nil {
		handle.bind.NotifySocketProtected()
	}
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	tunnelMu.Lock()
	handle, ok := tunnelHandles[tunnelHandle]
	tunnelMu.Unlock()
	if !ok {
		return nil
	}
	settings, err := handle.device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgVersion
func wgVersion() *C.char {
	return C.CString("TravonetWG-1.11 (wireguard-go)")
}

//export wgStartSocks5
func wgStartSocks5(listenAddr string, settings string) int32 {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080"
	}
	tag := "TravonetWG/SOCKS5"
	logger := &device.Logger{
		Verbosef: AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: tag}.Printf,
		Errorf:   AndroidLogger{level: C.ANDROID_LOG_ERROR, tag: tag}.Printf,
	}

	cleanUapi, evasionCfg, endpoint, mtu, err := parseSettings(settings, logger)
	if err != nil {
		logger.Errorf("parseSettings error: %v", err)
		return -1
	}
	autoFakeTTL := evasionCfg.FakeTTL < 0

	var localIPs []netip.Addr
	var dnsIPs []netip.Addr
	var socksAuth string
	if parsed, parseErr := conf.ParseConfigString(settings); parseErr == nil {
		if parsed.SocksAuth != "" {
			socksAuth = parsed.SocksAuth
		}
		for _, a := range parsed.Addresses {
			addrStr := a
			if idx := strings.Index(addrStr, "/"); idx > 0 {
				addrStr = addrStr[:idx]
			}
			if ip, ipErr := netip.ParseAddr(addrStr); ipErr == nil {
				localIPs = append(localIPs, ip)
			}
		}
		for _, d := range parsed.DNS {
			if ip, ipErr := netip.ParseAddr(d); ipErr == nil {
				dnsIPs = append(dnsIPs, ip)
			}
		}
		if parsed.MTU > 0 {
			mtu = parsed.MTU
		}
	}
	if len(localIPs) == 0 {
		localIPs = []netip.Addr{netip.MustParseAddr("172.16.0.2")}
	}
	if len(dnsIPs) == 0 {
		dnsIPs = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}

	// Validate the proxy exposure before allocating any tunnel resources.
	var socksUser, socksPass string
	haveSocksAuth := false
	if socksAuth != "" {
		user, pass, cutOK := strings.Cut(socksAuth, ":")
		if !cutOK || user == "" || pass == "" {
			logger.Errorf("Invalid SocksAuth (expected USER:PASS)")
			return -1
		}
		socksUser, socksPass, haveSocksAuth = user, pass, true
	}
	if !isLoopbackListenAddr(listenAddr) && !haveSocksAuth {
		logger.Errorf("Refusing to expose the SOCKS5 proxy on %s without authentication; set SocksAuth = USER:PASS", listenAddr)
		return -1
	}

	if mtu > 1280 {
		mtu = 1280
	}

	tunDev, tnet, err := netstack.CreateNetTUN(localIPs, dnsIPs, mtu)
	if err != nil {
		logger.Errorf("CreateNetTUN: %v", err)
		return -1
	}

	evasionBind := conn.NewEvasionBind(conn.NewStdNetBind(), evasionCfg)
	dev := device.NewDevice(tunDev, evasionBind, logger)
	dev.SetMTU(mtu)

	// Open sockets before configuring peers, mirroring the VpnService path.
	if err := dev.Up(); err != nil {
		logger.Errorf("dev.Up: %v", err)
		dev.Close()
		return -1
	}
	if err := dev.IpcSet(cleanUapi); err != nil {
		logger.Errorf("IpcSet: %v", err)
		dev.Close()
		return -1
	}
	// Keep roaming enabled for mobile networks.

	if autoFakeTTL {
		startAutoFakeTTLProbe(evasionBind, endpoint, logger)
	}

	socksServer := proxy.NewSOCKS5Server(listenAddr, tnet.DialContext)
	socksServer.Debug = evasionCfg.Debug
	socksServer.Logf = logger.Verbosef
	if haveSocksAuth {
		socksServer.SetAuth(socksUser, socksPass)
		logger.Verbosef("SOCKS5 authentication enabled")
	}

	// Bind synchronously so a busy port is reported to the caller instead of
	// being discovered asynchronously in a goroutine.
	if listenErr := socksServer.Listen(); listenErr != nil {
		logger.Errorf("SOCKS5 listen failed: %v", listenErr)
		dev.Close()
		return -1
	}
	go func() {
		if serveErr := socksServer.Serve(); serveErr != nil {
			logger.Errorf("SOCKS5 server: %v", serveErr)
		}
	}()

	logger.Verbosef("SOCKS5 proxy listening on %s (WireGuard peer connected)", socksServer.Addr())

	socksMu.Lock()
	defer socksMu.Unlock()
	for attempts := 0; attempts < math.MaxInt32; attempts++ {
		nextSocksHandle++
		if nextSocksHandle <= 0 {
			nextSocksHandle = 1
		}
		if _, exists := socksHandles[nextSocksHandle]; !exists {
			socksHandles[nextSocksHandle] = &Socks5Handle{
				server: socksServer,
				device: dev,
			}
			return nextSocksHandle
		}
	}
	_ = socksServer.Close()
	dev.Close()
	return -1
}

//export wgStopSocks5
func wgStopSocks5(socksHandle int32) {
	socksMu.Lock()
	handle, ok := socksHandles[socksHandle]
	if !ok {
		socksMu.Unlock()
		return
	}
	delete(socksHandles, socksHandle)
	socksMu.Unlock()

	_ = handle.server.Close()
	handle.device.Close()
}

//export wgGetSocks5SocketV4
func wgGetSocks5SocketV4(socksHandle int32) int32 {
	socksMu.Lock()
	handle, ok := socksHandles[socksHandle]
	socksMu.Unlock()
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export wgGetSocks5SocketV6
func wgGetSocks5SocketV6(socksHandle int32) int32 {
	socksMu.Lock()
	handle, ok := socksHandles[socksHandle]
	socksMu.Unlock()
	if !ok {
		return -1
	}
	bind, _ := handle.device.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		return -1
	}
	fd, err := bind.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	return int32(fd)
}

func main() {}
