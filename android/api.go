//go:build android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
import "C"

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conf"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/proxy"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type AndroidLogger struct {
	level C.int
	tag   *C.char
}

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l AndroidLogger) Printf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	C.__android_log_write(l.level, l.tag, cstring(msg))
}

type TunnelHandle struct {
	device *device.Device
	uapi   net.Listener
	bind   *conn.EvasionBind
}

type Socks5Handle struct {
	server *proxy.SOCKS5Server
	device *device.Device
	bind   *conn.EvasionBind
}

var (
	tunnelMu      sync.Mutex
	tunnelHandles = make(map[int32]TunnelHandle)

	socksMu      sync.Mutex
	socksHandles = make(map[int32]*Socks5Handle)
)

func init() {
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
			C.__android_log_write(C.ANDROID_LOG_ERROR, cstring("TravonetWG/Stacktrace"), (*C.char)(unsafe.Pointer(&buf[0])))
		}
	}()
}

// parseSettings parses incoming configuration (either standard WG .conf or UAPI)
// and extracts evasion options without breaking WireGuard UAPI parser.
func parseSettings(settings string, logger *device.Logger) (cleanUapi string, evasionCfg conn.EvasionConfig, pka int, endpoint string, err error) {
	evasionCfg = conn.DefaultEvasionConfig()
	evasionCfg.LogFunc = logger.Verbosef

	lower := strings.ToLower(settings)
	if strings.Contains(lower, "[interface]") {
		parsed, err := conf.ParseConfigString(settings)
		if err != nil {
			return "", evasionCfg, 0, "", fmt.Errorf("failed to parse WireGuard .conf: %w", err)
		}
		if parsed.Strategy != "" {
			evasionCfg.Strategy = parsed.Strategy
		}
		if parsed.FakeTTL != 0 {
			evasionCfg.FakeTTL = parsed.FakeTTL
		}
		if parsed.PreJunkSize > 0 {
			evasionCfg.PreJunkSize = parsed.PreJunkSize
		}

		uapi, err := parsed.ToUAPI()
		if err != nil {
			return "", evasionCfg, 0, "", fmt.Errorf("failed to generate UAPI: %w", err)
		}
		return uapi, evasionCfg, parsed.PersistentKeepalive, parsed.Endpoint, nil
	}

	// UAPI format - filter custom evasion parameters
	var uapiLines []string
	scanner := bufio.NewScanner(strings.NewReader(settings))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			uapiLines = append(uapiLines, line)
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			uapiLines = append(uapiLines, line)
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		switch key {
		case "strategy":
			evasionCfg.Strategy = val
		case "fake_ttl", "fakettl":
			if strings.EqualFold(val, "auto") {
				evasionCfg.FakeTTL = -1
			} else if v, err := strconv.Atoi(val); err == nil {
				evasionCfg.FakeTTL = v
			}
		case "normal_ttl", "normalttl":
			if v, err := strconv.Atoi(val); err == nil {
				evasionCfg.NormalTTL = v
			}
		case "pre_junk", "prejunk", "prejunksize":
			if v, err := strconv.Atoi(val); err == nil {
				evasionCfg.PreJunkSize = v
			}
		case "no_evasion", "disable_evasion":
			if strings.EqualFold(val, "true") || val == "1" {
				evasionCfg.Enabled = false
			}
		case "endpoint":
			endpoint = val
			uapiLines = append(uapiLines, line)
		case "persistent_keepalive_interval":
			if v, err := strconv.Atoi(val); err == nil {
				pka = v
			}
			uapiLines = append(uapiLines, line)
		default:
			uapiLines = append(uapiLines, line)
		}
	}

	// Automatic PersistentKeepalive optimization for Android mobile networks and routers
	if conf.IsPort500Endpoint(endpoint) {
		if pka == 0 || pka > 10 {
			pka = 5
			uapiLines = append(uapiLines, fmt.Sprintf("persistent_keepalive_interval=%d", pka))
		}
	} else if pka == 0 {
		pka = 15
		uapiLines = append(uapiLines, fmt.Sprintf("persistent_keepalive_interval=%d", pka))
	}

	cleanUapi = strings.Join(uapiLines, "\n") + "\n"
	return cleanUapi, evasionCfg, pka, endpoint, nil
}

//export wgTurnOn
func wgTurnOn(interfaceName string, tunFd int32, settings string) int32 {
	tag := cstring("TravonetWG/" + interfaceName)
	logger := &device.Logger{
		Verbosef: AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: tag}.Printf,
		Errorf:   AndroidLogger{level: C.ANDROID_LOG_ERROR, tag: tag}.Printf,
	}

	cleanUapi, evasionCfg, pka, _, err := parseSettings(settings, logger)
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("parseSettings error: %v", err)
		return -1
	}

	tunDev, name, err := tun.CreateUnmonitoredTUNFromFD(int(tunFd))
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("CreateUnmonitoredTUNFromFD: %v", err)
		return -1
	}

	logger.Verbosef("Attaching to interface %v (strategy=%s, fake_ttl=%d, keepalive=%ds)",
		name, evasionCfg.Strategy, evasionCfg.FakeTTL, pka)

	evasionBind := conn.NewEvasionBind(conn.NewStdNetBind(), evasionCfg)
	dev := device.NewDevice(tunDev, evasionBind, logger)

	err = dev.IpcSet(cleanUapi)
	if err != nil {
		unix.Close(int(tunFd))
		logger.Errorf("IpcSet: %v", err)
		dev.Close()
		return -1
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()

	var uapi net.Listener
	uapiFile, err := ipc.UAPIOpen(name)
	if err != nil {
		logger.Verbosef("UAPIOpen (unprivileged): %v", err)
	} else {
		uapi, err = ipc.UAPIListen(name, uapiFile)
		if err != nil {
			uapiFile.Close()
			logger.Verbosef("UAPIListen: %v", err)
		} else {
			go func() {
				for {
					conn, err := uapi.Accept()
					if err != nil {
						return
					}
					go dev.IpcHandle(conn)
				}
			}()
		}
	}

	err = dev.Up()
	if err != nil {
		logger.Errorf("Unable to bring up device: %v", err)
		if uapiFile != nil {
			uapiFile.Close()
		}
		dev.Close()
		return -1
	}
	logger.Verbosef("TravonetWG device started")

	tunnelMu.Lock()
	defer tunnelMu.Unlock()
	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		logger.Errorf("Unable to find empty handle")
		if uapiFile != nil {
			uapiFile.Close()
		}
		dev.Close()
		return -1
	}
	tunnelHandles[i] = TunnelHandle{device: dev, uapi: uapi, bind: evasionBind}
	return i
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

	if handle.uapi != nil {
		handle.uapi.Close()
	}
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
	return int32(fd)
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
	return C.CString("TravonetWG-1.0 (wireguard-go)")
}

//export wgStartSocks5
func wgStartSocks5(listenAddr string, settings string) int32 {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080"
	}
	tag := cstring("TravonetWG/SOCKS5")
	logger := &device.Logger{
		Verbosef: AndroidLogger{level: C.ANDROID_LOG_DEBUG, tag: tag}.Printf,
		Errorf:   AndroidLogger{level: C.ANDROID_LOG_ERROR, tag: tag}.Printf,
	}

	cleanUapi, evasionCfg, pka, _, err := parseSettings(settings, logger)
	if err != nil {
		logger.Errorf("parseSettings error: %v", err)
		return -1
	}

	var localIPs []netip.Addr
	var dnsIPs []netip.Addr
	mtu := 1280
	if parsed, err := conf.ParseConfigString(settings); err == nil {
		for _, a := range parsed.Addresses {
			addrStr := a
			if idx := strings.Index(addrStr, "/"); idx > 0 {
				addrStr = addrStr[:idx]
			}
			if ip, err := netip.ParseAddr(addrStr); err == nil {
				localIPs = append(localIPs, ip)
			}
		}
		for _, d := range parsed.DNS {
			if ip, err := netip.ParseAddr(d); err == nil {
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

	tunDev, tnet, err := netstack.CreateNetTUN(localIPs, dnsIPs, mtu)
	if err != nil {
		logger.Errorf("CreateNetTUN: %v", err)
		return -1
	}

	evasionBind := conn.NewEvasionBind(conn.NewStdNetBind(), evasionCfg)
	dev := device.NewDevice(tunDev, evasionBind, logger)

	if err := dev.IpcSet(cleanUapi); err != nil {
		logger.Errorf("IpcSet: %v", err)
		dev.Close()
		return -1
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()

	if err := dev.Up(); err != nil {
		logger.Errorf("dev.Up: %v", err)
		dev.Close()
		return -1
	}

	socksServer := proxy.NewSOCKS5Server(listenAddr, tnet.DialContext)
	socksServer.Debug = true

	go func() {
		if err := socksServer.ListenAndServe(); err != nil && !strings.Contains(err.Error(), "closed") {
			logger.Errorf("SOCKS5 server: %v", err)
		}
	}()

	logger.Verbosef("SOCKS5 proxy listening on %s (WireGuard peer connected, keepalive: %ds)", listenAddr, pka)

	socksMu.Lock()
	defer socksMu.Unlock()
	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := socksHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		_ = socksServer.Close()
		dev.Close()
		return -1
	}

	socksHandles[i] = &Socks5Handle{
		server: socksServer,
		device: dev,
		bind:   evasionBind,
	}
	return i
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
