//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conf"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/proxy"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

func parseSocksAddr(val string) (string, bool) {
	val = strings.TrimSpace(val)
	if val == "" {
		return "127.0.0.1:1080", true
	}
	if p, err := strconv.Atoi(val); err == nil && p > 0 && p <= 65535 {
		return fmt.Sprintf("127.0.0.1:%d", p), true
	}
	if strings.HasPrefix(val, ":") {
		if p, err := strconv.Atoi(val[1:]); err == nil && p > 0 && p <= 65535 {
			return fmt.Sprintf("127.0.0.1:%d", p), true
		}
	}
	if host, port, err := net.SplitHostPort(val); err == nil {
		if p, err := strconv.Atoi(port); err == nil && p > 0 && p <= 65535 {
			if host == "" {
				return fmt.Sprintf("127.0.0.1:%d", p), true
			}
			return val, true
		}
	}
	return "", false
}

func isNonLoopbackAddress(addr string) (bool, string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true, fmt.Sprintf("proxy is bound to all network interfaces (%s)", addr)
	}
	if strings.EqualFold(host, "localhost") {
		return false, ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true, fmt.Sprintf("proxy is bound to an external address (%s)", addr)
	}
	if ip.IsLoopback() {
		return false, ""
	}
	if ip.IsPrivate() {
		return true, fmt.Sprintf("proxy is bound to local LAN (%s)", addr)
	}
	return true, fmt.Sprintf("proxy is bound to public IP (%s)", addr)
}

func isWindowsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

func printUsage() {
	fmt.Printf(`Usage: %s [OPTIONS] [INTERFACE-NAME]

TravonetWG (Windows Edition): WireGuard client with in-tree L3/L4 evasion engine
against TSPU / DPI filtering (Zapret-style Fake UDP + userspace desync).

Modes:
  Mode 1 (Userspace SOCKS5 Inbound - No Administrator / No Driver needed):
      Run pure userspace SOCKS5 proxy without admin privileges, driver, or routing changes:
          %s -c wg0.conf --socks
          %s -c wg0.conf --socks 127.0.0.1:1080
          %s -c wg0.conf --socks 1080

  Mode 2 (System TUN Adapter - Requires Administrator and wintun.dll):
      Create a system WireGuard network interface using Wintun:
          %s -c wg0.conf wg0
          %s -c wg0.conf --fake-ttl 10 wg0

Options:
  -c, --config FILE             Load WireGuard configuration file (.conf)
  --socks, --socks5 [ADDR:PORT] Start userspace SOCKS5 proxy (default: 127.0.0.1:1080)
  -s, --strategy DSL            Evasion pipeline DSL (default: "fake(148) -> frag(8) -> frag(72) -> fake(148) -> frag(76)")
  --fake-ttl N|auto             TTL for fake packets (number 1-255 or 'auto' for hop distance probe)
  --pre-junk N                  Size in bytes of initial junk UDP packet (default: 64, 0 to disable)
  --no-evasion                  Disable all evasion mechanisms (run as standard wireguard-go)
  -d, --debug                   Enable verbose debug logging
  -v, --verbose                 Log every transport data packet (verbose tracking)
  -f, --foreground              Run in foreground (default)
  -h, --help                    Show this help message
  --version                     Show version information
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func banner() {
	fmt.Fprintln(os.Stderr, "┌──────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "│   TravonetWG: Custom WireGuard with L3/L4 Evasion    │")
	fmt.Fprintln(os.Stderr, "│   Windows Edition (Wintun / Userspace SOCKS5)        │")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "└──────────────────────────────────────────────────────┘")
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("TravonetWG (wireguard-go v%s)\n\nCustom Userspace WireGuard with evasion for %s-%s.\n", Version, runtime.GOOS, runtime.GOARCH)
		return
	}

	banner()

	var debug bool
	var configFile string
	var interfaceName string
	evasionCfg := conn.DefaultEvasionConfig()

	// Environment variable overrides
	if os.Getenv("WG_DEBUG") == "1" || os.Getenv("TRAVONET_DEBUG") == "1" || os.Getenv("LOG_LEVEL") == "verbose" {
		debug = true
	}
	if os.Getenv("WG_NO_EVASION") == "1" {
		evasionCfg.Enabled = false
	}
	if strat := os.Getenv("WG_STRATEGY"); strat != "" {
		evasionCfg.Strategy = strat
	}
	if strat := os.Getenv("TRAVONET_STRATEGY"); strat != "" {
		evasionCfg.Strategy = strat
	}

	var cliFakeTTL int = 0
	var cliStrategy string
	var cliPreJunk int = -1
	var cliSocks5 string

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "-h", "--help", "-help":
			printUsage()
			return
		case "-f", "--foreground":
			// Default on Windows console
		case "-d", "--debug", "-debug":
			debug = true
		case "-v", "--verbose", "-verbose":
			debug = true
			evasionCfg.VerbosePacket = true
		case "--no-evasion":
			evasionCfg.Enabled = false
		case "-c", "--config", "-config":
			if i+1 < len(os.Args) {
				i++
				configFile = os.Args[i]
			}
		case "--socks5", "-socks5", "--socks", "-socks":
			cliSocks5 = "127.0.0.1:1080"
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				if parsedAddr, ok := parseSocksAddr(os.Args[i+1]); ok {
					cliSocks5 = parsedAddr
					i++
				}
			}
		case "-s", "--strategy", "-strategy":
			if i+1 < len(os.Args) {
				i++
				cliStrategy = os.Args[i]
			}
		case "--fake-ttl":
			if i+1 < len(os.Args) {
				i++
				if strings.EqualFold(os.Args[i], "auto") {
					cliFakeTTL = -1
				} else if ttl, err := strconv.Atoi(os.Args[i]); err == nil {
					cliFakeTTL = ttl
				}
			}
		case "--pre-junk":
			if i+1 < len(os.Args) {
				i++
				if sz, err := strconv.Atoi(os.Args[i]); err == nil {
					cliPreJunk = sz
				}
			}
		default:
			if strings.HasPrefix(arg, "--socks5=") || strings.HasPrefix(arg, "-socks5=") ||
				strings.HasPrefix(arg, "--socks=") || strings.HasPrefix(arg, "-socks=") {
				val := arg[strings.Index(arg, "=")+1:]
				if parsedAddr, ok := parseSocksAddr(val); ok {
					cliSocks5 = parsedAddr
				} else if val != "" {
					cliSocks5 = val
				} else {
					cliSocks5 = "127.0.0.1:1080"
				}
				continue
			}
			if strings.HasPrefix(arg, "-") {
				printUsage()
				return
			}
			interfaceName = arg
		}
	}

	var parsedConfig *conf.Config
	if configFile != "" {
		cfg, err := conf.ParseConfigFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing config file %s: %v\n", configFile, err)
			os.Exit(ExitSetupFailed)
			return
		}
		parsedConfig = cfg

		if interfaceName == "" {
			base := filepath.Base(configFile)
			ext := filepath.Ext(base)
			interfaceName = strings.TrimSuffix(base, ext)
			if len(interfaceName) > 15 {
				interfaceName = interfaceName[:15]
			}
		}

		if cfg.Strategy != "" {
			evasionCfg.Strategy = cfg.Strategy
		}
		if cfg.FakeTTL != 0 {
			evasionCfg.FakeTTL = cfg.FakeTTL
		}
		if cfg.PreJunkSize > 0 {
			evasionCfg.PreJunkSize = cfg.PreJunkSize
		}
	}

	if cliStrategy != "" {
		evasionCfg.Strategy = cliStrategy
	}
	if cliFakeTTL != 0 {
		evasionCfg.FakeTTL = cliFakeTTL
	}
	if cliPreJunk >= 0 {
		evasionCfg.PreJunkSize = cliPreJunk
	}

	// Auto-TTL resolution
	if evasionCfg.Enabled && evasionCfg.FakeTTL <= 0 {
		endpoint := ""
		if parsedConfig != nil && parsedConfig.Endpoint != "" {
			endpoint = parsedConfig.Endpoint
		}
		if endpoint != "" {
			if debug {
				fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] Measuring hop distance to endpoint %s...\n", endpoint)
			}
			totalHops, recommendedTTL, err := conn.MeasureTargetTTL(endpoint)
			if err == nil {
				evasionCfg.FakeTTL = recommendedTTL
				if debug {
					fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] Auto-measured %d hops to endpoint, setting FakeTTL = %d\n",
						totalHops, recommendedTTL)
				}
			} else {
				evasionCfg.FakeTTL = 11
				if debug {
					fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] Auto-measure failed: %v (falling back to FakeTTL = 11)\n", err)
				}
			}
		} else {
			evasionCfg.FakeTTL = 11
		}
	}

	var socks5Addr string
	if cliSocks5 != "" {
		socks5Addr = cliSocks5
	} else if parsedConfig != nil && parsedConfig.Socks5 != "" {
		if addr, ok := parseSocksAddr(parsedConfig.Socks5); ok {
			socks5Addr = addr
		} else {
			socks5Addr = parsedConfig.Socks5
		}
	}

	// Mode 1: Userspace SOCKS5 proxy (Works without Administrator rights and without Wintun)
	if socks5Addr != "" {
		if parsedConfig == nil {
			fmt.Fprintln(os.Stderr, "Error: SOCKS5 mode requires a WireGuard configuration file (-c config.conf)")
			os.Exit(ExitSetupFailed)
			return
		}

		runSocks5Windows(socks5Addr, parsedConfig, evasionCfg, debug)
		return
	}

	// Mode 2: System TUN mode (Requires Administrator rights and wintun.dll)
	if interfaceName == "" {
		printUsage()
		return
	}

	if !isWindowsAdmin() {
		fmt.Fprintln(os.Stderr, "================================================================================")
		fmt.Fprintln(os.Stderr, "Error: Running in TUN mode on Windows requires Administrator privileges!")
		fmt.Fprintln(os.Stderr, "Please run PowerShell or Command Prompt as Administrator.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Tip: To run without Administrator rights and without drivers, use SOCKS5 mode:")
		fmt.Fprintf(os.Stderr, "     %s -c %s --socks\n", os.Args[0], configFile)
		fmt.Fprintln(os.Stderr, "================================================================================")
		os.Exit(ExitSetupFailed)
		return
	}

	runTunWindows(interfaceName, parsedConfig, evasionCfg, debug)
}

func runSocks5Windows(socks5Addr string, parsedConfig *conf.Config, evasionCfg conn.EvasionConfig, debug bool) {
	if evasionCfg.Strategy != "" && evasionCfg.Strategy != "default" {
		if _, err := conn.ParseStrategy(evasionCfg.Strategy, evasionCfg.FakeTTL, evasionCfg.NormalTTL); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid evasion strategy: %v\n", err)
			os.Exit(ExitSetupFailed)
			return
		}
	}

	evasionCfg.Debug = debug

	var localIPs []netip.Addr
	for _, a := range parsedConfig.Addresses {
		addrStr := a
		if idx := strings.Index(addrStr, "/"); idx > 0 {
			addrStr = addrStr[:idx]
		}
		if ip, err := netip.ParseAddr(addrStr); err == nil {
			localIPs = append(localIPs, ip)
		}
	}
	if len(localIPs) == 0 {
		localIPs = []netip.Addr{netip.MustParseAddr("172.16.0.2")}
	}

	var dnsIPs []netip.Addr
	for _, d := range parsedConfig.DNS {
		if ip, err := netip.ParseAddr(d); err == nil {
			dnsIPs = append(dnsIPs, ip)
		}
	}
	if len(dnsIPs) == 0 {
		dnsIPs = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}

	mtu := parsedConfig.MTU
	if mtu <= 0 {
		mtu = 1280
	}

	tunDev, tnet, err := netstack.CreateNetTUN(localIPs, dnsIPs, mtu)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating netstack TUN: %v\n", err)
		os.Exit(ExitSetupFailed)
		return
	}

	logLevel := device.LogLevelError
	if debug {
		logLevel = device.LogLevelVerbose
	}
	logger := device.NewLogger(logLevel, "(socks5) ")

	bind := conn.NewEvasionBind(conn.NewDefaultBind(), evasionCfg)
	wgDevice := device.NewDevice(tunDev, bind, logger)

	uapiStr, err := parsedConfig.ToUAPI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building UAPI config: %v\n", err)
		os.Exit(ExitSetupFailed)
		return
	}

	if err := wgDevice.IpcSet(uapiStr); err != nil {
		fmt.Fprintf(os.Stderr, "Error applying WireGuard config: %v\n", err)
		os.Exit(ExitSetupFailed)
		return
	}

	if err := wgDevice.Up(); err != nil {
		fmt.Fprintf(os.Stderr, "Error bringing up WireGuard device: %v\n", err)
		os.Exit(ExitSetupFailed)
		return
	}

	socksServer := proxy.NewSOCKS5Server(socks5Addr, tnet.DialContext)
	socksServer.Debug = debug

	fmt.Println("┌──────────────────────────────────────────────────────────────┐")
	fmt.Println("│                                                              │")
	fmt.Println("│   TravonetWG: SOCKS5 Inbound Proxy Active                    │")
	fmt.Println("│   Zero-Admin / Pure Userspace Mode (Windows Netstack)        │")
	fmt.Println("│                                                              │")
	fmt.Println("└──────────────────────────────────────────────────────────────┘")
	if unsafe, reason := isNonLoopbackAddress(socks5Addr); unsafe {
		fmt.Fprintln(os.Stderr, "WARNING: Non-loopback address bound: ", reason)
	}
	fmt.Printf("SOCKS5 Proxy Listening on: %s\n", socks5Addr)
	fmt.Printf("Evasion Strategy:          %s\n", evasionCfg.Strategy)
	fmt.Printf("Fake TTL:                  %d\n", evasionCfg.FakeTTL)
	fmt.Printf("Persistent Keepalive:      %ds\n", parsedConfig.PersistentKeepalive)
	if conf.IsPort500Endpoint(parsedConfig.Endpoint) {
		fmt.Printf("Port 500 Endpoint:         %s (Keepalive clamped to %ds)\n", parsedConfig.Endpoint, parsedConfig.PersistentKeepalive)
	}
	fmt.Printf("Internal Tunnel IP:        %s (DNS: %s)\n", localIPs[0], dnsIPs[0])
	fmt.Println("Example usage:")
	fmt.Printf("   curl -x socks5h://%s https://cloudflare.com/cdn-cgi/trace\n", socks5Addr)
	fmt.Println("Press Ctrl+C to terminate.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill, windows.SIGTERM)

	go func() {
		if err := socksServer.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(os.Stderr, "SOCKS5 server error: %v\n", err)
		}
	}()

	<-sigCh
	fmt.Println("\nStopping SOCKS5 proxy and WireGuard device...")

	_ = socksServer.Close()
	wgDevice.Close()
	fmt.Println("Stopped cleanly.")
}

func runTunWindows(interfaceName string, parsedConfig *conf.Config, evasionCfg conn.EvasionConfig, debug bool) {
	logLevel := device.LogLevelError
	if debug {
		logLevel = device.LogLevelVerbose
	}
	logger := device.NewLogger(logLevel, fmt.Sprintf("(%s) ", interfaceName))

	mtu := 1280
	if parsedConfig != nil && parsedConfig.MTU > 0 {
		mtu = parsedConfig.MTU
	}

	tdev, err := tun.CreateTUN(interfaceName, mtu)
	if err != nil {
		logger.Errorf("Failed to create Wintun adapter %s (is wintun.dll in current directory or PATH?): %v", interfaceName, err)
		os.Exit(ExitSetupFailed)
		return
	}

	realName, err := tdev.Name()
	if err == nil {
		interfaceName = realName
	}

	bind := conn.NewEvasionBind(conn.NewDefaultBind(), evasionCfg)
	dev := device.NewDevice(tdev, bind, logger)

	if parsedConfig != nil {
		uapiStr, err := parsedConfig.ToUAPI()
		if err != nil {
			logger.Errorf("Failed to build UAPI config: %v", err)
			os.Exit(ExitSetupFailed)
			return
		}

		if err := dev.IpcSetOperation(bufio.NewReader(strings.NewReader(uapiStr))); err != nil {
			logger.Errorf("Failed to apply UAPI config: %v", err)
			os.Exit(ExitSetupFailed)
			return
		}

		if err := parsedConfig.ApplyNetworkConfig(interfaceName); err != nil {
			logger.Errorf("Failed to configure network interface %s: %v", interfaceName, err)
			os.Exit(ExitSetupFailed)
			return
		}
		logger.Verbosef("Network configuration applied to %s", interfaceName)
	}

	err = dev.Up()
	if err != nil {
		logger.Errorf("Failed to bring up device: %v", err)
		dev.Close()
		os.Exit(ExitSetupFailed)
		return
	}
	logger.Verbosef("Device started")

	uapi, err := ipc.UAPIListen(interfaceName)
	if err != nil {
		logger.Errorf("Failed to listen on UAPI named pipe: %v", err)
	} else {
		go func() {
			for {
				c, err := uapi.Accept()
				if err != nil {
					return
				}
				go dev.IpcHandle(c)
			}
		}()
		logger.Verbosef("UAPI named pipe listener started for %s", interfaceName)
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, os.Kill, windows.SIGTERM)

	select {
	case <-term:
	case <-dev.Wait():
	}

	if parsedConfig != nil {
		parsedConfig.CleanupRoutes(interfaceName)
	}

	if uapi != nil {
		uapi.Close()
	}
	dev.Close()
	logger.Verbosef("Shutting down cleanly")
}
