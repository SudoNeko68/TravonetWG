//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
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

	"golang.org/x/sys/unix"
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

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

func parseSocksAddr(val string) (string, bool) {
	val = strings.TrimSpace(val)
	if val == "" {
		return "127.0.0.1:1080", true
	}
	// Pure port number: "1080" -> "127.0.0.1:1080"
	if p, err := strconv.Atoi(val); err == nil && p > 0 && p <= 65535 {
		return fmt.Sprintf("127.0.0.1:%d", p), true
	}
	// Port with colon: ":1080" -> "127.0.0.1:1080"
	if strings.HasPrefix(val, ":") {
		if p, err := strconv.Atoi(val[1:]); err == nil && p > 0 && p <= 65535 {
			return fmt.Sprintf("127.0.0.1:%d", p), true
		}
	}
	// "host:port" or "ip:port"
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
		return true, fmt.Sprintf("прокси привязан ко всем сетевым интерфейсам (%s)", addr)
	}
	if strings.EqualFold(host, "localhost") {
		return false, ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true, fmt.Sprintf("прокси привязан к внешнему адресу (%s)", addr)
	}
	if ip.IsLoopback() {
		return false, ""
	}
	if ip.IsPrivate() {
		return true, fmt.Sprintf("прокси привязан к локальной сети (%s), доступен другим устройствам в LAN", addr)
	}
	return true, fmt.Sprintf("прокси привязан к публичному/внешнему IP (%s), доступен из интернета", addr)
}

func printUsage() {
	fmt.Printf(`Usage: %s [OPTIONS] [INTERFACE-NAME]

TravonetWG: High-performance WireGuard client with in-tree L3 evasion engine
against TSPU / DPI filtering (Zapret-style Fake UDP + IPFrag2 / Early-Termination).

Modes:
  Mode 1 (Embedded in .conf):
      Put evasion directives directly inside your WireGuard .conf file:
          [Interface]
          FakeTTL = auto
          PreJunk = 64
          Strategy = junk(64) -> fake_udp(148) -> frag(8) -> frag(148)

  Mode 2 (Vanilla WG .conf + CLI parameters):
      Use a 100%% standard, unmodified WireGuard .conf file, and configure or
      override evasion parameters via command-line arguments:
          %s -f -c wg0.conf --fake-ttl auto wg0
      Or run with zero flags to use intelligent auto-detection and defaults:
          %s -f -c wg0.conf wg0

  Mode 3 (Zero-Root Userspace SOCKS5 Inbound):
      Run pure userspace SOCKS5 proxy without root, TUN device, or routing changes:
          %s -c wg0.conf --socks
          %s -c wg0.conf --socks 127.0.0.1:1080
          %s -c wg0.conf --socks 1080

Options:
  -c, --config FILE             Load WireGuard configuration file (.conf)
  --socks, --socks5 [ADDR:PORT] Start userspace SOCKS5 proxy (default: 127.0.0.1:1080)
  -s, --strategy DSL            Evasion pipeline DSL (default: "junk(64) -> fake_udp(148) -> frag(8) -> frag(148)")
  --fake-ttl N|auto             TTL for fake packets (number 1-255 or 'auto' for hop distance probe)
  --pre-junk N                  Size in bytes of initial junk UDP packet (default: 64, 0 to disable)
  --no-evasion                  Disable all evasion mechanisms (run as standard wireguard-go)
  -d, --debug                   Enable verbose debug logging
  -f, --foreground              Run in foreground instead of daemonizing
  -h, --help                    Show this help message
  --version                     Show version information
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func warning() {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		if os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1" {
			return
		}
	default:
		return
	}

	fmt.Fprintln(os.Stderr, "┌──────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "│   TravonetWG: Custom WireGuard with L3 Evasion       │")
	fmt.Fprintln(os.Stderr, "│   Early-termination Desync against TSPU / DPI        │")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "└──────────────────────────────────────────────────────┘")
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("TravonetWG (wireguard-go v%s)\n\nCustom Userspace WireGuard with L3 early-termination evasion for %s-%s.\n", Version, runtime.GOOS, runtime.GOARCH)
		return
	}

	warning()

	var foreground bool
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
			foreground = true
		case "-d", "--debug", "-debug":
			debug = true
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

		// If interface name not provided, derive from filename
		if interfaceName == "" {
			base := filepath.Base(configFile)
			ext := filepath.Ext(base)
			interfaceName = strings.TrimSuffix(base, ext)
		}

		// Mode 1: Apply evasion overrides from config file
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

	// Mode 2 / CLI Overrides: CLI flags have highest priority
	if cliStrategy != "" {
		evasionCfg.Strategy = cliStrategy
	}
	if cliFakeTTL != 0 {
		evasionCfg.FakeTTL = cliFakeTTL
	}
	if cliPreJunk >= 0 {
		evasionCfg.PreJunkSize = cliPreJunk
	}

	// Resolve auto-TTL (FakeTTL <= 0) if evasion is enabled
	if evasionCfg.Enabled && evasionCfg.FakeTTL <= 0 {
		endpoint := ""
		if parsedConfig != nil && parsedConfig.Endpoint != "" {
			endpoint = parsedConfig.Endpoint
		}
		if endpoint != "" {
			if debug {
				fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] 📏 Measuring hop distance to endpoint %s...\n", endpoint)
			}
			totalHops, recommendedTTL, err := conn.MeasureTargetTTL(endpoint)
			if err == nil {
				evasionCfg.FakeTTL = recommendedTTL
				if debug {
					fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] 🎯 Auto-measured %d hops to endpoint, setting FakeTTL = %d (DPI bypass zone: 8-%d)\n",
						totalHops, recommendedTTL, recommendedTTL)
				}
			} else {
				evasionCfg.FakeTTL = 11 // Fallback default
				if debug {
					fmt.Printf("DEBUG: (evasion) [TRAVONET-WG] ⚠️ Auto-measure failed: %v (falling back to FakeTTL = 11)\n", err)
				}
			}
		} else {
			evasionCfg.FakeTTL = 11 // Fallback default if endpoint not directly known
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

	if socks5Addr != "" {
		if parsedConfig == nil {
			fmt.Fprintln(os.Stderr, "Error: SOCKS5 mode requires a WireGuard configuration file (-c config.conf)")
			os.Exit(ExitSetupFailed)
			return
		}

		runSocks5Userspace(socks5Addr, parsedConfig, evasionCfg, debug)
		return
	}

	if interfaceName == "" {
		printUsage()
		return
	}

	if evasionCfg.Strategy != "" && evasionCfg.Strategy != "default" {
		if _, err := conn.ParseStrategy(evasionCfg.Strategy, evasionCfg.FakeTTL, evasionCfg.NormalTTL); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid evasion strategy: %v\n", err)
			os.Exit(ExitSetupFailed)
		}
	}

	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
	}

	evasionCfg.Debug = debug

	// get log level
	logLevel := func() int {
		if debug {
			return device.LogLevelVerbose
		}
		switch os.Getenv("LOG_LEVEL") {
		case "verbose", "debug":
			return device.LogLevelVerbose
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelError
	}()

	// open TUN device (or use supplied fd)

	tdev, err := func() (tun.Device, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return tun.CreateTUN(interfaceName, device.DefaultMTU)
		}

		// construct tun device from supplied fd

		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		err = unix.SetNonblock(int(fd), true)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "")
		return tun.CreateTUNFromFile(file, device.DefaultMTU)
	}()

	if err == nil {
		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Verbosef("Starting wireguard-go version %s", Version)

	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	// open UAPI file (or use supplied fd)

	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()
	if err != nil {
		logger.Errorf("UAPI listen error: %v", err)
		os.Exit(ExitSetupFailed)
		return
	}
	// daemonize the process

	if !foreground {
		env := os.Environ()
		env = append(env, fmt.Sprintf("%s=3", ENV_WG_TUN_FD))
		env = append(env, fmt.Sprintf("%s=4", ENV_WG_UAPI_FD))
		env = append(env, fmt.Sprintf("%s=1", ENV_WG_PROCESS_FOREGROUND))
		files := [3]*os.File{}
		if os.Getenv("LOG_LEVEL") != "" && logLevel != device.LogLevelSilent {
			files[0], _ = os.Open(os.DevNull)
			files[1] = os.Stdout
			files[2] = os.Stderr
		} else {
			files[0], _ = os.Open(os.DevNull)
			files[1], _ = os.Open(os.DevNull)
			files[2], _ = os.Open(os.DevNull)
		}
		attr := &os.ProcAttr{
			Files: []*os.File{
				files[0], // stdin
				files[1], // stdout
				files[2], // stderr
				tdev.File(),
				fileUAPI,
			},
			Dir: ".",
			Env: env,
		}

		path, err := os.Executable()
		if err != nil {
			logger.Errorf("Failed to determine executable: %v", err)
			os.Exit(ExitSetupFailed)
		}

		process, err := os.StartProcess(
			path,
			os.Args,
			attr,
		)
		if err != nil {
			logger.Errorf("Failed to daemonize: %v", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}

	bind := conn.NewEvasionBind(conn.NewDefaultBind(), evasionCfg)
	device := device.NewDevice(tdev, bind, logger)

	if parsedConfig != nil {
		uapiStr, err := parsedConfig.ToUAPI()
		if err != nil {
			logger.Errorf("Failed to build UAPI config: %v", err)
			os.Exit(ExitSetupFailed)
			return
		}

		if err := device.IpcSetOperation(bufio.NewReader(strings.NewReader(uapiStr))); err != nil {
			logger.Errorf("Failed to apply UAPI configuration: %v", err)
			os.Exit(ExitSetupFailed)
			return
		}

		if err := parsedConfig.ApplyNetworkConfig(interfaceName); err != nil {
			logger.Errorf("Failed to configure network interface %s: %v", interfaceName, err)
			os.Exit(ExitSetupFailed)
			return
		}

		logger.Verbosef("✅ WireGuard configuration from %s applied successfully to %s", configFile, interfaceName)
	}

	logger.Verbosef("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		os.Exit(ExitSetupFailed)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	logger.Verbosef("UAPI listener started")

	// wait for program to terminate

	signal.Notify(term, unix.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Verbosef("Shutting down")
}

func runSocks5Userspace(socks5Addr string, parsedConfig *conf.Config, evasionCfg conn.EvasionConfig, debug bool) {
	// 1. Validate strategy if specified
	if evasionCfg.Strategy != "" && evasionCfg.Strategy != "default" {
		if _, err := conn.ParseStrategy(evasionCfg.Strategy, evasionCfg.FakeTTL, evasionCfg.NormalTTL); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid evasion strategy: %v\n", err)
			os.Exit(ExitSetupFailed)
			return
		}
	}

	evasionCfg.Debug = debug

	// 2. Parse local addresses and DNS servers from parsedConfig
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

	// 3. Create userspace netstack TUN device (No /dev/net/tun needed!)
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

	// 4. Create EvasionBind wrapping StdNetBind
	bind := conn.NewEvasionBind(conn.NewDefaultBind(), evasionCfg)
	wgDevice := device.NewDevice(tunDev, bind, logger)

	// 5. Apply WireGuard UAPI config
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

	// 6. Start SOCKS5 Server
	socksServer := proxy.NewSOCKS5Server(socks5Addr, tnet.DialContext)
	socksServer.Debug = debug

	fmt.Println("┌──────────────────────────────────────────────────────────────┐")
	fmt.Println("│                                                              │")
	fmt.Println("│   TravonetWG: SOCKS5 Inbound Proxy Active                    │")
	fmt.Println("│   Zero-Root / Pure Userspace Mode (gVisor Netstack)          │")
	fmt.Println("│                                                              │")
	fmt.Println("└──────────────────────────────────────────────────────────────┘")
	if unsafe, reason := isNonLoopbackAddress(socks5Addr); unsafe {
		fmt.Fprintln(os.Stderr, "════════════════════════════════════════════════════════════════")
		fmt.Fprintln(os.Stderr, "[!] ВНИМАНИЕ: НЕБЕЗОПАСНАЯ КОНФИГУРАЦИЯ СЕТИ (SECURITY WARNING)!")
		fmt.Fprintf(os.Stderr, "    %s.\n", reason)
		fmt.Fprintln(os.Stderr, "    SOCKS5-прокси работает БЕЗ пароля и авторизации.")
		fmt.Fprintln(os.Stderr, "    Любой узел сети может использовать этот туннель (Open Proxy).")
		fmt.Fprintln(os.Stderr, "    Для безопасности привязывайте к 127.0.0.1 (только этот ПК).")
		fmt.Fprintln(os.Stderr, "════════════════════════════════════════════════════════════════")
	}
	fmt.Printf("🚀 SOCKS5 Proxy Listening on: %s\n", socks5Addr)
	fmt.Printf("📜 Evasion Strategy:          %s\n", evasionCfg.Strategy)
	fmt.Printf("🎯 Fake TTL:                  %d\n", evasionCfg.FakeTTL)
	fmt.Printf("🌐 Internal Tunnel IP:        %s (DNS: %s)\n", localIPs[0], dnsIPs[0])
	fmt.Println("💡 Example usage:")
	fmt.Printf("   curl -x socks5h://%s https://cloudflare.com/cdn-cgi/trace\n", socks5Addr)
	fmt.Println("   Press Ctrl+C to terminate.")

	// Trap termination signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, unix.SIGTERM)

	go func() {
		if err := socksServer.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(os.Stderr, "SOCKS5 server error: %v\n", err)
		}
	}()

	<-sigCh
	fmt.Println("\n🛑 Stopping SOCKS5 proxy and WireGuard device...")
	_ = socksServer.Close()
	wgDevice.Close()
	fmt.Println("✅ Stopped cleanly.")
}
