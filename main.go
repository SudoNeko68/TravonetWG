//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bufio"
	"fmt"
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
	"golang.zx2c4.com/wireguard/tun"
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

func printUsage() {
	fmt.Printf("Usage: %s [-f/--foreground] [-d/--debug] [-c/--config CONFIG_FILE] [--strategy \"...\"] [--fake-ttl N] [--pre-junk N] [--no-evasion] [INTERFACE-NAME]\n", os.Args[0])
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

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
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
		case "-s", "--strategy", "-strategy":
			if i+1 < len(os.Args) {
				i++
				evasionCfg.Strategy = os.Args[i]
			}
		case "--fake-ttl":
			if i+1 < len(os.Args) {
				i++
				if ttl, err := strconv.Atoi(os.Args[i]); err == nil {
					evasionCfg.FakeTTL = ttl
				}
			}
		case "--pre-junk":
			if i+1 < len(os.Args) {
				i++
				if sz, err := strconv.Atoi(os.Args[i]); err == nil {
					evasionCfg.PreJunkSize = sz
				}
			}
		default:
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

		// Apply evasion overrides from config file
		if cfg.Strategy != "" && evasionCfg.Strategy == "default" {
			evasionCfg.Strategy = cfg.Strategy
		}
		if cfg.FakeTTL > 0 {
			evasionCfg.FakeTTL = cfg.FakeTTL
		}
		if cfg.PreJunkSize > 0 {
			evasionCfg.PreJunkSize = cfg.PreJunkSize
		}
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
