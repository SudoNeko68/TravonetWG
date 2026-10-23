/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"sync"
	"syscall"
)

// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it is
// the max supported by a default configuration of macOS. Some platforms will
// silently clamp the value to other maximums, such as linux clamping to
// net.core.{r,w}mem_max (see _linux.go for additional implementation that works
// around this limitation)
const socketBufferSize = 7 << 20

// controlFn is the callback function signature from net.ListenConfig.Control.
// It is used to apply platform specific configuration to the socket prior to
// bind.
type controlFn func(network, address string, c syscall.RawConn) error

// controlFns is a list of functions that are called from the listen config
// that can apply socket options.
var controlFns = []controlFn{}

// socketProtectorMu guards socketProtectorFn.
var socketProtectorMu sync.RWMutex

// socketProtectorFn is an optional callback used to protect a raw socket
// descriptor from being routed back into the VPN tunnel. On Android this is
// wired to VpnService.protect(fd) through the JNI layer.
var socketProtectorFn func(fd int) error

// SetSocketProtector registers the callback used to protect newly created
// sockets (e.g. Android's VpnService.protect). Passing nil disables it.
func SetSocketProtector(fn func(fd int) error) {
	socketProtectorMu.Lock()
	socketProtectorFn = fn
	socketProtectorMu.Unlock()
}

// ProtectSocket asks the registered protector (if any) to protect fd. It is a
// no-op when no protector is registered, so it is safe to call on every
// platform.
func ProtectSocket(fd int) error {
	if fd < 0 {
		return nil
	}
	socketProtectorMu.RLock()
	fn := socketProtectorFn
	socketProtectorMu.RUnlock()
	if fn != nil {
		return fn(fd)
	}
	return nil
}

// listenConfig returns a net.ListenConfig that applies the controlFns to the
// socket prior to bind. This is used to apply socket buffer sizing and packet
// information OOB configuration for sticky sockets.
func listenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			for _, fn := range controlFns {
				if err := fn(network, address, c); err != nil {
					return err
				}
			}
			return nil
		},
	}
}
