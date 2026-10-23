/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package device

import (
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// rotatingBind simulates a kernel that hands out a fresh ephemeral port for
// every Open(0) request and honours explicit ports otherwise. It reports
// IsAutoPort the same way conn.EvasionBind does.
type rotatingBind struct {
	*bindtest.ChannelBind

	mu        sync.Mutex
	lastPort  uint16
	openPorts []uint16
	autoPort  bool
}

func (b *rotatingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	b.openPorts = append(b.openPorts, port)
	actual := port
	if port == 0 {
		b.lastPort++
		actual = 40000 + b.lastPort
		b.autoPort = true
	} else {
		// Re-opening the previously assigned port keeps the socket dynamic;
		// a genuinely different explicit port makes it fixed.
		b.autoPort = port == b.lastPort
		b.lastPort = port
	}
	b.mu.Unlock()

	fns, _, err := b.ChannelBind.Open(port)
	return fns, actual, err
}

func (b *rotatingBind) IsAutoPort() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.autoPort
}

func (b *rotatingBind) opens() []uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]uint16(nil), b.openPorts...)
}

func newRotatingDevice(t *testing.T, bind *rotatingBind) *Device {
	t.Helper()
	tunDev := tuntest.NewChannelTUN()
	dev := NewDevice(tunDev.TUN(), bind, NewLogger(LogLevelError, "rotate: "))
	t.Cleanup(dev.Close)
	return dev
}

// TestRotatePortAssignsNewPort is a regression test for the handshake-retry
// port rotation: BindUpdate used to re-open the previously assigned port, so
// "rotating" the port was a no-op and a blocked 4-tuple stayed blocked.
func TestRotatePortAssignsNewPort(t *testing.T) {
	bind := &rotatingBind{ChannelBind: bindtest.NewChannelBinds()[0].(*bindtest.ChannelBind)}
	dev := newRotatingDevice(t, bind)

	if err := dev.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	dev.net.Lock()
	initialPort := dev.net.port
	dev.net.Unlock()

	rotated, err := dev.RotatePort()
	if err != nil {
		t.Fatalf("RotatePort: %v", err)
	}
	if !rotated {
		t.Fatal("RotatePort did not rotate a kernel-assigned port")
	}

	dev.net.Lock()
	rotatedPort := dev.net.port
	dev.net.Unlock()

	if rotatedPort == initialPort {
		t.Fatalf("port was not rotated: still %d", rotatedPort)
	}
	if got := bind.opens(); len(got) != 2 || got[0] != 0 || got[1] != 0 {
		t.Fatalf("expected two Open(0) calls, got %v", got)
	}
}

// TestRotatePortKeepsExplicitPort verifies that an explicit listen_port is
// never changed behind the application's back.
func TestRotatePortKeepsExplicitPort(t *testing.T) {
	bind := &rotatingBind{ChannelBind: bindtest.NewChannelBinds()[0].(*bindtest.ChannelBind)}
	dev := newRotatingDevice(t, bind)

	dev.net.Lock()
	dev.net.port = 51820
	dev.net.Unlock()

	if err := dev.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if got := bind.opens(); len(got) != 1 || got[0] != 51820 {
		t.Fatalf("expected Open(51820), got %v", got)
	}

	rotated, err := dev.RotatePort()
	if err != nil {
		t.Fatalf("RotatePort: %v", err)
	}
	if rotated {
		t.Fatal("RotatePort must not touch an explicitly configured port")
	}

	dev.net.Lock()
	port := dev.net.port
	dev.net.Unlock()
	if port != 51820 {
		t.Fatalf("explicit port changed to %d", port)
	}
	if got := bind.opens(); len(got) != 1 {
		t.Fatalf("unexpected extra Open calls: %v", got)
	}
}

// TestRotatePortWhileDown verifies that rotation is a no-op when the device is
// not running.
func TestRotatePortWhileDown(t *testing.T) {
	bind := &rotatingBind{ChannelBind: bindtest.NewChannelBinds()[0].(*bindtest.ChannelBind)}
	dev := newRotatingDevice(t, bind)

	rotated, err := dev.RotatePort()
	if err != nil {
		t.Fatalf("RotatePort: %v", err)
	}
	if rotated {
		t.Fatal("RotatePort must be a no-op while the device is down")
	}
	if got := bind.opens(); len(got) != 0 {
		t.Fatalf("unexpected Open calls: %v", got)
	}
}
