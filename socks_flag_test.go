/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package main

import (
	"testing"
)

func TestParseSocksAddr(t *testing.T) {
	tests := []struct {
		input       string
		expectedOut string
		expectedOk  bool
	}{
		{"", "127.0.0.1:1080", true},
		{"   ", "127.0.0.1:1080", true},
		{"1080", "127.0.0.1:1080", true},
		{"1088", "127.0.0.1:1088", true},
		{":1080", "127.0.0.1:1080", true},
		{":8080", "127.0.0.1:8080", true},
		{"127.0.0.1:1080", "127.0.0.1:1080", true},
		{"127.0.0.1:1088", "127.0.0.1:1088", true},
		{"0.0.0.0:1080", "0.0.0.0:1080", true},
		{"192.168.1.100:9050", "192.168.1.100:9050", true},
		{"[::1]:1080", "[::1]:1080", true},
		{"localhost:1080", "localhost:1080", true},
		// Invalid / non-address inputs that shouldn't be consumed as socks address
		{"warp", "", false},
		{"-c", "", false},
		{"--debug", "", false},
		{"0", "", false},
		{"70000", "", false},
		{"invalid:port", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			out, ok := parseSocksAddr(tt.input)
			if ok != tt.expectedOk {
				t.Errorf("parseSocksAddr(%q) ok = %v, expected %v", tt.input, ok, tt.expectedOk)
			}
			if out != tt.expectedOut {
				t.Errorf("parseSocksAddr(%q) out = %q, expected %q", tt.input, out, tt.expectedOut)
			}
		})
	}
}

func TestIsNonLoopbackAddress(t *testing.T) {
	tests := []struct {
		addr         string
		expectUnsafe bool
	}{
		{"127.0.0.1:1080", false},
		{"127.0.0.2:1080", false},
		{"localhost:1080", false},
		{"[::1]:1080", false},
		{"0.0.0.0:1080", true},
		{":1080", true},
		{"[::]:1080", true},
		{"192.168.1.1:1080", true},
		{"10.0.0.1:1080", true},
		{"172.20.0.1:1080", true},
		{"8.8.8.8:1080", true},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			unsafe, reason := isNonLoopbackAddress(tt.addr)
			if unsafe != tt.expectUnsafe {
				t.Errorf("isNonLoopbackAddress(%q) unsafe = %v, expected %v (reason: %s)",
					tt.addr, unsafe, tt.expectUnsafe, reason)
			}
		})
	}
}
