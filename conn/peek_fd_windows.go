//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"errors"

	"golang.org/x/sys/windows"
)

// PeekLookAtSocketFd4 returns the underlying file descriptor for IPv4 socket on Windows.
func (s *StdNetBind) PeekLookAtSocketFd4() (fd int, err error) {
	s.mu.Lock()
	conn := s.ipv4
	s.mu.Unlock()
	if conn == nil {
		return -1, errors.New("ipv4 socket is not open")
	}
	sysconn, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}

// PeekLookAtSocketFd6 returns the underlying file descriptor for IPv6 socket on Windows.
func (s *StdNetBind) PeekLookAtSocketFd6() (fd int, err error) {
	s.mu.Lock()
	conn := s.ipv6
	s.mu.Unlock()
	if conn == nil {
		return -1, errors.New("ipv6 socket is not open")
	}
	sysconn, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}

// SetIPv4TTL sets the IP_TTL socket option on the underlying IPv4 UDP socket on Windows.
func (s *StdNetBind) SetIPv4TTL(ttl int) error {
	s.mu.Lock()
	conn := s.ipv4
	s.mu.Unlock()
	if conn == nil {
		return errors.New("ipv4 socket is not open")
	}
	sysconn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	err = sysconn.Control(func(fd uintptr) {
		sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL, ttl)
	})
	if err != nil {
		return err
	}
	return sockErr
}

// SetIPv6HopLimit sets the IPV6_UNICAST_HOPS socket option on the underlying IPv6 UDP socket on Windows.
func (s *StdNetBind) SetIPv6HopLimit(hops int) error {
	s.mu.Lock()
	conn := s.ipv6
	s.mu.Unlock()
	if conn == nil {
		return errors.New("ipv6 socket is not open")
	}
	sysconn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	err = sysconn.Control(func(fd uintptr) {
		sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_UNICAST_HOPS, hops)
	})
	if err != nil {
		return err
	}
	return sockErr
}
