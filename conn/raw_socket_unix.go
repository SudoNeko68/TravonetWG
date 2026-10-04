//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"fmt"
	"syscall"
)

func initRawSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return -1, fmt.Errorf("syscall.Socket(AF_INET, SOCK_RAW, IPPROTO_RAW): %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("setsockopt IP_HDRINCL: %w", err)
	}
	// IP_NODEFRAG tells kernel not to reassemble fragments on outgoing raw socket.
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_NODEFRAG, 1)

	// IP_FREEBIND (15) allows binding/sending with non-local source addresses if needed.
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, 15, 1)

	return fd, nil
}

func closeRawSocket(rawFd int) error {
	if rawFd >= 0 {
		return syscall.Close(rawFd)
	}
	return nil
}

func sendRawPacket(rawFd int, dstIP []byte, packet []byte) error {
	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], dstIP)
	return syscall.Sendto(rawFd, packet, 0, &addr)
}
