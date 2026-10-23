//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// sendUDPWithTTL atomically sends one UDP datagram with an individual IP_TTL
// supplied through a sendmsg control message. This avoids the setsockopt race
// where a concurrent data packet could inherit the low fake TTL.
func sendUDPWithTTL(fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int) error {
	return sendUDPWithTTLAndOptions(fd, dstIP, dstPort, payload, ttl, nil)
}

// sendUDPWithTTLAndOptions is sendUDPWithTTL with optional raw IPv4 options
// (IP_OPTIONS). The options are applied only for the duration of this send and
// then cleared, so subsequent transport packets use a standard 20-byte header.
func sendUDPWithTTLAndOptions(fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int, ipOptions []byte) error {
	if fd < 0 {
		return unix.EBADF
	}
	if dstPort <= 0 || dstPort > 65535 {
		return unix.EINVAL
	}

	var addr unix.SockaddrInet4
	addr.Port = dstPort
	addr.Addr = dstIP

	var oob []byte
	if ttl > 0 {
		oob = make([]byte, unix.CmsgSpace(4))
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		hdr.Level = unix.IPPROTO_IP
		hdr.Type = unix.IP_TTL
		hdr.SetLen(unix.CmsgLen(4))
		*(*int32)(unsafe.Pointer(&oob[unix.CmsgLen(0)])) = int32(ttl)
	}

	if len(ipOptions) > 0 {
		if err := unix.SetsockoptString(fd, unix.IPPROTO_IP, unix.IP_OPTIONS, string(ipOptions)); err != nil {
			// Fall back to a plain datagram if the kernel rejects the options.
			return unix.Sendmsg(fd, payload, oob, &addr, 0)
		}
		defer func() {
			_ = unix.SetsockoptString(fd, unix.IPPROTO_IP, unix.IP_OPTIONS, "")
		}()
	}

	return unix.Sendmsg(fd, payload, oob, &addr, 0)
}

// sendUDPJumbo sends an oversized UDP datagram with a short TTL. IP_MTU_DISCOVER
// is disabled so the kernel performs real L3 IPv4 fragmentation (MF=1 + MF=0)
// of the decoy packet.
func sendUDPJumbo(fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int) error {
	if fd < 0 {
		return unix.EBADF
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
	return sendUDPWithTTL(fd, dstIP, dstPort, payload, ttl)
}

// userspaceRawSendAvailable reports whether per-packet cmsg sending works on
// this platform.
func userspaceRawSendAvailable() bool { return true }
