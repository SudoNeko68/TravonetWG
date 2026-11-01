//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

// pmtuDiscoverUnset tells sendUDPWithControl to leave the socket's
// IP_MTU_DISCOVER setting untouched for this datagram.
const pmtuDiscoverUnset = -1

// appendCmsg appends one control message to oob and returns the extended
// buffer. The data buffer is copied after the (aligned) cmsghdr.
func appendCmsg(oob []byte, level, typ int32, data []byte) []byte {
	start := len(oob)
	oob = append(oob, make([]byte, unix.CmsgSpace(len(data)))...)

	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[start]))
	hdr.Level = level
	hdr.Type = typ
	hdr.SetLen(unix.CmsgLen(len(data)))

	dst := oob[start+unix.CmsgLen(0) : start+unix.CmsgLen(0)+len(data)]
	copy(dst, data)
	return oob
}

// sendUDPWithTTL atomically sends one UDP datagram with an individual IP_TTL
// supplied through a sendmsg control message. This avoids the setsockopt race
// where a concurrent data packet could inherit the low fake TTL.
func sendUDPWithTTL(fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int) error {
	return sendUDPWithControl(fd, dstIP, dstPort, payload, ttl, nil, pmtuDiscoverUnset)
}

// sendUDPWithTTLAndOptions is sendUDPWithTTL with optional raw IPv4 options
// (IP_OPTIONS). The options are applied only for the duration of this send and
// then cleared, so subsequent transport packets use a standard 20-byte header.
//
// IP_OPTIONS cannot be supplied as a sendmsg control message on all supported
// kernels, so it is applied with setsockopt. Callers must therefore serialize
// sends on the same socket (EvasionBind.Send holds a mutex for this reason).
func sendUDPWithTTLAndOptions(fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int, ipOptions []byte) error {
	return sendUDPWithControl(fd, dstIP, dstPort, payload, ttl, ipOptions, pmtuDiscoverUnset)
}

// sendUDPWithControl sends one datagram with per-packet IP_TTL, optional
// IP_OPTIONS and an optional per-packet IP_MTU_DISCOVER value. The TTL and MTU
// discovery settings travel as cmsgs in the very same sendmsg, so they can
// never leak into unrelated datagrams sent by other goroutines.
func sendUDPWithControl(fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int, ipOptions []byte, pmtuDisc int) error {
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
		var ttlBuf [4]byte
		*(*int32)(unsafe.Pointer(&ttlBuf[0])) = int32(ttl)
		oob = appendCmsg(oob, unix.IPPROTO_IP, unix.IP_TTL, ttlBuf[:])
	}
	if pmtuDisc != pmtuDiscoverUnset {
		var pmtuBuf [4]byte
		*(*int32)(unsafe.Pointer(&pmtuBuf[0])) = int32(pmtuDisc)
		oob = appendCmsg(oob, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, pmtuBuf[:])
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
// is disabled for this datagram only (as a cmsg) so the kernel performs real L3
// IPv4 fragmentation (MF=1 + MF=0) of the decoy packet, while normal transport
// packets keep their path-MTU discovery state.
func sendUDPJumbo(fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int) error {
	if fd < 0 {
		return unix.EBADF
	}

	err := sendUDPWithControl(fd, dstIP, dstPort, payload, ttl, nil, unix.IP_PMTUDISC_DONT)
	if err == nil || !errors.Is(err, unix.EINVAL) {
		return err
	}

	// Kernels predating per-datagram IP_MTU_DISCOVER cmsg support reject the
	// control message with EINVAL. Fall back to a temporary socket option and
	// restore the previous value immediately.
	previous, getErr := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
	if getErr != nil {
		// WANT is the kernel default for unconnected UDP sockets.
		previous = unix.IP_PMTUDISC_WANT
	}
	if setErr := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT); setErr != nil {
		return err
	}
	defer func() {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, previous)
	}()

	return sendUDPWithTTL(fd, dstIP, dstPort, payload, ttl)
}

// sendUDP6WithControl sends one IPv6 datagram with per-packet IPV6_HOPLIMIT
// supplied through a sendmsg control message.
func sendUDP6WithControl(fd int, dstIP [16]byte, dstPort int, payload []byte, hopLimit int) error {
	if fd < 0 {
		return unix.EBADF
	}
	if dstPort <= 0 || dstPort > 65535 {
		return unix.EINVAL
	}

	var addr unix.SockaddrInet6
	addr.Port = dstPort
	addr.Addr = dstIP

	var oob []byte
	if hopLimit > 0 {
		var hopBuf [4]byte
		*(*int32)(unsafe.Pointer(&hopBuf[0])) = int32(hopLimit)
		oob = appendCmsg(oob, unix.IPPROTO_IPV6, unix.IPV6_HOPLIMIT, hopBuf[:])
	}

	return unix.Sendmsg(fd, payload, oob, &addr, 0)
}

// userspaceRawSendAvailable reports whether per-packet cmsg sending works on
// this platform.
func userspaceRawSendAvailable() bool { return true }
