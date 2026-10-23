//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// sockExtendedErr mirrors struct sock_extended_err from <linux/errqueue.h>.
type sockExtendedErr struct {
	Errno  uint32
	Origin uint8
	Type   uint8
	Code   uint8
	Pad    uint8
}

const (
	soEEOriginICMP      = 2 // SO_EE_ORIGIN_ICMP
	icmpDestUnreachable = 3 // ICMP_DEST_UNREACH
	icmpTimeExceeded    = 11
)

// buildErrQueueProbe returns a 20-byte RFC 5389 STUN Binding Request. It is only
// used to elicit ICMP Time Exceeded messages and is never sent to the real
// WireGuard endpoint as part of the tunnel.
func buildErrQueueProbe() []byte {
	probe := []byte{
		0x00, 0x01, 0x00, 0x00, // Binding Request, attribute length 0
		0x21, 0x12, 0xA4, 0x42, // Magic Cookie
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	if _, err := rand.Read(probe[8:]); err != nil {
		// Randomness is not security relevant here; zero transaction id is fine.
		_ = err
	}
	return probe
}

// measureTTLViaErrQueue probes the route to targetIP using a plain unprivileged
// SOCK_DGRAM socket with IP_RECVERR. It returns the estimated total hop count.
// ICMP is often filtered on mobile networks, in which case an error is
// returned and the caller falls back to a conservative default.
func measureTTLViaErrQueue(targetIP net.IP, port int) (int, error) {
	ip4 := targetIP.To4()
	if ip4 == nil {
		return 0, errors.New("errqueue TTL probe requires an IPv4 target")
	}
	if port <= 0 || port > 65535 {
		port = 51820
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	// Keep the probe out of an active VPN tunnel.
	_ = ProtectSocket(fd)

	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVERR, 1); err != nil {
		return 0, err
	}

	var sa unix.SockaddrInet4
	sa.Port = port
	copy(sa.Addr[:], ip4)

	probe := buildErrQueueProbe()
	lastRespondingHop := 0

	for ttl := 2; ttl <= maxProbeTTL; ttl++ {
		if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TTL, ttl); err != nil {
			return 0, err
		}
		if err := unix.Sendto(fd, probe, 0, &sa); err != nil {
			return 0, err
		}

		// Give the router a moment to answer before probing the next hop.
		time.Sleep(5 * time.Millisecond)

		reached, responded, pollErr := pollErrQueue(fd, 60*time.Millisecond)
		if pollErr != nil {
			return 0, pollErr
		}
		if reached {
			return ttl, nil
		}
		if responded {
			lastRespondingHop = ttl
			// Once the recommendation saturates, further probes cannot change
			// the result; stop early to keep the probe short.
			if recommendFakeTTL(ttl+1) >= maxFakeTTL {
				return ttl + 1, nil
			}
		}
	}

	if lastRespondingHop == 0 {
		return 0, errors.New("no ICMP responses received on route")
	}
	return lastRespondingHop + 1, nil
}

// pollErrQueue waits up to timeout for an ICMP response related to the probe.
// It reports whether the target itself answered (reached) and whether any hop
// answered (responded).
func pollErrQueue(fd int, timeout time.Duration) (reached bool, responded bool, err error) {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, responded, nil
		}
		ms := int(remaining / time.Millisecond)
		if ms < 1 {
			ms = 1
		}

		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLERR | unix.POLLIN}}
		n, pollErr := unix.Poll(pfd, ms)
		if pollErr != nil {
			if errors.Is(pollErr, unix.EINTR) {
				continue
			}
			return false, responded, pollErr
		}
		if n == 0 {
			return false, responded, nil
		}

		if pfd[0].Revents&unix.POLLIN != 0 {
			// A real UDP answer arrived, so the destination was reached.
			buf := make([]byte, 1500)
			if _, _, readErr := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); readErr == nil {
				return true, true, nil
			}
		}

		if pfd[0].Revents&(unix.POLLERR) != 0 {
			ee, ok, readErr := readRecvErr(fd)
			if readErr != nil {
				if errors.Is(readErr, unix.EAGAIN) {
					continue
				}
				return false, responded, readErr
			}
			if !ok {
				continue
			}
			if ee.Origin == soEEOriginICMP {
				switch ee.Type {
				case icmpTimeExceeded:
					return false, true, nil
				case icmpDestUnreachable:
					// Destination (or a router acting for it) reported the port
					// unreachable, meaning our probe reached the target.
					return true, true, nil
				}
			}
		}

		if pfd[0].Revents == 0 {
			return false, responded, nil
		}
	}
}

// readRecvErr reads and parses one datagram from the socket error queue.
func readRecvErr(fd int) (sockExtendedErr, bool, error) {
	var ee sockExtendedErr
	buf := make([]byte, 1500)
	oob := make([]byte, 512)

	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE)
	if err != nil {
		return ee, false, err
	}
	if oobn == 0 {
		return ee, false, nil
	}

	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return ee, false, err
	}
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level != unix.SOL_IP || cmsg.Header.Type != unix.IP_RECVERR {
			continue
		}
		if len(cmsg.Data) < 8 {
			continue
		}
		ee.Errno = binary.NativeEndian.Uint32(cmsg.Data[0:4])
		ee.Origin = cmsg.Data[4]
		ee.Type = cmsg.Data[5]
		ee.Code = cmsg.Data[6]
		ee.Pad = cmsg.Data[7]
		return ee, true, nil
	}
	return ee, false, nil
}
