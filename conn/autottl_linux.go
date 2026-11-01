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

// probeHopsViaDNS measures network hops to public anycast DNS resolvers (1.1.1.1, 8.8.8.8, 77.88.8.8)
// using UDP and IP_RECVTTL. This works on cellular networks (LTE/5G) where ICMP Time Exceeded is blocked.
func probeHopsViaDNS() (int, error) {
	resolvers := []string{
		"1.1.1.1",
		"8.8.8.8",
		"77.88.8.8",
	}

	var lastErr error
	for _, ipStr := range resolvers {
		hops, err := probeSingleDNSResolver(ipStr)
		if err == nil && hops > 0 {
			return hops, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return 0, lastErr
	}
	return 0, errors.New("no responses received from DNS resolvers")
}

func probeSingleDNSResolver(resolverIP string) (int, error) {
	ip := net.ParseIP(resolverIP).To4()
	if ip == nil {
		return 0, errors.New("invalid IPv4 address")
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_UDP)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	_ = ProtectSocket(fd)

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVTTL, 1); err != nil {
		return 0, err
	}

	// Standard DNS query for root "." type NS with recursion desired
	pkt := []byte{
		0xAB, 0xCD, // ID
		0x01, 0x00, // Standard query, recursion desired
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		0x00,       // root domain name "."
		0x00, 0x02, // QTYPE = NS
		0x00, 0x01, // QCLASS = IN
	}

	var sa unix.SockaddrInet4
	sa.Port = 53
	copy(sa.Addr[:], ip)

	if err := unix.Sendto(fd, pkt, 0, &sa); err != nil {
		return 0, err
	}

	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, 800) // 800ms timeout per resolver
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, errors.New("timeout waiting for DNS response")
	}

	buf := make([]byte, 1500)
	oob := make([]byte, 256)
	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, 0)
	if err != nil {
		return 0, err
	}

	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, err
	}
	for _, cm := range cmsgs {
		if cm.Header.Level == unix.IPPROTO_IP && cm.Header.Type == unix.IP_TTL {
			var inTTL int
			if len(cm.Data) >= 4 {
				inTTL = int(binary.NativeEndian.Uint32(cm.Data[:4]))
			} else if len(cm.Data) >= 1 {
				inTTL = int(cm.Data[0])
			}
			if inTTL <= 0 || inTTL > 255 {
				continue
			}
			baseTTL := 64
			if inTTL > 64 && inTTL <= 128 {
				baseTTL = 128
			} else if inTTL > 128 {
				baseTTL = 255
			}
			hops := baseTTL - inTTL
			if hops < 1 {
				hops = 1
			}
			return hops, nil
		}
	}
	return 0, errors.New("no IP_TTL control message in DNS response")
}
