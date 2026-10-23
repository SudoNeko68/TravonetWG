/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

const (
	// minFakeTTL .. maxFakeTTL is the DPI-safe window: the decoy must survive
	// long enough to reach the domestic DPI but expire before the real server.
	// On cellular networks (LTE/5G), hops to the carrier border TSPU are often 4-6,
	// so maxFakeTTL is expanded to 8.
	minFakeTTL = 3
	maxFakeTTL = 8

	// maxProbeTTL bounds the AutoTTL probe. Beyond this distance the
	// recommendation is already saturated, and mobile networks frequently
	// filter ICMP entirely, so probing further only wastes battery.
	maxProbeTTL = 14

	// autoTTLDNSTimeout bounds name resolution inside the probe.
	autoTTLDNSTimeout = 3 * time.Second
)

// lookupIPv4 resolves a hostname with a bounded timeout and returns its first
// IPv4 address. The probe runs in the background, but it must never hang on a
// black-holed resolver, so a context timeout is essential on Android.
func lookupIPv4(host string) (net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), autoTTLDNSTimeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if addr.Is4() {
			return net.IP(addr.AsSlice()), nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address found for %s", host)
}

// MeasureTargetTTL measures the network distance (hops) to the target endpoint
// and calculates the optimal FakeTTL for DPI early-termination desync.
//
// On Android the distance is measured without root through IP_RECVERR /
// MSG_ERRQUEUE, so no traceroute binary or CAP_NET_RAW is required. The probe
// may take up to ~0.7s, so callers must not run it on a latency-sensitive
// thread; the Android backend runs it in a goroutine after the tunnel is up.
func MeasureTargetTTL(endpoint string) (totalHops int, recommendedFakeTTL int, err error) {
	fallback := defaultFakeTTLForPlatform()

	host := endpoint
	port := 51820
	if h, p, splitErr := net.SplitHostPort(endpoint); splitErr == nil {
		host = h
		if parsedPort, convErr := strconv.Atoi(p); convErr == nil && parsedPort > 0 {
			port = parsedPort
		}
	}

	ip := net.ParseIP(host)
	if ip == nil {
		resolved, lookupErr := lookupIPv4(host)
		if lookupErr != nil {
			return 0, fallback, fmt.Errorf("failed to resolve endpoint %s: %w", host, lookupErr)
		}
		ip = resolved
	}

	hops, probeErr := measureTTLViaErrQueue(ip, port)
	if probeErr != nil {
		return 0, fallback, fmt.Errorf("kernel TTL probe unavailable: %w", probeErr)
	}
	if hops <= 0 {
		return 0, fallback, fmt.Errorf("kernel TTL probe returned no hops")
	}
	return hops, recommendFakeTTL(hops), nil
}

// recommendFakeTTL derives a safe fake TTL from the measured hop count. The
// fake packet must traverse the domestic DPI (TSPU) but expire before reaching
// the foreign server. The Android-safe window is minFakeTTL..maxFakeTTL.
func recommendFakeTTL(totalHops int) int {
	recommended := totalHops - 4
	if recommended < minFakeTTL {
		recommended = minFakeTTL
	}
	if recommended > maxFakeTTL {
		recommended = maxFakeTTL
	}
	return recommended
}
