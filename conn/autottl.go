/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var hopLineRegex = regexp.MustCompile(`^\s*(\d+)\s+([^\s]+)`)

// MeasureTargetTTL measures the network distance (hops) to target endpoint
// and calculates optimal FakeTTL for DPI early-termination desync.
func MeasureTargetTTL(endpoint string) (totalHops int, recommendedFakeTTL int, err error) {
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Resolve hostname if needed
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return 0, 10, fmt.Errorf("failed to resolve endpoint %s: %v", host, err)
		}
		for _, candidate := range ips {
			if candidate.To4() != nil {
				ip = candidate
				break
			}
		}
		if ip == nil {
			return 0, 10, fmt.Errorf("no IPv4 address found for %s", host)
		}
	}

	targetIPStr := ip.String()

	// Check if traceroute binary exists
	traceroutePath, err := exec.LookPath("traceroute")
	if err != nil {
		return 0, 10, fmt.Errorf("traceroute utility not found in PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, traceroutePath, "-q", "1", "-w", "1", "-m", "22", "-n", targetIPStr)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return 0, 10, fmt.Errorf("traceroute probe failed: %w", err)
	}

	maxHop := 0
	destFound := false

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		matches := hopLineRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			hopNum, err := strconv.Atoi(matches[1])
			if err != nil {
				continue
			}
			hopIP := matches[2]
			if hopIP != "*" {
				maxHop = hopNum
				if hopIP == targetIPStr {
					destFound = true
					break
				}
			}
		}
	}

	if maxHop == 0 {
		return 0, 10, fmt.Errorf("no responding hops discovered by traceroute")
	}

	if destFound {
		totalHops = maxHop
	} else {
		totalHops = maxHop + 1
	}

	// Calculate optimal FakeTTL:
	// The fake packet must pass through the domestic DPI (TSPU),
	// but expire before reaching the foreign server.
	// For international routes (e.g. Russia -> Cloudflare in EU):
	// Total hops ~13-15, domestic border ~8-10.
	switch {
	case totalHops >= 12:
		recommendedFakeTTL = totalHops - 4
	case totalHops >= 8:
		recommendedFakeTTL = totalHops - 3
	default:
		recommendedFakeTTL = totalHops - 2
	}

	if recommendedFakeTTL < 3 {
		recommendedFakeTTL = 3
	}

	return totalHops, recommendedFakeTTL, nil
}
