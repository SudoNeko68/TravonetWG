//go:build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// measureTTLViaErrQueue on non-Linux platforms uses tracert or ping fallback.
func measureTTLViaErrQueue(targetIP net.IP, port int) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tracertPath, err := exec.LookPath("tracert")
	if err != nil {
		return 0, fmt.Errorf("tracert not found: %w", err)
	}

	cmd := exec.CommandContext(ctx, tracertPath, "-d", "-h", "16", "-w", "500", targetIP.String())
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return 0, fmt.Errorf("tracert failed: %w", err)
	}

	maxHop := 0
	destFound := false
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			hopNum, err := strconv.Atoi(fields[0])
			if err != nil {
				continue
			}
			maxHop = hopNum
			for _, f := range fields[1:] {
				if f == targetIP.String() {
					destFound = true
					break
				}
			}
			if destFound {
				break
			}
		}
	}
	if maxHop == 0 {
		return 0, fmt.Errorf("no responding hops")
	}
	if destFound {
		return maxHop, nil
	}
	return maxHop + 1, nil
}

func probeHopsViaDNS() (int, error) {
	return 0, fmt.Errorf("DNS TTL probe not supported on this platform")
}
