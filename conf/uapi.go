/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conf

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

const (
	// DefaultKeepalive is the keepalive injected for peers that do not specify
	// one. Mobile NATs and operator CGNATs drop idle UDP 4-tuples aggressively,
	// and Android's radio sleeps when there is no traffic, so WireGuard's
	// "0 = disabled" default is a poor fit for this target.
	DefaultKeepalive = 10

	// LowPortKeepalive is used for endpoints on UDP port 500 (IKE/IPsec). Such
	// paths are frequently handled by ALGs that rewrite or expire state eagerly.
	LowPortKeepalive = 5

	// LowPortKeepaliveLimit is the highest keepalive accepted on port 500.
	LowPortKeepaliveLimit = 10
)

// UAPIEvasion carries the TravonetWG-specific knobs extracted from a UAPI blob.
// The Has* fields distinguish "not specified" (keep the caller's default) from
// an explicit zero value.
type UAPIEvasion struct {
	Strategy    string
	FakeTTL     int // -1 means "auto" (kernel probe at runtime)
	NormalTTL   int
	PreJunkSize int
	Enabled     bool
	Debug       bool
	MTU         int
	Endpoint    string

	// PersistentKeepalive is the effective keepalive of the last peer. It is
	// reported for diagnostics only; the value that matters is already written
	// into CleanUAPI.
	PersistentKeepalive int

	HasStrategy    bool
	HasFakeTTL     bool
	HasNormalTTL   bool
	HasPreJunkSize bool
	HasEnabled     bool
	HasDebug       bool
	HasMTU         bool
	HasPeer        bool
}

// FilterUAPI strips TravonetWG- and AmneziaWG-specific keys from a UAPI blob and
// returns a string that device.IpcSet accepts.
//
// Two details matter for correctness:
//
//   - persistent_keepalive_interval is a peer-level UAPI key. It must be kept in
//     the peer section it belongs to, never hoisted to a single trailing value,
//     otherwise multi-peer configs silently lose the other peers' keepalives.
//   - Peers without an explicit keepalive get DefaultKeepalive injected inside
//     their own section (WireGuard's own default of 0 is unsuitable on mobile).
func FilterUAPI(settings string) (cleanUAPI string, ev UAPIEvasion) {
	var out []string

	var (
		peerOpen     bool
		curKeepalive int
		curHasKA     bool
		curEndpoint  string
		explicitPre  bool
	)

	finalizePeer := func() {
		if !peerOpen {
			return
		}
		keepalive := curKeepalive
		if !curHasKA {
			keepalive = DefaultKeepalive
		}
		if IsPort500Endpoint(curEndpoint) && (keepalive == 0 || keepalive > LowPortKeepaliveLimit) {
			keepalive = LowPortKeepalive
		}
		if keepalive > 0 {
			out = append(out, fmt.Sprintf("persistent_keepalive_interval=%d", keepalive))
		}
		ev.PersistentKeepalive = keepalive
		peerOpen = false
		curKeepalive = 0
		curHasKA = false
		curEndpoint = ""
	}

	scanner := bufio.NewScanner(strings.NewReader(settings))
	// UAPI blobs are small, but allow long lines (e.g. base64 comments) without
	// silently truncating the config.
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		switch key {
		case "strategy":
			ev.Strategy, ev.HasStrategy = val, true
			continue

		case "fake_ttl", "fakettl":
			ev.HasFakeTTL = true
			if strings.EqualFold(val, "auto") {
				ev.FakeTTL = -1
			} else if v, convErr := strconv.Atoi(val); convErr == nil {
				ev.FakeTTL = v
			}
			continue

		case "normal_ttl", "normalttl":
			if v, convErr := strconv.Atoi(val); convErr == nil && v > 0 {
				ev.NormalTTL, ev.HasNormalTTL = v, true
			}
			continue

		case "pre_junk", "prejunk", "pre_junksize", "prejunksize":
			if v, convErr := strconv.Atoi(val); convErr == nil {
				ev.PreJunkSize, ev.HasPreJunkSize = v, true
				explicitPre = true
			}
			continue

		case "jmin":
			// AmneziaWG compatibility: jmin maps to PreJunkSize, but an explicit
			// PreJunk setting always wins regardless of ordering.
			if v, convErr := strconv.Atoi(val); convErr == nil && !explicitPre {
				ev.PreJunkSize, ev.HasPreJunkSize = v, true
			}
			out = append(out, line)
			continue

		case "noevasion", "no_evasion", "disableevasion", "disable_evasion":
			ev.HasEnabled = true
			ev.Enabled = !parseBoolValue(val)
			continue

		case "debug", "evasion_debug":
			ev.HasDebug = true
			ev.Debug = parseBoolValue(val)
			continue

		case "mtu":
			if v, convErr := strconv.Atoi(val); convErr == nil && v > 0 {
				ev.MTU, ev.HasMTU = v, true
			}
			continue

		case "public_key":
			// A new peer starts: finalize the previous one first so its
			// keepalive lands in the right section.
			finalizePeer()
			peerOpen = true
			ev.HasPeer = true

		case "endpoint":
			curEndpoint = val
			ev.Endpoint = val
			out = append(out, "endpoint="+ResolveEndpointHostPort(val))
			continue

		case "persistent_keepalive_interval", "persistentkeepalive":
			if v, convErr := strconv.Atoi(val); convErr == nil {
				curKeepalive, curHasKA = v, true
			}
			continue
		}

		out = append(out, line)
	}
	finalizePeer()

	return strings.Join(out, "\n") + "\n", ev
}

func parseBoolValue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
