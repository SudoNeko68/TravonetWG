/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ActionType represents an action in the userspace Evasion DSL pipeline.
type ActionType int

const (
	ActionJunk ActionType = iota
	ActionFakeUDP
	ActionSleep
	ActionMimic
	ActionJumboFake
	ActionIPOptShift
)

func (a ActionType) String() string {
	switch a {
	case ActionJunk:
		return "junk"
	case ActionFakeUDP:
		return "fake_udp"
	case ActionSleep:
		return "sleep"
	case ActionMimic:
		return "mimic"
	case ActionJumboFake:
		return "jumbo_fake"
	case ActionIPOptShift:
		return "ipopt_shift"
	default:
		return "unknown"
	}
}

// Step represents a single compiled instruction in an evasion strategy.
type Step struct {
	Action        ActionType
	Length        int           // Length of the UDP payload for this step
	TTL           int           // 0 = engine default: NormalTTL for junk/mimic, live FakeTTL for fake_udp/jumbo_fake
	SleepDur      time.Duration // Duration for ActionSleep
	MimicProto    string        // "stun", "quic" or "dns" for ActionMimic
	IPOptMode     string        // "nop", "ts", "rr" or "none" for IPv4 options
	CorruptHeader bool          // Corrupt the fake WireGuard header to avoid stateless bans
}

// Strategy contains compiled pipeline steps.
type Strategy struct {
	Raw      string
	Steps    []Step
	Warnings []string
}

func (s *Strategy) String() string {
	if s == nil || len(s.Steps) == 0 {
		return "none"
	}
	var parts []string
	for _, step := range s.Steps {
		switch step.Action {
		case ActionJunk:
			parts = append(parts, fmt.Sprintf("junk(size=%d)", step.Length))
		case ActionFakeUDP:
			parts = append(parts, fmt.Sprintf("fake_udp(size=%d, ttl=%s, corrupt=%v, ipopt=%s)", step.Length, formatTTL(step.TTL), step.CorruptHeader, step.IPOptMode))
		case ActionSleep:
			parts = append(parts, fmt.Sprintf("sleep(%v)", step.SleepDur))
		case ActionMimic:
			parts = append(parts, fmt.Sprintf("mimic(%s)", step.MimicProto))
		case ActionJumboFake:
			parts = append(parts, fmt.Sprintf("jumbo_fake(size=%d, ttl=%s)", step.Length, formatTTL(step.TTL)))
		case ActionIPOptShift:
			parts = append(parts, fmt.Sprintf("ipopt_shift(%d, mode=%s)", step.Length, step.IPOptMode))
		}
	}
	return strings.Join(parts, " -> ")
}

// formatTTL renders a step TTL for logs. TTL 0 means "resolve at send time".
func formatTTL(ttl int) string {
	if ttl <= 0 {
		return "auto"
	}
	return strconv.Itoa(ttl)
}

// DefaultUserspaceStrategy creates the unprivileged, mobile-safe Android desync pipeline.
// It relies only on standard unfragmented UDP datagrams without IP Options:
//
//	mimic(quic) -> mimic(stun) -> junk(64) -> fake_udp(148, corrupt=true) -> sleep(15ms)
//
// The legitimate WireGuard handshake is appended by the caller.
//
// Key mobile-safe design choices:
//   - No IP Options (ipopt): cellular carriers (LTE/5G PGW/UPF) drop packets with IP Options (IHL > 5).
//   - No L3 fragmentation (jumbo_fake): cellular networks drop UDP fragments.
//   - All packets fit within mobile MTU (<= 1200 bytes).
//   - 15ms sleep allows cellular radio scheduling (PUCCH/PUSCH BSR) to serialize decoys before the real handshake.
//
// Steps are compiled with TTL 0, meaning "resolve at send time": mimic and junk
// packets use NormalTTL, while fake_udp uses the bind's live FakeTTL (defaulting to 7 on Android).
func DefaultUserspaceStrategy() *Strategy {
	return &Strategy{
		Raw: "mimic(quic) -> mimic(stun) -> junk(size=64) -> fake_udp(size=148, corrupt=true) -> sleep(15ms)",
		Steps: []Step{
			{
				Action:     ActionMimic,
				MimicProto: "quic",
			},
			{
				Action:     ActionMimic,
				MimicProto: "stun",
			},
			{
				Action: ActionJunk,
				Length: 64,
			},
			{
				Action:        ActionFakeUDP,
				Length:        WGHandshakeInitiationSize,
				CorruptHeader: true,
			},
			{
				Action:   ActionSleep,
				SleepDur: 15 * time.Millisecond,
			},
		},
	}
}

// BroadbandUserspaceStrategy provides the legacy oversized decoy strategy
// for wired broadband / Wi-Fi connections that do not drop IP Options or fragments.
func BroadbandUserspaceStrategy() *Strategy {
	return &Strategy{
		Raw: "mimic(quic) -> mimic(stun) -> jumbo_fake(size=1600) -> fake_udp(size=148, ipopt=ts) -> sleep(2ms)",
		Steps: []Step{
			{
				Action:     ActionMimic,
				MimicProto: "quic",
			},
			{
				Action:     ActionMimic,
				MimicProto: "stun",
			},
			{
				Action: ActionJumboFake,
				Length: 1600,
			},
			{
				Action:        ActionFakeUDP,
				Length:        WGHandshakeInitiationSize,
				IPOptMode:     "ts",
				CorruptHeader: true,
			},
			{
				Action:   ActionSleep,
				SleepDur: 2 * time.Millisecond,
			},
		},
	}
}

// ParseStrategy compiles a userspace DSL pipeline string. Only actions that can
// be executed without CAP_NET_RAW are accepted; raw L3 fragmentation actions
// are deliberately rejected and cause the caller to fall back to the default
// userspace pipeline.
func ParseStrategy(dsl string) (*Strategy, error) {
	clean := strings.TrimSpace(dsl)
	switch strings.ToLower(clean) {
	case "", "default", "default-userspace", "userspace", "mobile", "mobile-safe", "5packet", "early-term", "ipfrag2", "split2":
		return DefaultUserspaceStrategy(), nil
	case "broadband", "wifi", "wifi-jumbo", "jumbo":
		return BroadbandUserspaceStrategy(), nil
	case "fake,ipfrag2", "fake,split2", "fake", "fake_udp", "fake_packet":
		// Old raw-fragmentation aliases degrade to the userspace fake packet.
		clean = "fake_udp(148)"
	}

	// Delimiters can be "->" or ";" or newlines.
	normalized := strings.ReplaceAll(clean, "\n", "->")
	normalized = strings.ReplaceAll(normalized, ";", "->")
	rawParts := strings.Split(normalized, "->")

	var steps []Step
	var warnings []string

	for _, part := range rawParts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		openParen := strings.Index(part, "(")
		closeParen := strings.LastIndex(part, ")")
		if openParen < 0 || closeParen <= openParen {
			return nil, fmt.Errorf("invalid action syntax '%s': expected action_name(args...)", part)
		}

		actionName := strings.ToLower(strings.TrimSpace(part[:openParen]))
		argsStr := strings.TrimSpace(part[openParen+1 : closeParen])

		argsList := splitArgs(argsStr)
		namedArgs := make(map[string]string)
		var posArgs []string

		for _, arg := range argsList {
			arg = strings.TrimSpace(arg)
			if arg == "" {
				continue
			}
			if eqIdx := strings.Index(arg, "="); eqIdx > 0 {
				k := strings.ToLower(strings.TrimSpace(arg[:eqIdx]))
				v := strings.TrimSpace(arg[eqIdx+1:])
				namedArgs[k] = v
			} else {
				posArgs = append(posArgs, arg)
			}
		}

		switch actionName {
		case "junk", "udp_junk", "pre_junk":
			step := Step{
				Action: ActionJunk,
				Length: 64,
			}
			if szStr, ok := namedArgs["size"]; ok {
				step.Length, _ = strconv.Atoi(szStr)
			} else if szStr, ok := namedArgs["len"]; ok {
				step.Length, _ = strconv.Atoi(szStr)
			} else if len(posArgs) > 0 {
				step.Length, _ = strconv.Atoi(posArgs[0])
			}
			if bStr, ok := namedArgs["badsum"]; ok && parseBool(bStr) {
				warnings = append(warnings, fmt.Sprintf("junk '%s': badsum requires a raw socket and is ignored on Android", part))
			}
			if tStr, ok := namedArgs["ttl"]; ok {
				step.TTL, _ = strconv.Atoi(tStr)
			}
			steps = append(steps, step)

		case "fake_udp", "fakeudp", "fake", "fake_packet":
			step := Step{
				Action: ActionFakeUDP,
				Length: WGHandshakeInitiationSize,
			}
			if szStr, ok := namedArgs["size"]; ok {
				step.Length, _ = strconv.Atoi(szStr)
			} else if szStr, ok := namedArgs["len"]; ok {
				step.Length, _ = strconv.Atoi(szStr)
			} else if len(posArgs) > 0 {
				step.Length, _ = strconv.Atoi(posArgs[0])
			}

			if tStr, ok := namedArgs["ttl"]; ok {
				step.TTL, _ = strconv.Atoi(tStr)
			} else if len(posArgs) > 1 {
				step.TTL, _ = strconv.Atoi(posArgs[1])
			}

			if ipOpt, ok := namedArgs["ipopt"]; ok {
				step.IPOptMode = strings.ToLower(ipOpt)
			}
			if corrupt, ok := namedArgs["corrupt"]; ok {
				step.CorruptHeader = parseBool(corrupt)
			}

			steps = append(steps, step)

		case "mimic", "mimicry":
			step := Step{
				Action:     ActionMimic,
				MimicProto: "stun",
			}
			if proto, ok := namedArgs["proto"]; ok {
				step.MimicProto = strings.ToLower(proto)
			} else if len(posArgs) > 0 {
				step.MimicProto = strings.ToLower(posArgs[0])
			}
			switch step.MimicProto {
			case "stun", "quic", "dns":
			default:
				return nil, fmt.Errorf("mimic action requires one of stun/quic/dns, got '%s'", step.MimicProto)
			}
			if tStr, ok := namedArgs["ttl"]; ok {
				step.TTL, _ = strconv.Atoi(tStr)
			}
			steps = append(steps, step)

		case "jumbo_fake", "jumbofake", "jumbo":
			step := Step{
				Action: ActionJumboFake,
				Length: 1600,
			}
			if szStr, ok := namedArgs["size"]; ok {
				step.Length, _ = strconv.Atoi(szStr)
			} else if szStr, ok := namedArgs["len"]; ok {
				step.Length, _ = strconv.Atoi(szStr)
			} else if len(posArgs) > 0 {
				step.Length, _ = strconv.Atoi(posArgs[0])
			}
			if step.Length < 1500 {
				step.Length = 1500
			}
			if tStr, ok := namedArgs["ttl"]; ok {
				step.TTL, _ = strconv.Atoi(tStr)
			} else if len(posArgs) > 1 {
				step.TTL, _ = strconv.Atoi(posArgs[1])
			}
			steps = append(steps, step)

		case "ipopt_shift", "ipoptshift", "ipopt":
			step := Step{
				Action:    ActionIPOptShift,
				Length:    40,
				IPOptMode: "nop",
			}
			if szStr, ok := namedArgs["size"]; ok {
				step.Length, _ = strconv.Atoi(szStr)
			} else if szStr, ok := namedArgs["len"]; ok {
				step.Length, _ = strconv.Atoi(szStr)
			} else if len(posArgs) > 0 {
				step.Length, _ = strconv.Atoi(posArgs[0])
			}
			step.Length = (step.Length / 4) * 4
			if step.Length < 0 {
				step.Length = 0
			}
			if step.Length > 40 {
				step.Length = 40
			}
			if mode, ok := namedArgs["mode"]; ok {
				step.IPOptMode = strings.ToLower(mode)
			} else if len(posArgs) > 1 {
				step.IPOptMode = strings.ToLower(posArgs[1])
			}
			switch step.IPOptMode {
			case "nop", "ts", "rr":
			case "none", "":
				step.IPOptMode = "nop"
			default:
				return nil, fmt.Errorf("ipopt_shift: unsupported mode '%s'", step.IPOptMode)
			}
			steps = append(steps, step)

		case "sleep", "delay":
			step := Step{
				Action: ActionSleep,
			}
			var durStr string
			if d, ok := namedArgs["dur"]; ok {
				durStr = d
			} else if d, ok := namedArgs["ms"]; ok {
				durStr = d + "ms"
			} else if len(posArgs) > 0 {
				durStr = posArgs[0]
				if !strings.HasSuffix(durStr, "ms") && !strings.HasSuffix(durStr, "s") {
					durStr += "ms"
				}
			}
			dur, err := time.ParseDuration(durStr)
			if err != nil {
				return nil, fmt.Errorf("invalid sleep duration '%s': %w", durStr, err)
			}
			step.SleepDur = dur
			steps = append(steps, step)

		case "frag", "fragment", "fake_frag", "fakefrag", "fake_fragment":
			return nil, fmt.Errorf("action '%s' requires a raw socket (CAP_NET_RAW) and is not available on non-rooted Android", actionName)

		default:
			return nil, fmt.Errorf("unknown strategy action '%s'", actionName)
		}
	}

	if len(steps) == 0 {
		return DefaultUserspaceStrategy(), nil
	}

	return &Strategy{
		Raw:      clean,
		Steps:    steps,
		Warnings: warnings,
	}, nil
}

func splitArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inQuotes := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\'':
			inQuotes = !inQuotes
		case ',':
			if inQuotes {
				cur.WriteByte(c)
			} else {
				args = append(args, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		args = append(args, strings.TrimSpace(cur.String()))
	}
	return args
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "1" || s == "true" || s == "yes" || s == "on"
}
