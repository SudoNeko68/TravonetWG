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

// ActionType represents an action in the Evasion DSL pipeline.
type ActionType int

const (
	ActionJunk ActionType = iota
	ActionFrag
	ActionFakeFrag
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
	case ActionFrag:
		return "frag"
	case ActionFakeFrag:
		return "fake_frag"
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
	Offset        int           // For ActionFrag, ActionFakeFrag: byte offset (-1 for auto-tracking)
	Length        int           // Length of payload to send
	AutoMF        bool          // Automatically calculate MF based on offset and length
	MF            bool          // More Fragments flag
	TTL           int           // 0 = engine default: NormalTTL for junk/mimic, live FakeTTL for fake_udp/jumbo_fake
	Badsum        bool          // Corrupt UDP checksum (ActionJunk, raw socket only)
	SleepDur      time.Duration // Duration for ActionSleep
	Payload       string        // "random", "zeros", or raw hex (ActionFakeFrag)
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
			if step.Badsum {
				parts = append(parts, fmt.Sprintf("junk(size=%d, badsum=true)", step.Length))
			} else {
				parts = append(parts, fmt.Sprintf("junk(size=%d)", step.Length))
			}
		case ActionFrag:
			if step.Offset >= 0 {
				parts = append(parts, fmt.Sprintf("frag(offset=%d, len=%d, mf=%v, ttl=%d)", step.Offset, step.Length, step.MF, step.TTL))
			} else {
				parts = append(parts, fmt.Sprintf("frag(len=%d, ttl=%d)", step.Length, step.TTL))
			}
		case ActionFakeFrag:
			parts = append(parts, fmt.Sprintf("fake_frag(offset=%d, len=%d, mf=%v, ttl=%d)", step.Offset, step.Length, step.MF, step.TTL))
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

// DefaultStrategy creates the proven 5-step dual-fake L3 evasion pipeline:
// fake(148) -> frag(8) -> frag(72) -> fake(148) -> frag(76)
func DefaultStrategy(fakeTTL, normalTTL int) *Strategy {
	return &Strategy{
		Raw: "fake(148) -> frag(8) -> frag(72) -> fake(148) -> frag(76)",
		Steps: []Step{
			{
				Action: ActionFakeUDP,
				Length: WGHandshakeInitiationSize,
				TTL:    fakeTTL,
			},
			{
				Action: ActionFrag,
				Offset: 0,
				Length: UDPHeaderSize, // 8 bytes (UDP header)
				MF:     true,
				TTL:    normalTTL,
			},
			{
				Action: ActionFrag,
				Offset: UDPHeaderSize, // 8 bytes
				Length: 72,            // 72 bytes
				MF:     true,
				TTL:    normalTTL,
			},
			{
				Action: ActionFakeUDP,
				Length: WGHandshakeInitiationSize,
				TTL:    fakeTTL,
			},
			{
				Action: ActionFrag,
				Offset: UDPHeaderSize + 72,                             // 80 bytes
				Length: WGHandshakeInitiationSize + UDPHeaderSize - 80, // 76 bytes (80 + 76 = 156 bytes total)
				MF:     false,                                          // Real termination for server
				TTL:    normalTTL,
			},
		},
	}
}

// FivePacketStrategy creates the experimental 5-packet early-termination pipeline:
// junk(64) -> frag(8) -> frag(80) -> fake_frag(offset=88, len=32, mf=0, ttl=fakeTTL) -> frag(68)
func FivePacketStrategy(fakeTTL, normalTTL int) *Strategy {
	return &Strategy{
		Raw: "junk(64) -> frag(8) -> frag(80) -> fake_frag(offset=88, len=32, mf=0) -> frag(68)",
		Steps: []Step{
			{
				Action: ActionJunk,
				Length: 64,
				TTL:    normalTTL,
			},
			{
				Action: ActionFrag,
				Offset: 0,
				Length: UDPHeaderSize, // 8 bytes (UDP header)
				MF:     true,
				TTL:    normalTTL,
			},
			{
				Action: ActionFrag,
				Offset: UDPHeaderSize,      // 8 bytes
				Length: DefaultPart1WGSize, // 80 bytes
				MF:     true,
				TTL:    normalTTL,
			},
			{
				Action: ActionFakeFrag,
				Offset: UDPHeaderSize + DefaultPart1WGSize, // 88 bytes
				Length: 32,
				MF:     false, // MF=0 Early Termination poison for DPI
				TTL:    fakeTTL,
			},
			{
				Action: ActionFrag,
				Offset: UDPHeaderSize + DefaultPart1WGSize,                                                 // 88 bytes
				Length: (UDPHeaderSize + WGHandshakeInitiationSize) - (UDPHeaderSize + DefaultPart1WGSize), // 68 bytes
				MF:     false,                                                                              // Real termination for server
				TTL:    normalTTL,
			},
		},
	}
}

// DefaultUserspaceStrategy creates the unprivileged, cellular-safe desync pipeline.
// It relies only on standard unfragmented UDP datagrams without IP Options:
//
//	mimic(quic) -> mimic(stun) -> junk(64) -> fake_udp(148, corrupt=true) -> sleep(15ms)
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

// BroadbandUserspaceStrategy creates the oversized decoy pipeline:
//
//	mimic(quic) -> mimic(stun) -> jumbo_fake(1600) -> fake_udp(148, ipopt=ts) -> sleep(2ms)
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
				Action:    ActionFakeUDP,
				Length:    WGHandshakeInitiationSize,
				IPOptMode: "ts",
			},
			{
				Action:   ActionSleep,
				SleepDur: 2 * time.Millisecond,
			},
		},
	}
}

// ParseStrategy compiles a DSL pipeline string.
// Optional defaults: defaults[0] = defaultFakeTTL, defaults[1] = defaultNormalTTL.
func ParseStrategy(dsl string, defaults ...int) (*Strategy, error) {
	defaultFakeTTL := 0
	defaultNormalTTL := 64
	if len(defaults) > 0 {
		defaultFakeTTL = defaults[0]
	}
	if len(defaults) > 1 && defaults[1] > 0 {
		defaultNormalTTL = defaults[1]
	}

	clean := strings.TrimSpace(dsl)
	if clean == "" || strings.EqualFold(clean, "default") {
		if defaultFakeTTL > 0 {
			return DefaultStrategy(defaultFakeTTL, defaultNormalTTL), nil
		}
		return DefaultUserspaceStrategy(), nil
	}
	if strings.EqualFold(clean, "userspace") || strings.EqualFold(clean, "mobile") || strings.EqualFold(clean, "cellular") {
		return DefaultUserspaceStrategy(), nil
	}
	if strings.EqualFold(clean, "broadband") || strings.EqualFold(clean, "wifi") || strings.EqualFold(clean, "wifi-jumbo") || strings.EqualFold(clean, "jumbo") {
		return BroadbandUserspaceStrategy(), nil
	}
	if strings.EqualFold(clean, "5packet") || strings.EqualFold(clean, "early-term") {
		fakeTTL := defaultFakeTTL
		if fakeTTL <= 0 {
			fakeTTL = 11
		}
		return FivePacketStrategy(fakeTTL, defaultNormalTTL), nil
	}
	if strings.EqualFold(clean, "l3") || strings.EqualFold(clean, "raw") || strings.EqualFold(clean, "dual-fake") {
		fakeTTL := defaultFakeTTL
		if fakeTTL <= 0 {
			fakeTTL = 11
		}
		return DefaultStrategy(fakeTTL, defaultNormalTTL), nil
	}

	// Support Zapret/legacy aliases mentioned in docs
	switch strings.ToLower(clean) {
	case "fake,ipfrag2", "fake,split2":
		clean = "fake_udp(148) -> frag(8) -> frag(148)"
	case "ipfrag2", "split2":
		clean = "frag(8) -> frag(148)"
	case "fake", "fake_udp", "fake_packet":
		clean = "fake_udp(148)"
	}

	// Delimiters can be "->" or ";" or newlines
	normalized := strings.ReplaceAll(clean, "\n", "->")
	normalized = strings.ReplaceAll(normalized, ";", "->")
	rawParts := strings.Split(normalized, "->")

	var steps []Step
	var warnings []string
	currentOffset := 0

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
				Length: 64, // default size
				TTL:    defaultNormalTTL,
			}
			if szStr, ok := namedArgs["size"]; ok {
				step.Length, _ = strconv.Atoi(szStr)
			} else if szStr, ok := namedArgs["len"]; ok {
				step.Length, _ = strconv.Atoi(szStr)
			} else if len(posArgs) > 0 {
				step.Length, _ = strconv.Atoi(posArgs[0])
			}

			if bStr, ok := namedArgs["badsum"]; ok {
				step.Badsum = parseBool(bStr)
			} else if len(posArgs) > 1 {
				step.Badsum = parseBool(posArgs[1])
			}

			if tStr, ok := namedArgs["ttl"]; ok {
				step.TTL, _ = strconv.Atoi(tStr)
			}
			steps = append(steps, step)

		case "frag", "fragment":
			step := Step{
				Action: ActionFrag,
				Offset: currentOffset,
				Length: 0,
				AutoMF: true,
				MF:     true,
				TTL:    defaultNormalTTL,
			}

			// Parse offset / slice
			if sliceStr, ok := namedArgs["slice"]; ok {
				// slice=start:end or slice=offset:len
				parts := strings.Split(sliceStr, ":")
				if len(parts) == 2 {
					start, _ := strconv.Atoi(parts[0])
					end, _ := strconv.Atoi(parts[1])
					step.Offset = start
					step.Length = end - start
				}
			} else {
				if offStr, ok := namedArgs["offset"]; ok {
					step.Offset, _ = strconv.Atoi(offStr)
				}
				if lenStr, ok := namedArgs["len"]; ok {
					step.Length, _ = strconv.Atoi(lenStr)
				} else if szStr, ok := namedArgs["size"]; ok {
					step.Length, _ = strconv.Atoi(szStr)
				} else if len(posArgs) > 0 {
					step.Length, _ = strconv.Atoi(posArgs[0])
				}
			}

			if mfStr, ok := namedArgs["mf"]; ok {
				step.AutoMF = false
				step.MF = parseBool(mfStr)
			}
			if tStr, ok := namedArgs["ttl"]; ok {
				step.TTL, _ = strconv.Atoi(tStr)
			} else if len(posArgs) > 1 {
				step.TTL, _ = strconv.Atoi(posArgs[1])
			}

			if step.Length <= 0 {
				return nil, fmt.Errorf("frag action requires positive length: '%s'", part)
			}

			if step.MF && step.Length%8 != 0 {
				warnings = append(warnings, fmt.Sprintf("fragment '%s': length (%d) is not a multiple of 8 octets; RFC 791 IPv4 reassembly on the receiving endpoint may fail", part, step.Length))
			}

			currentOffset = step.Offset + step.Length
			steps = append(steps, step)

		case "fake_frag", "fakefrag", "fake_fragment":
			step := Step{
				Action: ActionFakeFrag,
				Offset: currentOffset,
				Length: 32, // default 32B noise
				MF:     false,
				TTL:    defaultFakeTTL,
			}

			if offStr, ok := namedArgs["offset"]; ok {
				step.Offset, _ = strconv.Atoi(offStr)
			}
			if lenStr, ok := namedArgs["len"]; ok {
				step.Length, _ = strconv.Atoi(lenStr)
			} else if szStr, ok := namedArgs["size"]; ok {
				step.Length, _ = strconv.Atoi(szStr)
			}

			// Positional fallback: fake_frag(offset, len, mf, ttl)
			if len(posArgs) >= 1 && namedArgs["offset"] == "" && namedArgs["len"] == "" {
				step.Offset, _ = strconv.Atoi(posArgs[0])
			}
			if len(posArgs) >= 2 && namedArgs["len"] == "" {
				step.Length, _ = strconv.Atoi(posArgs[1])
			}
			if len(posArgs) >= 3 && namedArgs["mf"] == "" {
				step.MF = parseBool(posArgs[2])
			} else if mfStr, ok := namedArgs["mf"]; ok {
				step.MF = parseBool(mfStr)
			}

			if tStr, ok := namedArgs["ttl"]; ok {
				step.TTL, _ = strconv.Atoi(tStr)
			} else if len(posArgs) >= 4 {
				step.TTL, _ = strconv.Atoi(posArgs[3])
			}

			if pStr, ok := namedArgs["payload"]; ok {
				step.Payload = pStr
			}

			steps = append(steps, step)

		case "fake_udp", "fakeudp", "fake", "fake_packet":
			step := Step{
				Action: ActionFakeUDP,
				Length: WGHandshakeInitiationSize,
				TTL:    0,
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

		default:
			return nil, fmt.Errorf("unknown strategy action '%s'", actionName)
		}
	}

	if len(steps) == 0 {
		if defaultFakeTTL > 0 {
			return DefaultStrategy(defaultFakeTTL, defaultNormalTTL), nil
		}
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
