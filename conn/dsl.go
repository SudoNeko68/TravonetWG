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

// ActionType represents an action in the Evasion DSL pipeline
type ActionType int

const (
	ActionJunk ActionType = iota
	ActionFrag
	ActionFakeFrag
	ActionFakeUDP
	ActionSleep
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
	default:
		return "unknown"
	}
}

// Step represents a single compiled instruction in an evasion strategy
type Step struct {
	Action   ActionType
	Offset   int           // Byte offset (-1 for auto-tracking from previous frag)
	Length   int           // Length of payload to send
	AutoMF   bool          // If true, MF is calculated based on reaching end of packet
	MF       bool          // More Fragments flag
	TTL      int           // TTL for this packet (0 = default normal TTL)
	Badsum   bool          // Corrupt UDP checksum (for junk/fake_udp)
	SleepDur time.Duration // Duration for ActionSleep
	Payload  string        // "random", "zeros", or raw hex
}

// Strategy contains compiled pipeline steps
type Strategy struct {
	Raw   string
	Steps []Step
}

func (s *Strategy) String() string {
	if s == nil || len(s.Steps) == 0 {
		return "none"
	}
	var parts []string
	for _, step := range s.Steps {
		switch step.Action {
		case ActionJunk:
			parts = append(parts, fmt.Sprintf("junk(size=%d, badsum=%v)", step.Length, step.Badsum))
		case ActionFrag:
			if step.Offset >= 0 {
				parts = append(parts, fmt.Sprintf("frag(offset=%d, len=%d, mf=%v, ttl=%d)", step.Offset, step.Length, step.MF, step.TTL))
			} else {
				parts = append(parts, fmt.Sprintf("frag(len=%d, ttl=%d)", step.Length, step.TTL))
			}
		case ActionFakeFrag:
			parts = append(parts, fmt.Sprintf("fake_frag(offset=%d, len=%d, mf=%v, ttl=%d)", step.Offset, step.Length, step.MF, step.TTL))
		case ActionFakeUDP:
			parts = append(parts, fmt.Sprintf("fake_udp(size=%d, ttl=%d)", step.Length, step.TTL))
		case ActionSleep:
			parts = append(parts, fmt.Sprintf("sleep(%v)", step.SleepDur))
		}
	}
	return strings.Join(parts, " -> ")
}

// DefaultStrategy creates the proven working evasion pipeline (Zapret Fake UDP + IPFrag2):
// junk(64) -> fake_udp(148, ttl=fakeTTL) -> frag(8) -> frag(148)
func DefaultStrategy(fakeTTL, normalTTL int) *Strategy {
	return &Strategy{
		Raw: "junk(64) -> fake_udp(148) -> frag(8) -> frag(148)",
		Steps: []Step{
			{
				Action: ActionJunk,
				Length: 64,
				TTL:    normalTTL,
			},
			{
				Action: ActionFakeUDP,
				Length: WGHandshakeInitiationSize, // 148 bytes (with 0x01 Handshake Initiation type)
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
				Offset: UDPHeaderSize,             // 8 bytes
				Length: WGHandshakeInitiationSize, // 148 bytes
				MF:     false,                     // Real termination for server
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

// ParseStrategy compiles a DSL pipeline string (e.g. "junk(64) -> frag(8) -> frag(80) -> fake_frag(88, 32, 0, 3) -> frag(68)")
func ParseStrategy(dsl string, defaultFakeTTL, defaultNormalTTL int) (*Strategy, error) {
	clean := strings.TrimSpace(dsl)
	if clean == "" || strings.EqualFold(clean, "default") {
		return DefaultStrategy(defaultFakeTTL, defaultNormalTTL), nil
	}
	if strings.EqualFold(clean, "5packet") || strings.EqualFold(clean, "early-term") {
		return FivePacketStrategy(defaultFakeTTL, defaultNormalTTL), nil
	}

	// Delimiters can be "->" or ";" or newlines
	normalized := strings.ReplaceAll(clean, "\n", "->")
	normalized = strings.ReplaceAll(normalized, ";", "->")
	rawParts := strings.Split(normalized, "->")

	var steps []Step
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

			currentOffset = step.Offset + step.Length
			steps = append(steps, step)

		case "fake_frag", "fakefrag", "fake_fragment":
			step := Step{
				Action: ActionFakeFrag,
				Offset: currentOffset,
				Length: 32,    // default 32B noise
				MF:     false, // default false (Early-Termination trick!)
				TTL:    defaultFakeTTL,
			}

			if offStr, ok := namedArgs["offset"]; ok {
				step.Offset, _ = strconv.Atoi(offStr)
			} else if len(posArgs) > 0 && strings.Contains(part, "offset=") {
				// handled by named
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

		case "fake_udp", "fakeudp":
			step := Step{
				Action: ActionFakeUDP,
				Length: 64,
				TTL:    defaultFakeTTL,
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
		return DefaultStrategy(defaultFakeTTL, defaultNormalTTL), nil
	}

	return &Strategy{
		Raw:   clean,
		Steps: steps,
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
