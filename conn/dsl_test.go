/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"testing"
	"time"
)

func TestParseDefaultL3Strategy(t *testing.T) {
	st, err := ParseStrategy("default", 10, 64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(st.Steps) != 5 {
		t.Fatalf("expected 5 steps in default L3 strategy, got %d", len(st.Steps))
	}

	// 1. Fake UDP 1 (148 bytes, TTL=10)
	if st.Steps[0].Action != ActionFakeUDP || st.Steps[0].Length != 148 || st.Steps[0].TTL != 10 {
		t.Errorf("step 0 mismatch: %+v", st.Steps[0])
	}
	// 2. Frag 1 (8 bytes UDP header, MF=true)
	if st.Steps[1].Action != ActionFrag || st.Steps[1].Length != 8 || st.Steps[1].Offset != 0 || !st.Steps[1].MF {
		t.Errorf("step 1 mismatch: %+v", st.Steps[1])
	}
	// 3. Frag 2 (72 bytes WG payload, MF=true)
	if st.Steps[2].Action != ActionFrag || st.Steps[2].Length != 72 || st.Steps[2].Offset != 8 || !st.Steps[2].MF {
		t.Errorf("step 2 mismatch: %+v", st.Steps[2])
	}
	// 4. Fake UDP 2 (148 bytes, TTL=10)
	if st.Steps[3].Action != ActionFakeUDP || st.Steps[3].Length != 148 || st.Steps[3].TTL != 10 {
		t.Errorf("step 3 mismatch: %+v", st.Steps[3])
	}
	// 5. Frag 3 (76 bytes WG payload, MF=false, TTL=64)
	if st.Steps[4].Action != ActionFrag || st.Steps[4].Length != 76 || st.Steps[4].Offset != 80 || st.Steps[4].MF != false {
		t.Errorf("step 4 mismatch: %+v", st.Steps[4])
	}
}

func TestParseDefaultUserspaceStrategy(t *testing.T) {
	st, err := ParseStrategy("default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(st.Steps) != 5 {
		t.Fatalf("expected 5 steps in default userspace strategy, got %d", len(st.Steps))
	}

	if st.Steps[0].Action != ActionMimic || st.Steps[0].MimicProto != "quic" {
		t.Errorf("step 0 mismatch: %+v", st.Steps[0])
	}
	if st.Steps[1].Action != ActionMimic || st.Steps[1].MimicProto != "stun" {
		t.Errorf("step 1 mismatch: %+v", st.Steps[1])
	}
	if st.Steps[2].Action != ActionJunk || st.Steps[2].Length != 64 {
		t.Errorf("step 2 mismatch: %+v", st.Steps[2])
	}
	if st.Steps[3].Action != ActionFakeUDP || st.Steps[3].Length != 148 || !st.Steps[3].CorruptHeader || st.Steps[3].IPOptMode != "" {
		t.Errorf("step 3 mismatch: %+v", st.Steps[3])
	}
	if st.Steps[4].Action != ActionSleep || st.Steps[4].SleepDur != 15*time.Millisecond {
		t.Errorf("step 4 mismatch: %+v", st.Steps[4])
	}
}

func TestParseBroadbandStrategy(t *testing.T) {
	st, err := ParseStrategy("broadband")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(st.Steps) != 5 {
		t.Fatalf("expected 5 steps in broadband strategy, got %d", len(st.Steps))
	}
	if st.Steps[2].Action != ActionJumboFake || st.Steps[2].Length != 1600 {
		t.Errorf("step 2 mismatch: %+v", st.Steps[2])
	}
	if st.Steps[3].Action != ActionFakeUDP || st.Steps[3].IPOptMode != "ts" {
		t.Errorf("step 3 mismatch: %+v", st.Steps[3])
	}
}

func TestParseFivePacketStrategy(t *testing.T) {
	st, err := ParseStrategy("5packet", 3, 64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(st.Steps) != 5 {
		t.Fatalf("expected 5 steps in 5packet strategy, got %d", len(st.Steps))
	}

	if st.Steps[0].Action != ActionJunk || st.Steps[0].Length != 64 {
		t.Errorf("step 0 mismatch: %+v", st.Steps[0])
	}
	if st.Steps[1].Action != ActionFrag || st.Steps[1].Length != 8 || st.Steps[1].Offset != 0 || !st.Steps[1].MF {
		t.Errorf("step 1 mismatch: %+v", st.Steps[1])
	}
	if st.Steps[2].Action != ActionFrag || st.Steps[2].Length != 80 || st.Steps[2].Offset != 8 || !st.Steps[2].MF {
		t.Errorf("step 2 mismatch: %+v", st.Steps[2])
	}
	if st.Steps[3].Action != ActionFakeFrag || st.Steps[3].Length != 32 || st.Steps[3].Offset != 88 || st.Steps[3].MF != false || st.Steps[3].TTL != 3 {
		t.Errorf("step 3 mismatch: %+v", st.Steps[3])
	}
	if st.Steps[4].Action != ActionFrag || st.Steps[4].Length != 68 || st.Steps[4].Offset != 88 || st.Steps[4].MF != false {
		t.Errorf("step 4 mismatch: %+v", st.Steps[4])
	}
}

func TestParseCustomPipeline(t *testing.T) {
	input := "junk(size=128, badsum=true) -> frag(len=16) -> fake_frag(offset=16, len=48, mf=0, ttl=4) -> frag(len=140)"
	st, err := ParseStrategy(input, 3, 64)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(st.Steps) != 4 {
		t.Fatalf("expected 4 steps, got %d", len(st.Steps))
	}

	if st.Steps[0].Action != ActionJunk || st.Steps[0].Length != 128 || !st.Steps[0].Badsum {
		t.Errorf("step 0 error: %+v", st.Steps[0])
	}
	if st.Steps[1].Action != ActionFrag || st.Steps[1].Length != 16 || st.Steps[1].Offset != 0 {
		t.Errorf("step 1 error: %+v", st.Steps[1])
	}
	if st.Steps[2].Action != ActionFakeFrag || st.Steps[2].Offset != 16 || st.Steps[2].Length != 48 || st.Steps[2].MF || st.Steps[2].TTL != 4 {
		t.Errorf("step 2 error: %+v", st.Steps[2])
	}
	if st.Steps[3].Action != ActionFrag || st.Steps[3].Offset != 16 || st.Steps[3].Length != 140 {
		t.Errorf("step 3 error: %+v", st.Steps[3])
	}
}

func TestParseSleepAndFakeUDP(t *testing.T) {
	input := "junk(64) -> sleep(10ms) -> fake_udp(size=80, ttl=3) -> frag(8) -> frag(148)"
	st, err := ParseStrategy(input, 3, 64)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(st.Steps) != 5 {
		t.Fatalf("expected 5 steps, got %d", len(st.Steps))
	}
	if st.Steps[1].Action != ActionSleep || st.Steps[1].SleepDur != 10*time.Millisecond {
		t.Errorf("sleep error: %+v", st.Steps[1])
	}
	if st.Steps[2].Action != ActionFakeUDP || st.Steps[2].Length != 80 || st.Steps[2].TTL != 3 {
		t.Errorf("fake_udp error: %+v", st.Steps[2])
	}
}

func TestParseCustomUserspacePipeline(t *testing.T) {
	input := "junk(size=128, badsum=true) -> mimic(quic) -> fake_udp(size=148, ttl=4, corrupt=true) -> sleep(5ms)"
	st, err := ParseStrategy(input)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(st.Steps) != 4 {
		t.Fatalf("expected 4 steps, got %d", len(st.Steps))
	}
	if st.Steps[0].Action != ActionJunk || st.Steps[0].Length != 128 {
		t.Errorf("step 0 error: %+v", st.Steps[0])
	}
	if st.Steps[1].Action != ActionMimic || st.Steps[1].MimicProto != "quic" {
		t.Errorf("step 1 error: %+v", st.Steps[1])
	}
	if st.Steps[2].Action != ActionFakeUDP || st.Steps[2].Length != 148 || st.Steps[2].TTL != 4 || !st.Steps[2].CorruptHeader {
		t.Errorf("step 2 error: %+v", st.Steps[2])
	}
	if st.Steps[3].Action != ActionSleep || st.Steps[3].SleepDur != 5*time.Millisecond {
		t.Errorf("step 3 error: %+v", st.Steps[3])
	}
}

func TestParseStrategyValidationWarnings(t *testing.T) {
	// Offset not multiple of 8
	input := "frag(offset=0, len=10, mf=true) -> frag(offset=10, len=138, mf=false)"
	st, err := ParseStrategy(input, 3, 64)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(st.Warnings) == 0 {
		t.Errorf("expected warning for non-multiple-of-8 fragment length, got none")
	}
}
