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

func TestParseDefaultStrategy(t *testing.T) {
	st, err := ParseStrategy("default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(st.Steps) != 5 {
		t.Fatalf("expected 5 steps in default strategy, got %d", len(st.Steps))
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

func TestLegacyRawAliasesBecomeUserspace(t *testing.T) {
	// These aliases used to select raw L3 fragmentation. On non-rooted Android
	// they must resolve to a userspace-safe strategy.
	for _, alias := range []string{"5packet", "early-term", "ipfrag2", "split2", "userspace"} {
		st, err := ParseStrategy(alias)
		if err != nil {
			t.Fatalf("failed to parse alias %s: %v", alias, err)
		}
		if len(st.Steps) != 5 {
			t.Errorf("alias %s: expected 5 userspace steps, got %d", alias, len(st.Steps))
		}
	}

	for _, alias := range []string{"fake", "fake_udp", "fake_packet", "fake,ipfrag2", "fake,split2"} {
		st, err := ParseStrategy(alias)
		if err != nil {
			t.Fatalf("failed to parse alias %s: %v", alias, err)
		}
		if len(st.Steps) != 1 || st.Steps[0].Action != ActionFakeUDP {
			t.Errorf("alias %s: expected a single fake_udp step, got %+v", alias, st.Steps)
		}
		if st.Steps[0].TTL != 0 {
			t.Errorf("alias %s: expected auto TTL, got %d", alias, st.Steps[0].TTL)
		}
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
	if len(st.Warnings) == 0 {
		t.Error("expected a warning for unsupported badsum")
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

func TestParseSleepAndFakeUDP(t *testing.T) {
	input := "junk(64) -> sleep(10ms) -> fake_udp(size=80, ttl=3) -> ipopt_shift(8, mode=nop)"
	st, err := ParseStrategy(input)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(st.Steps) != 4 {
		t.Fatalf("expected 4 steps, got %d", len(st.Steps))
	}
	if st.Steps[1].Action != ActionSleep || st.Steps[1].SleepDur != 10*time.Millisecond {
		t.Errorf("sleep step error: %+v", st.Steps[1])
	}
	if st.Steps[2].Action != ActionFakeUDP || st.Steps[2].Length != 80 || st.Steps[2].TTL != 3 {
		t.Errorf("fake_udp step error: %+v", st.Steps[2])
	}
	if st.Steps[3].Action != ActionIPOptShift || st.Steps[3].Length != 8 || st.Steps[3].IPOptMode != "nop" {
		t.Errorf("ipopt_shift step error: %+v", st.Steps[3])
	}
}

func TestRejectRawFragmentationActions(t *testing.T) {
	for _, input := range []string{
		"frag(8) -> frag(148)",
		"fake_frag(offset=8, len=32, mf=0, ttl=5)",
	} {
		if _, err := ParseStrategy(input); err == nil {
			t.Errorf("expected %q to be rejected on non-rooted Android", input)
		}
	}
}
