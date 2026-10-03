/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"testing"
)

func TestMeasureTargetTTL(t *testing.T) {
	totalHops, fakeTTL, err := MeasureTargetTTL("8.34.70.70:500")
	if err != nil {
		t.Logf("Notice: MeasureTargetTTL failed (might be network/permissions): %v", err)
		return
	}

	t.Logf("Measured totalHops=%d, recommendedFakeTTL=%d", totalHops, fakeTTL)
	if totalHops < 3 {
		t.Errorf("unexpected totalHops: %d", totalHops)
	}
	if fakeTTL < 3 || fakeTTL >= totalHops {
		t.Errorf("invalid fakeTTL %d (must be between 3 and %d)", fakeTTL, totalHops)
	}
}
