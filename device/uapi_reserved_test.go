package device

import "testing"

func TestParseReservedValue(t *testing.T) {
	tests := []struct {
		value string
		want  uint32
		ok    bool
	}{
		{"104, 157, 231", 104 | 157<<8 | 231<<16, true},
		{"0x68, 0x9d, 0xe7", 104 | 157<<8 | 231<<16, true},
		{"e79d68", 104 | 157<<8 | 231<<16, true},
		{"", 0, true},
		{"104,157", 0, false},
		{"104,157,999", 0, false},
		{"not-hex", 0, false},
	}
	for _, tc := range tests {
		got, err := parseReservedValue(tc.value)
		if tc.ok && err != nil {
			t.Errorf("parseReservedValue(%q) error: %v", tc.value, err)
			continue
		}
		if !tc.ok && err == nil {
			t.Errorf("parseReservedValue(%q) expected error", tc.value)
			continue
		}
		if got != tc.want {
			t.Errorf("parseReservedValue(%q) = %#x; want %#x", tc.value, got, tc.want)
		}
	}
}
