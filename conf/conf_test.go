package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsPort500Endpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		expected bool
	}{
		{"162.159.192.1:500", true},
		{"8.34.70.70:500", true},
		{"[2606:4700:d0::a29f:c001]:500", true},
		{"example.com:500", true},
		{"162.159.192.1:51820", false},
		{"162.159.192.1:2408", false},
		{"8.34.70.70:5000", false},
		{"", false},
	}

	for _, tc := range tests {
		got := IsPort500Endpoint(tc.endpoint)
		if got != tc.expected {
			t.Errorf("IsPort500Endpoint(%q) = %v; want %v", tc.endpoint, got, tc.expected)
		}
	}
}

func TestConfigKeepaliveParsingAndDefaults(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []struct {
		name             string
		content          string
		wantKeepalive    int
		expectUAPIAssert string
	}{
		{
			name: "Standard peer PersistentKeepalive",
			content: `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:2408
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
`,
			wantKeepalive:    15,
			expectUAPIAssert: "persistent_keepalive_interval=15",
		},
		{
			name: "Underscore variation Persistent_Keepalive",
			content: `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:2408
AllowedIPs = 0.0.0.0/0
Persistent_Keepalive = 12
`,
			wantKeepalive:    12,
			expectUAPIAssert: "persistent_keepalive_interval=12",
		},
		{
			name: "Interface level keepalive fallback",
			content: `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32
Persistent_Keepalive = 14

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:2408
AllowedIPs = 0.0.0.0/0
`,
			wantKeepalive:    14,
			expectUAPIAssert: "persistent_keepalive_interval=14",
		},
		{
			name: "Default keepalive when omitted",
			content: `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:2408
AllowedIPs = 0.0.0.0/0
`,
			wantKeepalive:    10,
			expectUAPIAssert: "persistent_keepalive_interval=10",
		},
		{
			name: "Port 500 endpoint clamps keepalive to 5s",
			content: `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 8.34.70.70:500
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`,
			wantKeepalive:    5,
			expectUAPIAssert: "persistent_keepalive_interval=5",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			confPath := filepath.Join(tempDir, tc.name+".conf")
			if err := os.WriteFile(confPath, []byte(tc.content), 0600); err != nil {
				t.Fatalf("Failed to write test conf: %v", err)
			}

			cfg, err := ParseConfigFile(confPath)
			if err != nil {
				t.Fatalf("ParseConfigFile failed: %v", err)
			}

			if cfg.PersistentKeepalive != tc.wantKeepalive {
				t.Errorf("PersistentKeepalive = %d; want %d", cfg.PersistentKeepalive, tc.wantKeepalive)
			}

			uapi, err := cfg.ToUAPI()
			if err != nil {
				t.Fatalf("ToUAPI failed: %v", err)
			}

			if !strings.Contains(uapi, tc.expectUAPIAssert) {
				t.Errorf("ToUAPI output missing expected substring %q:\n%s", tc.expectUAPIAssert, uapi)
			}
		})
	}
}
