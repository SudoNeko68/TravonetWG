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

func TestMultiplePeersAndPSK(t *testing.T) {
	confContent := `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
Endpoint = 192.168.1.1:51820
AllowedIPs = 10.0.0.0/24

[Peer]
PublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
Endpoint = 192.168.2.1:51820
AllowedIPs = 10.0.1.0/24
PersistentKeepalive = 15
`
	cfg, err := ParseConfigString(confContent)
	if err != nil {
		t.Fatalf("ParseConfigString failed: %v", err)
	}

	if len(cfg.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(cfg.Peers))
	}

	if cfg.Peers[0].PresharedKey != "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=" {
		t.Errorf("peer 0 PSK mismatch: %s", cfg.Peers[0].PresharedKey)
	}
	if cfg.Peers[1].PersistentKeepalive != 15 {
		t.Errorf("peer 1 keepalive mismatch: %d", cfg.Peers[1].PersistentKeepalive)
	}

	uapi, err := cfg.ToUAPI()
	if err != nil {
		t.Fatalf("ToUAPI failed: %v", err)
	}

	if !strings.Contains(uapi, "preshared_key=") {
		t.Errorf("ToUAPI missing preshared_key:\n%s", uapi)
	}
	if strings.Count(uapi, "public_key=") != 2 {
		t.Errorf("expected 2 public_key in ToUAPI, got count %d:\n%s", strings.Count(uapi, "public_key="), uapi)
	}
}

func TestConfigEvasionFlags(t *testing.T) {
	const header = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32
`

	cfg, err := ParseConfig(strings.NewReader(header))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.DebugSet {
		t.Error("DebugSet must stay false when the key is absent")
	}
	if cfg.NoEvasion {
		t.Error("NoEvasion must default to false")
	}

	cfg, err = ParseConfig(strings.NewReader(header + "Debug = false\nNoEvasion = true\n"))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if !cfg.DebugSet {
		t.Error("DebugSet must be true for an explicit Debug key")
	}
	if cfg.Debug {
		t.Error("Debug = false must be recorded as false")
	}
	if !cfg.NoEvasion {
		t.Error("NoEvasion = true must disable the evasion engine")
	}
}

func TestAmneziaConfigParsing(t *testing.T) {
	confContent := `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 172.16.0.2/32
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 30
S2 = 20
S3 = 10
S4 = 15
H1 = 123456-123466
H2 = 234567
H3 = 345678
H4 = 456789
I1 = <b 0xdeadbeef>
I2 = <r 16>
I3 = <rc 8>
I4 = <rd 8>
I5 = <t>
HeaderProtectionKey = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
ContentPaddingAddition = 16-32
RandomTrailers = true
DisableCookies = true
RekeyAfterTime = 60
RekeyTimeout = 4
RejectAfterTime = 90
KeepaliveTimeout = 8
MaxHandshakeAttempts = 6

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
`
	cfg, err := ParseConfigString(confContent)
	if err != nil {
		t.Fatalf("ParseConfigString failed: %v", err)
	}

	if cfg.Jc != 4 || cfg.Jmin != 50 || cfg.Jmax != 1000 {
		t.Errorf("junk parameters mismatch: %+v", cfg)
	}
	if cfg.S1 != 30 || cfg.S2 != 20 || cfg.S3 != 10 || cfg.S4 != 15 {
		t.Errorf("padding parameters mismatch: %+v", cfg)
	}
	if cfg.H1 != "123456-123466" || cfg.H2 != "234567" || cfg.H3 != "345678" || cfg.H4 != "456789" {
		t.Errorf("header parameters mismatch: %+v", cfg)
	}
	if cfg.I1 != "<b 0xdeadbeef>" || cfg.I5 != "<t>" {
		t.Errorf("signature parameters mismatch: %+v", cfg)
	}
	if cfg.HeaderProtectionKey != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("header protection key mismatch: %q", cfg.HeaderProtectionKey)
	}
	if cfg.ContentPaddingAddition != "16-32" || !cfg.RandomTrailers || !cfg.DisableCookies {
		t.Errorf("extended amnezia options mismatch: %+v", cfg)
	}
	if cfg.RekeyAfterTime != "60" || cfg.RekeyTimeout != "4" || cfg.RejectAfterTime != "90" || cfg.KeepaliveTimeout != "8" || cfg.MaxHandshakeAttempts != "6" {
		t.Errorf("extended timing options mismatch: %+v", cfg)
	}

	uapi, err := cfg.ToUAPI()
	if err != nil {
		t.Fatalf("ToUAPI failed: %v", err)
	}
	for _, expected := range []string{
		"jc=4", "jmin=50", "jmax=1000",
		"s1=30", "s2=20", "s3=10", "s4=15",
		"h1=123456-123466", "h2=234567", "h3=345678", "h4=456789",
		"i1=<b 0xdeadbeef>", "i5=<t>",
		"header_protection_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"content_padding_addition=16-32",
		"random_trailers=true",
		"disable_cookies=true",
		"rekey_after_time=60",
		"rekey_timeout=4",
		"reject_after_time=90",
		"keepalive_timeout=8",
		"max_handshake_attempts=6",
	} {
		if !strings.Contains(uapi, expected) {
			t.Errorf("ToUAPI missing %q:\n%s", expected, uapi)
		}
	}
}
