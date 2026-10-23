/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conf

import (
	"strconv"
	"strings"
	"testing"
)

func TestFilterUAPIKeepsPerPeerKeepalive(t *testing.T) {
	const settings = `private_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
replace_peers=true
public_key=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
endpoint=1.2.3.4:2408
replace_allowed_ips=true
allowed_ip=0.0.0.0/0
persistent_keepalive_interval=25
public_key=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
endpoint=5.6.7.8:2408
replace_allowed_ips=true
allowed_ip=10.0.0.0/24
`

	clean, ev := FilterUAPI(settings)

	if ev.HasPeer != true {
		t.Fatal("expected HasPeer to be reported")
	}
	// The last peer has no explicit keepalive, so the Android default applies.
	if ev.PersistentKeepalive != DefaultKeepalive {
		t.Errorf("PersistentKeepalive = %d; want %d", ev.PersistentKeepalive, DefaultKeepalive)
	}

	// Each peer must keep its own value: the first peer asked for 25s and must
	// not be overwritten with the default.
	firstKeepalive := strings.Index(clean, "persistent_keepalive_interval=25")
	secondPublic := strings.Index(clean, "public_key=cccccccc")
	secondKeepalive := strings.Index(clean, "persistent_keepalive_interval="+strconv.Itoa(DefaultKeepalive))

	if firstKeepalive < 0 {
		t.Fatalf("explicit keepalive of the first peer was lost:\n%s", clean)
	}
	if secondKeepalive < 0 {
		t.Fatalf("default keepalive of the second peer is missing:\n%s", clean)
	}
	if !(firstKeepalive < secondPublic && secondPublic < secondKeepalive) {
		t.Fatalf("keepalives are not attached to their own peer section:\n%s", clean)
	}
	if strings.Count(clean, "persistent_keepalive_interval=") != 2 {
		t.Fatalf("expected exactly one keepalive per peer:\n%s", clean)
	}
}

func TestFilterUAPIPort500Clamp(t *testing.T) {
	const settings = `public_key=bbbb
endpoint=8.34.70.70:500
persistent_keepalive_interval=25
public_key=cccc
endpoint=1.2.3.4:2408
persistent_keepalive_interval=25
`

	clean, _ := FilterUAPI(settings)
	if !strings.Contains(clean, "persistent_keepalive_interval=5") {
		t.Fatalf("port 500 keepalive was not clamped to %d:\n%s", LowPortKeepalive, clean)
	}
	if !strings.Contains(clean, "persistent_keepalive_interval=25") {
		t.Fatalf("non-500 keepalive was unexpectedly changed:\n%s", clean)
	}
}

func TestFilterUAPIStripsEvasionKeysAndPreservesAmneziaWG(t *testing.T) {
	const settings = `private_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
jc=5
jmax=120
s1=16
h1=123456
i1=<b 0xdeadbeef>
strategy=junk(64) -> fake_udp(148)
fake_ttl=auto
normal_ttl=48
jmin=40
no_evasion=true
debug=1
mtu=1400
public_key=bbbb
endpoint=1.2.3.4:2408
`

	clean, ev := FilterUAPI(settings)

	// Evasion-only keys must be stripped from UAPI stream
	for _, leaked := range []string{"strategy=", "fake_ttl=", "normal_ttl=", "no_evasion=", "debug=", "mtu="} {
		if strings.Contains(clean, leaked) {
			t.Errorf("evasion key %q leaked into the UAPI stream:\n%s", leaked, clean)
		}
	}

	// AmneziaWG keys must be preserved for device.IpcSet
	for _, expected := range []string{"jc=5", "jmax=120", "jmin=40", "s1=16", "h1=123456", "i1=<b 0xdeadbeef>"} {
		if !strings.Contains(clean, expected) {
			t.Errorf("AmneziaWG key %q was incorrectly stripped from UAPI stream:\n%s", expected, clean)
		}
	}

	if !ev.HasStrategy || ev.Strategy != "junk(64) -> fake_udp(148)" {
		t.Errorf("strategy not captured: %+v", ev)
	}
	if !ev.HasFakeTTL || ev.FakeTTL != -1 {
		t.Errorf("fake_ttl=auto not mapped to -1: %+v", ev)
	}
	if !ev.HasNormalTTL || ev.NormalTTL != 48 {
		t.Errorf("normal_ttl not captured: %+v", ev)
	}
	if !ev.HasPreJunkSize || ev.PreJunkSize != 40 {
		t.Errorf("jmin not mapped to PreJunkSize: %+v", ev)
	}
	if !ev.HasEnabled || ev.Enabled {
		t.Errorf("no_evasion=true not honored: %+v", ev)
	}
	if !ev.HasDebug || !ev.Debug {
		t.Errorf("debug=1 not honored: %+v", ev)
	}
	if !ev.HasMTU || ev.MTU != 1400 {
		t.Errorf("mtu not captured: %+v", ev)
	}
	if !strings.Contains(clean, "private_key=") || !strings.Contains(clean, "public_key=bbbb") {
		t.Errorf("vanilla UAPI keys were dropped:\n%s", clean)
	}
}

func TestFilterUAPIExplicitPreJunkWinsOverJmin(t *testing.T) {
	// Explicit PreJunk before jmin.
	_, ev := FilterUAPI("pre_junk=100\njmin=40\n")
	if ev.PreJunkSize != 100 {
		t.Errorf("later jmin overrode explicit pre_junk: %d", ev.PreJunkSize)
	}

	// jmin before an explicit PreJunk.
	_, ev = FilterUAPI("jmin=40\npre_junk=100\n")
	if ev.PreJunkSize != 100 {
		t.Errorf("explicit pre_junk did not win over jmin: %d", ev.PreJunkSize)
	}

	// jmin alone still applies.
	_, ev = FilterUAPI("jmin=40\n")
	if !ev.HasPreJunkSize || ev.PreJunkSize != 40 {
		t.Errorf("jmin alone was not applied: %+v", ev)
	}
}

func TestFilterUAPINumericEndpointIsPreserved(t *testing.T) {
	clean, ev := FilterUAPI("public_key=bbbb\nendpoint=192.0.2.10:51820\n")
	if ev.Endpoint != "192.0.2.10:51820" {
		t.Errorf("endpoint = %q", ev.Endpoint)
	}
	if !strings.Contains(clean, "endpoint=192.0.2.10:51820") {
		t.Errorf("numeric endpoint was rewritten:\n%s", clean)
	}
	if got := strings.Count(clean, "persistent_keepalive_interval="); got != 1 {
		t.Errorf("expected the default keepalive to be injected, got %d lines:\n%s", got, clean)
	}
}

func TestFilterUAPINoPeerNoKeepalive(t *testing.T) {
	clean, ev := FilterUAPI("private_key=aaaa\nlisten_port=1234\n")
	if ev.HasPeer {
		t.Error("HasPeer must stay false without a public_key")
	}
	if strings.Contains(clean, "persistent_keepalive_interval") {
		t.Errorf("keepalive must not be injected without peers:\n%s", clean)
	}
	if !strings.Contains(clean, "listen_port=1234") {
		t.Errorf("device-level keys were dropped:\n%s", clean)
	}
}
