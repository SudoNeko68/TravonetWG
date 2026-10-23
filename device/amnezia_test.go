/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package device

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func TestUintRange(t *testing.T) {
	var r UintRange
	if err := r.FromString("123"); err != nil {
		t.Fatalf("single value: %v", err)
	}
	if !r.Contains(123) || r.Contains(122) || r.Contains(124) {
		t.Fatalf("single value range mismatch: %s", r)
	}
	if got := r.PickOne(); got != 123 {
		t.Fatalf("single value PickOne = %d", got)
	}

	if err := r.FromString("10-20"); err != nil {
		t.Fatalf("range: %v", err)
	}
	for i := 0; i < 100; i++ {
		v := r.PickOne()
		if v < 10 || v > 20 {
			t.Fatalf("PickOne out of range: %d", v)
		}
	}
	if r.Contains(9) || !r.Contains(10) || !r.Contains(20) || r.Contains(21) {
		t.Fatalf("range bounds mismatch: %s", r)
	}

	if err := r.FromString("20-10"); err == nil {
		t.Fatal("expected error for inverted range")
	}
	if err := r.FromString("nonsense"); err == nil {
		t.Fatal("expected error for invalid value")
	}
}

func TestSignaturePacketBuild(t *testing.T) {
	packet, err := newSignaturePacket("<b 0xdeadbeef><r 8><rc 4><rd 5><t>")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if packet == nil {
		t.Fatal("nil packet")
	}

	got := packet.Build()
	if len(got) != 4+8+4+5+4 {
		t.Fatalf("unexpected length %d", len(got))
	}
	if !bytes.Equal(got[:4], []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("static bytes mismatch: %x", got[:4])
	}
	for _, b := range got[12:16] {
		if !strings.ContainsRune(signatureChars52, rune(b)) {
			t.Fatalf("random chars contains non-letter %q", b)
		}
	}
	for _, b := range got[16:21] {
		if b < '0' || b > '9' {
			t.Fatalf("random digits contains non-digit %q", b)
		}
	}

	if packet, err := newSignaturePacket(""); err != nil || packet != nil {
		t.Fatalf("empty signature should be disabled: %v %v", packet, err)
	}
	if _, err := newSignaturePacket("<unknown 1>"); err == nil {
		t.Fatal("expected error for unknown tag")
	}
	if _, err := newSignaturePacket("<b 0xabc>"); err == nil {
		t.Fatal("expected error for odd hex string")
	}
}

// genAmneziaConfigs builds a pair of UAPI configs that use non-default
// AmneziaWG obfuscation parameters on the device level.
func genAmneziaConfigs(tb testing.TB) (cfgs [2]string) {
	var key1, key2 NoisePrivateKey
	if _, err := rand.Read(key1[:]); err != nil {
		tb.Fatal(err)
	}
	if _, err := rand.Read(key2[:]); err != nil {
		tb.Fatal(err)
	}
	pub1, pub2 := key1.publicKey(), key2.publicKey()

	amnezia := uapiCfg(
		"jc", "3",
		"jmin", "32",
		"jmax", "96",
		"s1", "32",
		"s2", "24",
		"s3", "16",
		"s4", "16",
		"h1", "100000-100010",
		"h2", "200000",
		"h3", "300000",
		"h4", "400000",
		"i1", "<b 0xdeadbeef><r 8>",
		"i2", "<rc 12>",
	)

	cfgs[0] = uapiCfg(
		"private_key", hex.EncodeToString(key1[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub2[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.2/32",
	)
	cfgs[1] = uapiCfg(
		"private_key", hex.EncodeToString(key2[:]),
		"listen_port", "0",
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub1[:]),
		"protocol_version", "1",
		"replace_allowed_ips", "true",
		"allowed_ip", "1.0.0.1/32",
	)

	for i := range cfgs {
		cfgs[i] = strings.Replace(cfgs[i], "replace_peers=true\n", amnezia+"replace_peers=true\n", 1)
	}
	return cfgs
}

func TestAmneziaTwoDevicePing(t *testing.T) {
	goroutineLeakCheck(t)

	cfgs := genAmneziaConfigs(t)
	binds := bindtest.NewChannelBinds()

	var pair [2]struct {
		tun *tuntest.ChannelTUN
		dev *Device
		ip  netip.Addr
	}

	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		p.dev = NewDevice(p.tun.TUN(), binds[i], NewLogger(LogLevelError, fmt.Sprintf("awg%d: ", i)))
		if err := p.dev.IpcSet(cfgs[i]); err != nil {
			t.Fatalf("failed to configure device %d: %v", i, err)
		}
		if err := p.dev.Up(); err != nil {
			t.Fatalf("failed to bring up device %d: %v", i, err)
		}
		t.Cleanup(p.dev.Close)
	}

	for i := range pair {
		other := (i + 1) % len(pair)
		endpointCfg := uapiCfg(
			"public_key", hex.EncodeToString(pair[other].dev.staticIdentity.publicKey[:]),
			"endpoint", fmt.Sprintf("127.0.0.1:%d", pair[other].dev.net.port),
		)
		if err := pair[i].dev.IpcSet(endpointCfg); err != nil {
			t.Fatalf("failed to configure endpoint %d: %v", i, err)
		}
	}

	// Verify that the obfuscation parameters made it into the device.
	if got := pair[0].dev.amnezia.paddings.init.Load(); got != 32 {
		t.Fatalf("s1 = %d, want 32", got)
	}
	if got := pair[0].dev.amnezia.headers.transport.Load(); !got.Contains(400000) {
		t.Fatalf("h4 = %s, want 400000", got)
	}

	msg := tuntest.Ping(pair[0].ip, pair[1].ip)
	pair[1].tun.Outbound <- msg

	select {
	case got := <-pair[0].tun.Inbound:
		if !bytes.Equal(msg, got) {
			t.Fatalf("ping did not transit correctly\nwant %x\ngot  %x", msg, got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ping did not transit")
	}
}

func TestAmneziaVanillaCompatibility(t *testing.T) {
	// A device with default AmneziaWG parameters must still accept a plain
	// WireGuard handshake/transport exchange.
	goroutineLeakCheck(t)

	cfgs, endpointCfgs := genConfigs(t)
	binds := bindtest.NewChannelBinds()

	var pair testPair
	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		p.dev = NewDevice(p.tun.TUN(), binds[i], NewLogger(LogLevelError, fmt.Sprintf("wg%d: ", i)))
		if err := p.dev.IpcSet(cfgs[i]); err != nil {
			t.Fatalf("failed to configure device %d: %v", i, err)
		}
		if err := p.dev.Up(); err != nil {
			t.Fatalf("failed to bring up device %d: %v", i, err)
		}
		t.Cleanup(p.dev.Close)
		endpointCfgs[i^1] = fmt.Sprintf(endpointCfgs[i^1], p.dev.net.port)
	}
	for i := range pair {
		if err := pair[i].dev.IpcSet(endpointCfgs[i]); err != nil {
			t.Fatalf("failed to configure endpoint %d: %v", i, err)
		}
	}

	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
}

func TestHeaderProtectionPing(t *testing.T) {
	goroutineLeakCheck(t)

	var key1, key2 NoisePrivateKey
	if _, err := rand.Read(key1[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(key2[:]); err != nil {
		t.Fatal(err)
	}
	pub1, pub2 := key1.publicKey(), key2.publicKey()

	hpKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	amnezia := uapiCfg(
		"jc", "2",
		"jmin", "20",
		"jmax", "50",
		"s1", "24",
		"s2", "20",
		"s3", "16",
		"s4", "16",
		"h1", "123456",
		"h2", "654321",
		"h3", "789012",
		"h4", "210987",
		"header_protection_key", hpKey,
		"content_padding_addition", "8-24",
		"random_trailers", "true",
	)

	cfgs := [2]string{
		uapiCfg(
			"private_key", hex.EncodeToString(key1[:]),
			"listen_port", "0",
			"replace_peers", "true",
			"public_key", hex.EncodeToString(pub2[:]),
			"protocol_version", "1",
			"replace_allowed_ips", "true",
			"allowed_ip", "1.0.0.2/32",
		),
		uapiCfg(
			"private_key", hex.EncodeToString(key2[:]),
			"listen_port", "0",
			"replace_peers", "true",
			"public_key", hex.EncodeToString(pub1[:]),
			"protocol_version", "1",
			"replace_allowed_ips", "true",
			"allowed_ip", "1.0.0.1/32",
		),
	}

	for i := range cfgs {
		cfgs[i] = strings.Replace(cfgs[i], "replace_peers=true\n", amnezia+"replace_peers=true\n", 1)
	}

	binds := bindtest.NewChannelBinds()
	var pair [2]struct {
		tun *tuntest.ChannelTUN
		dev *Device
		ip  netip.Addr
	}

	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		p.dev = NewDevice(p.tun.TUN(), binds[i], NewLogger(LogLevelError, fmt.Sprintf("awg-hp%d: ", i)))
		if err := p.dev.IpcSet(cfgs[i]); err != nil {
			t.Fatalf("failed to configure device %d: %v", i, err)
		}
		if err := p.dev.Up(); err != nil {
			t.Fatalf("failed to bring up device %d: %v", i, err)
		}
		t.Cleanup(p.dev.Close)
	}

	for i := range pair {
		other := (i + 1) % len(pair)
		endpointCfg := uapiCfg(
			"public_key", hex.EncodeToString(pair[other].dev.staticIdentity.publicKey[:]),
			"endpoint", fmt.Sprintf("127.0.0.1:%d", pair[other].dev.net.port),
		)
		if err := pair[i].dev.IpcSet(endpointCfg); err != nil {
			t.Fatalf("failed to configure endpoint %d: %v", i, err)
		}
	}

	msg := tuntest.Ping(pair[0].ip, pair[1].ip)
	pair[1].tun.Outbound <- msg

	select {
	case got := <-pair[0].tun.Inbound:
		if !bytes.Equal(msg, got) {
			t.Fatalf("ping with header protection did not transit correctly\nwant %x\ngot  %x", msg, got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ping with header protection timed out")
	}

	msg2 := tuntest.Ping(pair[1].ip, pair[0].ip)
	pair[0].tun.Outbound <- msg2

	select {
	case got := <-pair[1].tun.Inbound:
		if !bytes.Equal(msg2, got) {
			t.Fatalf("reverse ping did not transit correctly\nwant %x\ngot  %x", msg2, got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reverse ping timed out")
	}
}

func TestAmneziaUAPIConfigGet(t *testing.T) {
	goroutineLeakCheck(t)

	tun := tuntest.NewChannelTUN()
	bind := bindtest.NewChannelBinds()[0]
	dev := NewDevice(tun.TUN(), bind, NewLogger(LogLevelError, "uapi-test: "))
	t.Cleanup(dev.Close)

	hpKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	input := uapiCfg(
		"jc", "5",
		"jmin", "30",
		"jmax", "80",
		"s1", "30",
		"s2", "25",
		"s3", "18",
		"s4", "18",
		"h1", "111111",
		"h2", "222222",
		"h3", "333333",
		"h4", "444444",
		"header_protection_key", hpKey,
		"content_padding_addition", "16-32",
		"random_trailers", "true",
		"disable_cookies", "true",
		"rekey_after_time", "60",
		"rekey_timeout", "3",
		"reject_after_time", "90",
		"keepalive_timeout", "8",
		"max_handshake_attempts", "6",
	)

	if err := dev.IpcSet(input); err != nil {
		t.Fatalf("IpcSet failed: %v", err)
	}

	var sb strings.Builder
	if err := dev.IpcGetOperation(&sb); err != nil {
		t.Fatalf("IpcGetOperation failed: %v", err)
	}

	out := sb.String()
	checks := []string{
		"jc=5", "jmin=30", "jmax=80",
		"s1=30", "s2=25", "s3=18", "s4=18",
		"h1=111111", "h2=222222", "h3=333333", "h4=444444",
		"header_protection_key=" + hpKey,
		"content_padding_addition=16-32",
		"random_trailers=true",
		"disable_cookies=true",
		"rekey_after_time=60",
		"rekey_timeout=3",
		"reject_after_time=90",
		"keepalive_timeout=8",
		"max_handshake_attempts=6",
	}

	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("IpcGet output missing %q, got:\n%s", check, out)
		}
	}
}
