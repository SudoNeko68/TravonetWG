/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conf

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseVPNURL_PlainJSON(t *testing.T) {
	sampleJSON := `{
		"hostName": "my-server.example.com",
		"description": "My Personal AWG",
		"containers": [
			{
				"container": "amnezia-awg",
				"awg": {
					"last_config": "[Interface]\nPrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\nAddress = 10.8.0.2/24\nDNS = 1.1.1.1\nJc = 4\nJmin = 50\nJmax = 100\nS1 = 15\nS2 = 20\nH1 = 1234567\nH2 = 2345678\nH3 = 3456789\nH4 = 4567890\n\n[Peer]\nPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\nEndpoint = 198.51.100.1:29835\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
				}
			}
		]
	}`

	b64 := base64.RawURLEncoding.EncodeToString([]byte(sampleJSON))
	vpnURL := "vpn://" + b64

	confText, name, err := ParseVPNURL(vpnURL)
	if err != nil {
		t.Fatalf("ParseVPNURL failed: %v", err)
	}

	if name != "My Personal AWG" {
		t.Errorf("name = %q, want 'My Personal AWG'", name)
	}

	if !strings.Contains(confText, "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=") {
		t.Errorf("missing PrivateKey: %s", confText)
	}
	if !strings.Contains(confText, "Jc = 4") || !strings.Contains(confText, "H1 = 1234567") {
		t.Errorf("missing AWG params: %s", confText)
	}

	cfg, err := ParseConfigString(vpnURL)
	if err != nil {
		t.Fatalf("ParseConfigString(vpnURL) failed: %v", err)
	}
	if cfg.Jc != 4 || cfg.Jmin != 50 || cfg.Jmax != 100 {
		t.Errorf("parsed config AWG mismatch: %+v", cfg)
	}
}

func TestParseVPNURL_QtQCompress(t *testing.T) {
	sampleJSON := `{
		"hostName": "qt-server.example.com",
		"description": "Qt Compressed Server",
		"containers": [
			{
				"container": "amnezia-awg",
				"awg": {
					"last_config": "{\"client_priv_key\":\"ccccccccccccccccccccccccccccccccccccccccccc=\",\"server_pub_key\":\"ddddddddddddddddddddddddddddddddddddddddddd=\",\"client_ip\":\"10.7.0.2\",\"port\":51820,\"Jc\":3,\"Jmin\":40,\"Jmax\":80,\"S1\":50,\"S2\":100,\"H1\":\"111\",\"H2\":\"222\",\"H3\":\"333\",\"H4\":\"444\"}"
				}
			}
		]
	}`

	// qCompress format: 4 bytes big endian uncompressed length + zlib compressed stream
	var zlibBuf bytes.Buffer
	zw := zlib.NewWriter(&zlibBuf)
	_, _ = zw.Write([]byte(sampleJSON))
	_ = zw.Close()

	var qtBuf bytes.Buffer
	_ = binary.Write(&qtBuf, binary.BigEndian, uint32(len(sampleJSON)))
	qtBuf.Write(zlibBuf.Bytes())

	b64 := base64.RawURLEncoding.EncodeToString(qtBuf.Bytes())
	vpnURL := "vpn://" + b64

	confText, name, err := ParseVPNURL(vpnURL)
	if err != nil {
		t.Fatalf("ParseVPNURL failed for Qt compressed payload: %v", err)
	}

	if name != "Qt Compressed Server" {
		t.Errorf("name = %q, want 'Qt Compressed Server'", name)
	}

	if !strings.Contains(confText, "PrivateKey = ccccccccccccccccccccccccccccccccccccccccccc=") {
		t.Errorf("missing PrivateKey: %s", confText)
	}
	if !strings.Contains(confText, "Endpoint = qt-server.example.com:51820") {
		t.Errorf("missing or invalid Endpoint: %s", confText)
	}
	if !strings.Contains(confText, "Jc = 3") || !strings.Contains(confText, "H4 = 444") {
		t.Errorf("missing AWG params: %s", confText)
	}

	cfg, err := ParseConfigString(vpnURL)
	if err != nil {
		t.Fatalf("ParseConfigString(vpnURL) failed: %v", err)
	}
	if cfg.Jc != 3 || cfg.Endpoint != "qt-server.example.com:51820" {
		t.Errorf("parsed config mismatch: %+v", cfg)
	}
}

func TestParseVPNURL_RawINI3XUI(t *testing.T) {
	// Real 3X-UI generated vpn:// link with trailing dot
	testURL := "vpn://W0ludGVyZmFjZV0KUHJpdmF0ZUtleSA9IHdKREQ2RXF3UmxWd09DWVNUc1RkU21ycVVRNC84NlZkYURqWnA4QmNmazQ9CkFkZHJlc3MgPSAxMC44LjEuMjYvMzIKRE5TID0gOC44LjguOCwgOC44LjQuNApNVFUgPSAxMjAwCkpjID0gNApKbWluID0gNTIKSm1heCA9IDEwNQpTMSA9IDE1MApTMiA9IDc0ClMzID0gNDAKUzQgPSAyMwpIMSA9IDUyMTMxNDY5NwpIMiA9IDk0NzYxOTA3MApIMyA9IDE0NTE2MDExNDIKSDQgPSAyMDg3NzI5MTYyCkkxID0gPHIgMTc1PgpIZWFkZXJQcm90ZWN0aW9uS2V5ID0gc0lKVGN0VHFneklEa2k4bGp5YWtaeTZhQWNWM0N0TW9nb2xZbjc5NVhtVT0KQ29udGVudFBhZGRpbmdBZGRpdGlvbiA9IDgtMzMKUmVrZXlBZnRlclRpbWUgPSAxMDYtMTM4ClJla2V5VGltZW91dCA9IDQtNwpSZWplY3RBZnRlclRpbWUgPSAxODAtMjY0CktlZXBhbGl2ZVRpbWVvdXQgPSA5LTEyCk1heEhhbmRzaGFrZUF0dGVtcHRzID0gMTgtMjUKUmFuZG9tVHJhaWxlcnMgPSBvbgpEaXNhYmxlQ29va2llcyA9IG9uCgojIEFtbmV6aWFXRwpbUGVlcl0KUHVibGljS2V5ID0gbC91Ti9hQ2pIQ25Ndmw4a3NtS1F2bU82aEpQY0dRZXpkQnFPcVVZcXAxTT0KQWxsb3dlZElQcyA9IDAuMC4wLjAvMCwgOjovMApFbmRwb2ludCA9IHRyYXZvbmV0LnJ1OjI5ODM1ClBlcnNpc3RlbnRLZWVwYWxpdmUgPSAyNQ."

	confText, name, err := ParseVPNURL(testURL)
	if err != nil {
		t.Fatalf("ParseVPNURL failed on raw 3X-UI URL: %v", err)
	}

	if !strings.Contains(confText, "PrivateKey = wJDD6EqwRlVwOCYSTsTdSmrqUQ4/86VdaDjZp8Bcfk4=") {
		t.Errorf("missing PrivateKey in config: %s", confText)
	}
	if !strings.Contains(confText, "Endpoint = travonet.ru:29835") {
		t.Errorf("missing Endpoint in config: %s", confText)
	}
	if name != "AmneziaWG (travonet.ru)" {
		t.Errorf("expected name 'AmneziaWG (travonet.ru)', got %q", name)
	}

	cfg, err := ParseConfigString(testURL)
	if err != nil {
		t.Fatalf("ParseConfigString failed: %v", err)
	}

	if cfg.Jc != 4 || cfg.Jmin != 52 || cfg.Jmax != 105 {
		t.Errorf("AWG J params mismatch: %+v", cfg)
	}
	if cfg.S1 != 150 || cfg.S2 != 74 || cfg.S3 != 40 || cfg.S4 != 23 {
		t.Errorf("AWG S params mismatch: %+v", cfg)
	}
	if cfg.H1 != "521314697" || cfg.H4 != "2087729162" {
		t.Errorf("AWG H params mismatch: %+v", cfg)
	}
	if cfg.I1 != "<r 175>" {
		t.Errorf("AWG I1 mismatch: %q", cfg.I1)
	}
	if !cfg.RandomTrailers || !cfg.DisableCookies {
		t.Errorf("RandomTrailers (%v) or DisableCookies (%v) not parsed as true", cfg.RandomTrailers, cfg.DisableCookies)
	}
	if cfg.HeaderProtectionKey != "sIJTctTqgzIDki8ljyakZy6aAcV3CtMogolYn795XmU=" {
		t.Errorf("HeaderProtectionKey mismatch: %q", cfg.HeaderProtectionKey)
	}
	if cfg.RekeyAfterTime != "106-138" {
		t.Errorf("RekeyAfterTime mismatch: %q", cfg.RekeyAfterTime)
	}

	uapi, err := cfg.ToUAPI()
	if err != nil {
		t.Fatalf("ToUAPI failed: %v", err)
	}
	if !strings.Contains(uapi, "jc=4") || !strings.Contains(uapi, "random_trailers=true") || !strings.Contains(uapi, "disable_cookies=true") {
		t.Errorf("UAPI missing AWG parameters: %s", uapi)
	}
}
