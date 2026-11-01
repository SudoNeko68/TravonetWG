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
