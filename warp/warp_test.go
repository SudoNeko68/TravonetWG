/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package warp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateKeypair(t *testing.T) {
	first, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	second, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if first.PrivateKey == second.PrivateKey {
		t.Fatal("two generated keys are identical")
	}

	private, err := base64.StdEncoding.DecodeString(first.PrivateKey)
	if err != nil {
		t.Fatalf("private key is not base64: %v", err)
	}
	if len(private) != 32 {
		t.Fatalf("private key length = %d, want 32", len(private))
	}
	if private[0]&7 != 0 {
		t.Errorf("private key is not clamped: first byte %#x", private[0])
	}
	if private[31]&0x80 != 0 || private[31]&0x40 == 0 {
		t.Errorf("private key is not clamped: last byte %#x", private[31])
	}

	public, err := base64.StdEncoding.DecodeString(first.PublicKey)
	if err != nil {
		t.Fatalf("public key is not base64: %v", err)
	}
	want, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if !bytes.Equal(public, want) {
		t.Fatal("public key does not match private key")
	}
}

func TestBuildRegistrationBody(t *testing.T) {
	body, err := buildRegistrationBody(
		"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		"ru-RU",
		"Pixel 6",
		"2026-10-22T21:40:00.000+00:00",
		"0123456789abcdef",
	)
	if err != nil {
		t.Fatalf("buildRegistrationBody: %v", err)
	}

	var decoded registrationRequest
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if decoded.Key != "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" {
		t.Errorf("key = %q", decoded.Key)
	}
	if decoded.InstallID != "" || decoded.FcmToken != "" || decoded.OsVersion != "" {
		t.Errorf("device fields must be empty: %+v", decoded)
	}
	if decoded.KeyType != "curve25519" || decoded.TunnelType != "wireguard" {
		t.Errorf("key/tunnel type = %q/%q", decoded.KeyType, decoded.TunnelType)
	}
	if decoded.Locale != "ru-RU" || decoded.Model != "Pixel 6" {
		t.Errorf("locale/model = %q/%q", decoded.Locale, decoded.Model)
	}
	if decoded.SerialNumber != "0123456789abcdef" {
		t.Errorf("serial = %q", decoded.SerialNumber)
	}
	if decoded.Tos != "2026-10-22T21:40:00.000+00:00" {
		t.Errorf("tos = %q", decoded.Tos)
	}
}

func TestCloudflareTimeFormat(t *testing.T) {
	got := cloudflareTime(time.Date(2026, 10, 22, 21, 40, 0, 0, time.UTC))
	pattern := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}$`)
	if !pattern.MatchString(got) {
		t.Fatalf("timestamp %q does not match the WARP client format", got)
	}
	if got != "2026-10-22T21:40:00.000+00:00" {
		t.Errorf("timestamp = %q", got)
	}
}

func TestFragmentConnSplitsFirstWrite(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	var received bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = received.ReadFrom(server)
	}()

	conn := &fragmentConn{
		Conn:   client,
		plan:   []int{1, 255, 256},
		budget: 900,
		delay:  0,
	}
	payload := bytes.Repeat([]byte("a"), 3000)
	written, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if written != len(payload) {
		t.Fatalf("written = %d, want %d", written, len(payload))
	}
	_ = client.Close()
	<-done

	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("received %d bytes, want %d", received.Len(), len(payload))
	}

	// The plan must be fully consumed and the budget exhausted, so the next
	// write goes through untouched.
	if len(conn.plan) != 0 || conn.budget > 0 {
		t.Fatalf("plan left %d, budget left %d", len(conn.plan), conn.budget)
	}
}

func TestFragmentConnPassesLargeWritesThrough(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := server.Read(buf)
		received <- buf[:n]
	}()

	conn := &fragmentConn{
		Conn:   client,
		plan:   []int{1, 255, 256},
		budget: 0,
		delay:  0,
	}
	payload := bytes.Repeat([]byte("b"), 2000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := <-received; !bytes.Equal(got, payload) {
		t.Fatalf("received %d bytes, want %d", len(got), len(payload))
	}
}

func TestRegisterViaRelay(t *testing.T) {
	var gotToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Relay-Token")
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		var request RelayRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode: %v", err)
		}
		if request.PublicKey != "public" || request.Locale != "ru-RU" || request.Model != "Pixel" {
			t.Errorf("request = %+v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"config":{}}`)
	}))
	defer server.Close()

	body, err := RegisterViaRelay(context.Background(), server.URL, "secret", "public", "ru-RU", "Pixel")
	if err != nil {
		t.Fatalf("RegisterViaRelay: %v", err)
	}
	if string(body) != `{"config":{}}` {
		t.Fatalf("body = %s", body)
	}
	if gotToken != "secret" {
		t.Fatalf("token = %q", gotToken)
	}
}

func TestRegisterViaRelayRejectsNonJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "Hello World!")
	}))
	defer server.Close()

	_, err := RegisterViaRelay(context.Background(), server.URL, "secret", "public", "ru-RU", "Pixel")
	if err == nil {
		t.Fatal("expected non-JSON error")
	}
	if !strings.Contains(err.Error(), "non-JSON") {
		t.Fatalf("error = %v", err)
	}
}

func TestRegisterViaRelayRejectsBadScheme(t *testing.T) {
	if _, err := RegisterViaRelay(context.Background(), "ftp://relay/register", "", "public", "en-US", "PC"); err == nil {
		t.Fatal("expected scheme error")
	}
}

func TestRegisterWithFallbackMultipleRelays(t *testing.T) {
	// First server always fails
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server 1 error", http.StatusInternalServerError)
	}))
	defer server1.Close()

	// Second server succeeds
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"config":{"ok":true}}`)
	}))
	defer server2.Close()

	bothURLs := server1.URL + "," + server2.URL
	body, err := RegisterWithFallback(context.Background(), "public", "ru-RU", "Pixel", bothURLs, "token")
	if err != nil {
		t.Fatalf("RegisterWithFallback: %v", err)
	}
	if string(body) != `{"config":{"ok":true}}` {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestGenerateWireGuardConfig(t *testing.T) {
	fakeResp := []byte(`{
		"config": {
			"client_id": "aJ3n",
			"peers": [{
				"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
				"endpoint": {
					"v4": "162.159.192.1:2408",
					"host": "engage.cloudflareclient.com:2408"
				}
			}],
			"interface": {
				"addresses": {
					"v4": "172.16.0.2",
					"v6": "2606:4700:110:875d:81ab:2a00:231e:5f7e"
				}
			}
		}
	}`)

	cfg, err := GenerateWireGuardConfig(fakeResp, "TEST_PRIVATE_KEY", "")
	if err != nil {
		t.Fatalf("GenerateWireGuardConfig failed: %v", err)
	}

	if !strings.Contains(cfg, "PrivateKey = TEST_PRIVATE_KEY") {
		t.Errorf("missing PrivateKey in config: %s", cfg)
	}
	if !strings.Contains(cfg, "Address = 172.16.0.2/32, 2606:4700:110:875d:81ab:2a00:231e:5f7e/128") {
		t.Errorf("missing Address in config: %s", cfg)
	}
	if !strings.Contains(cfg, "Reserved =") {
		t.Errorf("missing Reserved in config: %s", cfg)
	}
	if !strings.Contains(cfg, "Endpoint = 162.159.192.1:2408") {
		t.Errorf("missing Endpoint in config: %s", cfg)
	}
	if !strings.Contains(cfg, "Strategy = mimic(quic)") {
		t.Errorf("missing default strategy in config: %s", cfg)
	}
}
