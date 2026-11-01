/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

// Package warp implements anonymous Cloudflare WARP registration.
//
// The control plane is filtered in some networks by the TLS server name
// (SNI), not by address: TCP connects, but the handshake for
// api.cloudflareclient.com is dropped while the same address answers for
// other names. The registration therefore tries several transports in
// parallel: a plain HTTPS request (works when nothing is filtered and inside
// an already established tunnel) and TLS connections to known Cloudflare
// addresses where the ClientHello is split into small TCP writes.
//
// Only the public key is ever sent to Cloudflare. The private key is
// generated on the device and never leaves it.
package warp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	// APIHost is the WARP control plane host name.
	APIHost = "api.cloudflareclient.com"
	// APIPath is the registration endpoint used by current WARP clients.
	APIPath = "/v0a4471/reg"
	// ClientVersion must match APIPath. Cloudflare gates unknown client
	// versions, so both constants are updated together.
	ClientVersion = "a-6.35-4471"

	dialTimeout      = 5 * time.Second
	handshakeTimeout = 8 * time.Second
	responseTimeout  = 10 * time.Second
	registerTimeout  = 22 * time.Second
	maxResponseBytes = 512 * 1024
)

// apiIPs are stable Cloudflare addresses that serve the WARP API. They are
// hardcoded on purpose: provider DNS in filtered networks returns unrelated
// addresses for this name.
var apiIPs = []string{
	"104.16.24.84",
	"104.16.192.82",
}

// fragmentPlans split the beginning of the TLS ClientHello into small writes.
// Different split points make sure a filter that only inspects the first
// segment does not see the full name.
var fragmentPlans = [][]int{
	{1, 255, 256},
	{1, 663},
	{1, 680},
	{1, 269, 270},
}

// Keypair is a WireGuard-compatible X25519 key pair, Base64 encoded.
type Keypair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// GenerateKeypair creates a clamped X25519 private key and its public key.
func GenerateKeypair() (Keypair, error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return Keypair{}, fmt.Errorf("generate private key: %w", err)
	}
	// WireGuard clamps the scalar before use; clamp it here so that the
	// exported private key is exactly what the tunnel will use.
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, fmt.Errorf("derive public key: %w", err)
	}
	return Keypair{
		PrivateKey: base64.StdEncoding.EncodeToString(private[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(public),
	}, nil
}

type registrationRequest struct {
	Key          string `json:"key"`
	InstallID    string `json:"install_id"`
	FcmToken     string `json:"fcm_token"`
	Tos          string `json:"tos"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	OsVersion    string `json:"os_version"`
	KeyType      string `json:"key_type"`
	TunnelType   string `json:"tunnel_type"`
	Locale       string `json:"locale"`
}

// Register asks Cloudflare to create an anonymous WARP device for publicKey
// and returns the raw JSON response.
func Register(ctx context.Context, publicKey, locale, model string) ([]byte, error) {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return nil, errors.New("public key is required")
	}
	if strings.TrimSpace(locale) == "" {
		locale = "en-US"
	}
	if strings.TrimSpace(model) == "" {
		model = "PC"
	}

	body, err := newRegistrationBody(publicKey, locale, model)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, registerTimeout)
	defer cancel()

	type outcome struct {
		label string
		body  []byte
		err   error
	}

	attempts := 1 + len(apiIPs)*len(fragmentPlans)
	results := make(chan outcome, attempts)

	launch := func(label string, request func(context.Context) ([]byte, error)) {
		go func() {
			response, err := request(ctx)
			results <- outcome{label: label, body: response, err: err}
		}()
	}

	launch("plain", func(c context.Context) ([]byte, error) {
		return requestPlain(c, body)
	})
	for _, ip := range apiIPs {
		for _, plan := range fragmentPlans {
			ip, plan := ip, plan
			launch("fragmented "+ip, func(c context.Context) ([]byte, error) {
				return requestFragmented(c, ip, plan, body)
			})
		}
	}

	failures := make([]string, 0, attempts)
	for i := 0; i < attempts; i++ {
		select {
		case result := <-results:
			if result.err == nil && len(result.body) > 0 {
				cancel()
				return result.body, nil
			}
			if result.err != nil {
				failures = append(failures, result.label+": "+result.err.Error())
			}
		case <-ctx.Done():
			failures = append(failures, "timeout")
			return nil, fmt.Errorf("WARP registration failed: %s", strings.Join(failures, " | "))
		}
	}

	if len(failures) > 6 {
		failures = failures[:6]
	}
	return nil, fmt.Errorf("WARP registration failed: %s", strings.Join(failures, " | "))
}

func newRegistrationBody(publicKey, locale, model string) ([]byte, error) {
	serial := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, serial); err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return buildRegistrationBody(
		publicKey,
		locale,
		model,
		cloudflareTime(time.Now()),
		hex.EncodeToString(serial),
	)
}

// buildRegistrationBody is split out so the request shape can be tested
// without touching the network.
func buildRegistrationBody(publicKey, locale, model, tos, serial string) ([]byte, error) {
	payload, err := json.Marshal(registrationRequest{
		Key:          publicKey,
		InstallID:    "",
		FcmToken:     "",
		Tos:          tos,
		Model:        model,
		SerialNumber: serial,
		OsVersion:    "",
		KeyType:      "curve25519",
		TunnelType:   "wireguard",
		Locale:       locale,
	})
	if err != nil {
		return nil, fmt.Errorf("encode registration request: %w", err)
	}
	return payload, nil
}

// cloudflareTime matches the WARP client: milliseconds and a numeric offset.
// The short "...Z" form is accepted by the API but the issued device is then
// not served, so the format matters.
func cloudflareTime(now time.Time) string {
	return now.UTC().Format("2006-01-02T15:04:05.000-07:00")
}

func newAPIRequest(ctx context.Context, body []byte) (*http.Request, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://"+APIHost+APIPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "WARP for Android")
	request.Header.Set("CF-Client-Version", ClientVersion)
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Connection", "close")
	return request, nil
}

func requestPlain(ctx context.Context, body []byte) ([]byte, error) {
	// ProxyFromEnvironment lets the relay use an upstream proxy (HTTPS_PROXY)
	// on hosts where the direct name is filtered. Android sets no such
	// variables, so on the device this is a no-op.
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		TLSHandshakeTimeout:   handshakeTimeout,
		ResponseHeaderTimeout: responseTimeout,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: responseTimeout}
	request, err := newAPIRequest(ctx, body)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s: %s", response.Status, truncate(string(payload), 160))
	}
	return payload, nil
}

func requestFragmented(ctx context.Context, ip string, plan []int, body []byte) ([]byte, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer raw.Close()

	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	fragmented := &fragmentConn{
		Conn:   raw,
		plan:   append([]int(nil), plan...),
		budget: 900,
		delay:  4 * time.Millisecond,
	}
	tlsConn := tls.Client(fragmented, &tls.Config{
		ServerName: APIHost,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	})
	defer tlsConn.Close()

	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, handshakeTimeout)
	err = tlsConn.HandshakeContext(handshakeCtx)
	cancelHandshake()
	if err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	request, err := newAPIRequest(ctx, body)
	if err != nil {
		return nil, err
	}

	_ = tlsConn.SetDeadline(time.Now().Add(responseTimeout))
	if err := request.Write(tlsConn); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(tlsConn), request)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s: %s", response.Status, truncate(string(payload), 160))
	}
	return payload, nil
}

// RelayRequest is the body the app sends to a registration relay.
type RelayRequest struct {
	PublicKey string `json:"public_key"`
	Locale    string `json:"locale"`
	Model     string `json:"model"`
}

// RegisterViaRelay asks an operator-run relay to perform the Cloudflare call.
// The relay exists because in some networks the API host name is filtered by
// SNI and no direct transport works. Only the public key travels through it.
func RegisterViaRelay(ctx context.Context, relayURL, token, publicKey, locale, model string) ([]byte, error) {
	relayURL = strings.TrimSpace(relayURL)
	if relayURL == "" {
		return nil, errors.New("relay URL is empty")
	}
	parsed, err := url.Parse(relayURL)
	if err != nil {
		return nil, fmt.Errorf("parse relay URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("relay URL scheme %q is not supported", parsed.Scheme)
	}

	payload, err := json.Marshal(RelayRequest{
		PublicKey: publicKey,
		Locale:    locale,
		Model:     model,
	})
	if err != nil {
		return nil, fmt.Errorf("encode relay request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, relayURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "TravonetWG/1.0")
	if strings.TrimSpace(token) != "" {
		request.Header.Set("X-Relay-Token", strings.TrimSpace(token))
	}

	client := &http.Client{Timeout: 18 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("relay request: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read relay response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay HTTP %s: %s", response.Status, truncate(string(body), 160))
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf(
			"relay returned non-JSON response (is warp-relay.js deployed?): %s",
			truncate(string(body), 160),
		)
	}
	return body, nil
}

// RegisterWithFallback uses the relays in order when configured and falls back
// to the direct transports otherwise. Multiple relays can be specified as a
// comma- or whitespace-separated list (e.g. primary Cloudflare proxy, secondary direct VPS).
func RegisterWithFallback(ctx context.Context, publicKey, locale, model, relayURLs, relayToken string) ([]byte, error) {
	urls := strings.FieldsFunc(relayURLs, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
	var cleanURLs []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u != "" {
			cleanURLs = append(cleanURLs, u)
		}
	}

	var relayFailures []string
	for _, u := range cleanURLs {
		relayCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		body, err := RegisterViaRelay(relayCtx, u, relayToken, publicKey, locale, model)
		cancel()
		if err == nil && len(body) > 0 {
			return body, nil
		}
		if err != nil {
			relayFailures = append(relayFailures, fmt.Sprintf("%s (%v)", u, err))
		}
	}

	directBody, directErr := Register(ctx, publicKey, locale, model)
	if directErr == nil {
		return directBody, nil
	}
	if len(relayFailures) > 0 {
		return nil, fmt.Errorf("relays failed: %s; direct: %v", strings.Join(relayFailures, " | "), directErr)
	}
	return nil, fmt.Errorf("direct: %v", directErr)
}

func truncate(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

// fragmentConn splits the first budget bytes written to it according to plan
// and passes everything after that straight through. It is used to hide the
// ClientHello from filters that only inspect the first TCP segment.
type fragmentConn struct {
	net.Conn
	plan   []int
	budget int
	delay  time.Duration
}

func (c *fragmentConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.budget <= 0 || len(c.plan) == 0 {
		return c.Conn.Write(p)
	}

	limit := len(p)
	if limit > c.budget {
		limit = c.budget
	}

	total := 0
	for total < limit && len(c.plan) > 0 {
		chunk := c.plan[0]
		c.plan = c.plan[1:]
		if chunk <= 0 {
			continue
		}
		end := total + chunk
		if end > limit {
			end = limit
		}
		written, err := c.Conn.Write(p[total:end])
		total += written
		if err != nil {
			c.budget -= total
			return total, err
		}
		if total < limit && c.delay > 0 {
			time.Sleep(c.delay)
		}
	}

	if total < limit {
		written, err := c.Conn.Write(p[total:limit])
		total += written
		if err != nil {
			c.budget -= total
			return total, err
		}
	}

	c.budget -= total
	if total < len(p) {
		written, err := c.Conn.Write(p[total:])
		return total + written, err
	}
	return total, nil
}

// GenerateWireGuardConfig parses a Cloudflare WARP registration JSON body and
// returns a ready-to-use WireGuard configuration file with evasion directives.
func GenerateWireGuardConfig(body []byte, privateKey, strategy string) (string, error) {
	var resp struct {
		Config struct {
			ClientID string `json:"client_id"`
			Peers    []struct {
				PublicKey string `json:"public_key"`
				Endpoint  struct {
					V4   string `json:"v4"`
					V6   string `json:"v6"`
					Host string `json:"host"`
				} `json:"endpoint"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("parse WARP response: %w", err)
	}

	if len(resp.Config.Peers) == 0 {
		return "", errors.New("no peers in WARP response")
	}

	peer := resp.Config.Peers[0]
	endpoint := peer.Endpoint.V4
	if endpoint == "" {
		endpoint = peer.Endpoint.Host
	}
	if endpoint == "" {
		endpoint = "162.159.192.1:2408"
	}

	var reserved string
	if resp.Config.ClientID != "" {
		if raw, err := base64.StdEncoding.DecodeString(resp.Config.ClientID); err == nil && len(raw) == 3 {
			reserved = fmt.Sprintf("%d, %d, %d", raw[0], raw[1], raw[2])
		} else {
			reserved = resp.Config.ClientID
		}
	}

	addresses := resp.Config.Interface.Addresses.V4
	if addresses != "" && !strings.Contains(addresses, "/") {
		addresses += "/32"
	}
	if v6 := resp.Config.Interface.Addresses.V6; v6 != "" {
		if !strings.Contains(v6, "/") {
			v6 += "/128"
		}
		if addresses != "" {
			addresses += ", " + v6
		} else {
			addresses = v6
		}
	}

	if strategy == "" {
		strategy = "mimic(quic) -> mimic(stun) -> junk(64) -> fake_udp(148, corrupt=true) -> sleep(15ms)"
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", privateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", addresses))
	sb.WriteString("DNS = 1.1.1.1, 2606:4700:4700::1111\n")
	if reserved != "" {
		sb.WriteString(fmt.Sprintf("Reserved = %s\n", reserved))
	}
	sb.WriteString("FakeTTL = auto\n")
	sb.WriteString("PreJunk = 64\n")
	sb.WriteString(fmt.Sprintf("Strategy = %s\n\n", strategy))

	sb.WriteString("[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", endpoint))
	sb.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	sb.WriteString("PersistentKeepalive = 10\n")

	return sb.String(), nil
}
