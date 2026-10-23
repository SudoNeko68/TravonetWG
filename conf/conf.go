/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conf

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type PeerConfig struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

type Config struct {
	// [Interface]
	PrivateKey string
	Addresses  []string
	DNS        []string
	MTU        int
	ListenPort int

	// Evasion settings in [Interface]
	Strategy    string
	FakeTTL     int
	NormalTTL   int
	PreJunkSize int
	Socks5      string
	SocksAuth   string
	NoEvasion   bool
	Debug       bool
	// DebugSet records that the config contained an explicit Debug key, so a
	// deliberate "Debug = false" can override the default verbose logging.
	DebugSet bool

	// AmneziaWG obfuscation settings in [Interface]
	Jc   int
	Jmin int
	Jmax int
	S1   int
	S2   int
	S3   int
	S4   int
	H1   string
	H2   string
	H3   string
	H4   string
	I1   string
	I2   string
	I3   string
	I4   string
	I5   string

	HeaderProtectionKey    string
	ContentPaddingAddition string
	RandomTrailers         bool
	DisableCookies         bool
	RekeyAfterTime         string
	RekeyTimeout           string
	RejectAfterTime        string
	KeepaliveTimeout       string
	MaxHandshakeAttempts   string

	// [Peer] list
	Peers []PeerConfig

	// Backward-compatibility shortcuts for primary peer
	PublicKey           string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

// ParseConfigFile parses a WireGuard .conf file
func ParseConfigFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config: %w", err)
	}
	defer file.Close()
	return ParseConfig(file)
}

// ParseConfigString parses a WireGuard .conf formatted string
func ParseConfigString(content string) (*Config, error) {
	return ParseConfig(strings.NewReader(content))
}

// ParseConfig parses WireGuard configuration from an io.Reader
func ParseConfig(r io.Reader) (*Config, error) {
	cfg := &Config{
		MTU:       1280,
		NormalTTL: 64,
	}

	scanner := bufio.NewScanner(r)
	currentSection := ""
	var peers []PeerConfig
	var curPeer *PeerConfig

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			newSection := strings.ToLower(line[1 : len(line)-1])
			if currentSection == "peer" && curPeer != nil {
				peers = append(peers, *curPeer)
				curPeer = nil
			}
			if newSection == "peer" {
				curPeer = &PeerConfig{}
			}
			currentSection = newSection
			continue
		}

		eqIdx := strings.Index(line, "=")
		if eqIdx < 0 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(line[:eqIdx]))
		val := strings.TrimSpace(line[eqIdx+1:])

		switch currentSection {
		case "interface":
			switch key {
			case "privatekey":
				cfg.PrivateKey = val
			case "address":
				for _, addr := range strings.Split(val, ",") {
					a := strings.TrimSpace(addr)
					if a != "" {
						cfg.Addresses = append(cfg.Addresses, a)
					}
				}
			case "dns":
				for _, dns := range strings.Split(val, ",") {
					d := strings.TrimSpace(dns)
					if d != "" {
						cfg.DNS = append(cfg.DNS, d)
					}
				}
			case "mtu":
				if mtu, err := strconv.Atoi(val); err == nil && mtu > 0 {
					cfg.MTU = mtu
				}
			case "listenport":
				if lp, err := strconv.Atoi(val); err == nil {
					cfg.ListenPort = lp
				}
			case "strategy":
				cfg.Strategy = val
			case "fakettl", "fake_ttl":
				if strings.EqualFold(val, "auto") {
					cfg.FakeTTL = -1
				} else if ttl, err := strconv.Atoi(val); err == nil {
					cfg.FakeTTL = ttl
				}
			case "prejunk", "pre_junk", "prejunksize":
				if sz, err := strconv.Atoi(val); err == nil {
					cfg.PreJunkSize = sz
				}
			case "normalttl", "normal_ttl":
				if ttl, err := strconv.Atoi(val); err == nil && ttl > 0 {
					cfg.NormalTTL = ttl
				}
			case "jc":
				if v, err := strconv.Atoi(val); err == nil && v >= 0 {
					cfg.Jc = v
				}
			case "jmin":
				if v, err := strconv.Atoi(val); err == nil && v >= 0 {
					cfg.Jmin = v
				}
				if sz, err := strconv.Atoi(val); err == nil && cfg.PreJunkSize == 0 {
					cfg.PreJunkSize = sz
				}
			case "jmax":
				if v, err := strconv.Atoi(val); err == nil && v >= 0 {
					cfg.Jmax = v
				}
			case "s1", "s2", "s3", "s4":
				v, err := strconv.Atoi(val)
				if err != nil || v < 0 {
					break
				}
				switch key {
				case "s1":
					cfg.S1 = v
				case "s2":
					cfg.S2 = v
				case "s3":
					cfg.S3 = v
				case "s4":
					cfg.S4 = v
				}
			case "h1", "h2", "h3", "h4":
				switch key {
				case "h1":
					cfg.H1 = val
				case "h2":
					cfg.H2 = val
				case "h3":
					cfg.H3 = val
				case "h4":
					cfg.H4 = val
				}
			case "i1", "i2", "i3", "i4", "i5":
				switch key {
				case "i1":
					cfg.I1 = val
				case "i2":
					cfg.I2 = val
				case "i3":
					cfg.I3 = val
				case "i4":
					cfg.I4 = val
				case "i5":
					cfg.I5 = val
				}
			case "headerprotectionkey", "header_protection_key":
				cfg.HeaderProtectionKey = val
			case "contentpaddingaddition", "content_padding_addition":
				cfg.ContentPaddingAddition = val
			case "randomtrailers", "random_trailers":
				if b, err := strconv.ParseBool(val); err == nil {
					cfg.RandomTrailers = b
				}
			case "disablecookies", "disable_cookies":
				if b, err := strconv.ParseBool(val); err == nil {
					cfg.DisableCookies = b
				}
			case "rekeyaftertime", "rekey_after_time":
				cfg.RekeyAfterTime = val
			case "rekeytimeout", "rekey_timeout":
				cfg.RekeyTimeout = val
			case "rejectaftertime", "reject_after_time":
				cfg.RejectAfterTime = val
			case "keepalivetimeout", "keepalive_timeout":
				cfg.KeepaliveTimeout = val
			case "maxhandshakeattempts", "max_handshake_attempts":
				cfg.MaxHandshakeAttempts = val
			case "persistentkeepalive", "persistent_keepalive", "persistent-keepalive":
				if pka, err := strconv.Atoi(val); err == nil && pka > 0 {
					cfg.PersistentKeepalive = pka
				}
			case "socks5", "socks", "socks_proxy", "socks5_proxy":
				cfg.Socks5 = val
			case "socksauth", "socks_auth", "socks-auth":
				cfg.SocksAuth = val
			case "noevasion", "no_evasion", "disableevasion", "disable_evasion":
				cfg.NoEvasion = parseBoolValue(val)
			case "debug", "evasion_debug", "evasiondebug":
				cfg.Debug = parseBoolValue(val)
				cfg.DebugSet = true
			}

		case "peer":
			if curPeer == nil {
				curPeer = &PeerConfig{}
			}
			switch key {
			case "publickey":
				curPeer.PublicKey = val
			case "presharedkey", "preshared_key":
				curPeer.PresharedKey = val
			case "endpoint":
				curPeer.Endpoint = val
			case "allowedips":
				for _, ip := range strings.Split(val, ",") {
					i := strings.TrimSpace(ip)
					if i != "" {
						curPeer.AllowedIPs = append(curPeer.AllowedIPs, i)
					}
				}
			case "persistentkeepalive", "persistent_keepalive", "persistent-keepalive", "persistentkeepaliveinterval", "persistent_keepalive_interval":
				if pka, err := strconv.Atoi(val); err == nil && pka > 0 {
					curPeer.PersistentKeepalive = pka
				}
			}
		}
	}

	if currentSection == "peer" && curPeer != nil {
		peers = append(peers, *curPeer)
		curPeer = nil
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	for i := range peers {
		if peers[i].PersistentKeepalive <= 0 {
			if cfg.PersistentKeepalive > 0 {
				peers[i].PersistentKeepalive = cfg.PersistentKeepalive
			} else {
				peers[i].PersistentKeepalive = DefaultKeepalive
			}
		}
		if IsPort500Endpoint(peers[i].Endpoint) && peers[i].PersistentKeepalive > LowPortKeepaliveLimit {
			peers[i].PersistentKeepalive = LowPortKeepalive
		}
	}
	cfg.Peers = peers
	if len(peers) > 0 {
		cfg.PublicKey = peers[0].PublicKey
		cfg.Endpoint = peers[0].Endpoint
		cfg.AllowedIPs = peers[0].AllowedIPs
		cfg.PersistentKeepalive = peers[0].PersistentKeepalive
	} else {
		if cfg.PersistentKeepalive <= 0 {
			cfg.PersistentKeepalive = DefaultKeepalive
		}
		if IsPort500Endpoint(cfg.Endpoint) && cfg.PersistentKeepalive > LowPortKeepaliveLimit {
			cfg.PersistentKeepalive = LowPortKeepalive
		}
	}

	return cfg, nil
}

// IsPort500Endpoint checks if the endpoint targets UDP port 500 (IKE / IPsec)
func IsPort500Endpoint(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	_, portStr, err := net.SplitHostPort(endpoint)
	if err == nil && portStr == "500" {
		return true
	}
	return strings.HasSuffix(endpoint, ":500")
}

// dnsLookupTimeout bounds hostname resolution so a black-holed DNS server can
// never stall tunnel setup (Android has no root and no way to inject a resolver
// into the Go runtime, so a bounded context is the only safe control).
const dnsLookupTimeout = 3 * time.Second

// LookupHostIPs resolves a hostname with a bounded timeout and returns every
// address advertised for it.
func LookupHostIPs(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, net.IP(addr.AsSlice()))
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}
	return ips, nil
}

// ResolveEndpointHostPort resolves the host part of an endpoint if it is a
// domain name. WireGuard's UAPI endpoint parser (netip.ParseAddrPort) only
// accepts numeric addresses, so domain endpoints must be resolved before the
// configuration is handed to device.IpcSet.
//
// If the endpoint already contains an IP address, or cannot be split into
// host:port, it is returned unchanged.
func ResolveEndpointHostPort(endpoint string) string {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint
	}
	if host == "" {
		return endpoint
	}
	if ip := net.ParseIP(host); ip != nil {
		return endpoint
	}

	ips, err := LookupHostIPs(host)
	if err != nil || len(ips) == 0 {
		return endpoint
	}

	var chosen net.IP
	for _, candidate := range ips {
		if candidate.To4() != nil {
			chosen = candidate
			break
		}
	}
	if chosen == nil {
		chosen = ips[0]
	}
	return net.JoinHostPort(chosen.String(), port)
}

// ToUAPI converts the parsed configuration to WireGuard UAPI format
func (c *Config) ToUAPI() (string, error) {
	var sb strings.Builder

	// PrivateKey base64 -> hex
	privBytes, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil || len(privBytes) != 32 {
		return "", fmt.Errorf("invalid PrivateKey (must be 32-byte base64): %v", err)
	}
	sb.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(privBytes)))

	if c.ListenPort > 0 {
		sb.WriteString(fmt.Sprintf("listen_port=%d\n", c.ListenPort))
	}

	// AmneziaWG obfuscation settings (device-level UAPI keys).
	if c.Jc > 0 {
		sb.WriteString(fmt.Sprintf("jc=%d\n", c.Jc))
	}
	if c.Jmin > 0 {
		sb.WriteString(fmt.Sprintf("jmin=%d\n", c.Jmin))
	}
	if c.Jmax > 0 {
		sb.WriteString(fmt.Sprintf("jmax=%d\n", c.Jmax))
	}
	if c.S1 > 0 {
		sb.WriteString(fmt.Sprintf("s1=%d\n", c.S1))
	}
	if c.S2 > 0 {
		sb.WriteString(fmt.Sprintf("s2=%d\n", c.S2))
	}
	if c.S3 > 0 {
		sb.WriteString(fmt.Sprintf("s3=%d\n", c.S3))
	}
	if c.S4 > 0 {
		sb.WriteString(fmt.Sprintf("s4=%d\n", c.S4))
	}
	if c.H1 != "" {
		sb.WriteString(fmt.Sprintf("h1=%s\n", c.H1))
	}
	if c.H2 != "" {
		sb.WriteString(fmt.Sprintf("h2=%s\n", c.H2))
	}
	if c.H3 != "" {
		sb.WriteString(fmt.Sprintf("h3=%s\n", c.H3))
	}
	if c.H4 != "" {
		sb.WriteString(fmt.Sprintf("h4=%s\n", c.H4))
	}
	if c.I1 != "" {
		sb.WriteString(fmt.Sprintf("i1=%s\n", c.I1))
	}
	if c.I2 != "" {
		sb.WriteString(fmt.Sprintf("i2=%s\n", c.I2))
	}
	if c.I3 != "" {
		sb.WriteString(fmt.Sprintf("i3=%s\n", c.I3))
	}
	if c.I4 != "" {
		sb.WriteString(fmt.Sprintf("i4=%s\n", c.I4))
	}
	if c.I5 != "" {
		sb.WriteString(fmt.Sprintf("i5=%s\n", c.I5))
	}
	if c.HeaderProtectionKey != "" {
		sb.WriteString(fmt.Sprintf("header_protection_key=%s\n", c.HeaderProtectionKey))
	}
	if c.ContentPaddingAddition != "" {
		sb.WriteString(fmt.Sprintf("content_padding_addition=%s\n", c.ContentPaddingAddition))
	}
	if c.RandomTrailers {
		sb.WriteString("random_trailers=true\n")
	}
	if c.DisableCookies {
		sb.WriteString("disable_cookies=true\n")
	}
	if c.RekeyAfterTime != "" {
		sb.WriteString(fmt.Sprintf("rekey_after_time=%s\n", c.RekeyAfterTime))
	}
	if c.RekeyTimeout != "" {
		sb.WriteString(fmt.Sprintf("rekey_timeout=%s\n", c.RekeyTimeout))
	}
	if c.RejectAfterTime != "" {
		sb.WriteString(fmt.Sprintf("reject_after_time=%s\n", c.RejectAfterTime))
	}
	if c.KeepaliveTimeout != "" {
		sb.WriteString(fmt.Sprintf("keepalive_timeout=%s\n", c.KeepaliveTimeout))
	}
	if c.MaxHandshakeAttempts != "" {
		sb.WriteString(fmt.Sprintf("max_handshake_attempts=%s\n", c.MaxHandshakeAttempts))
	}

	peers := c.Peers
	if len(peers) == 0 && c.PublicKey != "" {
		peers = []PeerConfig{{
			PublicKey:           c.PublicKey,
			Endpoint:            c.Endpoint,
			AllowedIPs:          c.AllowedIPs,
			PersistentKeepalive: c.PersistentKeepalive,
		}}
	}

	if len(peers) > 0 {
		sb.WriteString("replace_peers=true\n")
		for _, peer := range peers {
			if peer.PublicKey == "" {
				continue
			}
			pubBytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
			if err != nil || len(pubBytes) != 32 {
				return "", fmt.Errorf("invalid PublicKey (must be 32-byte base64): %v", err)
			}
			sb.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(pubBytes)))

			if peer.PresharedKey != "" {
				pskBytes, err := base64.StdEncoding.DecodeString(peer.PresharedKey)
				if err != nil || len(pskBytes) != 32 {
					return "", fmt.Errorf("invalid PresharedKey (must be 32-byte base64): %v", err)
				}
				sb.WriteString(fmt.Sprintf("preshared_key=%s\n", hex.EncodeToString(pskBytes)))
			}

			if peer.Endpoint != "" {
				sb.WriteString(fmt.Sprintf("endpoint=%s\n", ResolveEndpointHostPort(peer.Endpoint)))
			}

			if len(peer.AllowedIPs) > 0 {
				sb.WriteString("replace_allowed_ips=true\n")
				for _, aip := range peer.AllowedIPs {
					sb.WriteString(fmt.Sprintf("allowed_ip=%s\n", aip))
				}
			}

			if peer.PersistentKeepalive > 0 {
				sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))
			}
		}
	}

	return sb.String(), nil
}
