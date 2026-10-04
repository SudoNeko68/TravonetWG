/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conf

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

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
	PreJunkSize int
	Socks5      string

	// [Peer]
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
		MTU: 1280,
	}

	scanner := bufio.NewScanner(r)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(line[1 : len(line)-1])
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
			case "persistentkeepalive", "persistent_keepalive", "persistent-keepalive":
				if pka, err := strconv.Atoi(val); err == nil && pka > 0 {
					cfg.PersistentKeepalive = pka
				}
			case "socks5", "socks", "socks_proxy", "socks5_proxy":
				cfg.Socks5 = val
			}

		case "peer":
			switch key {
			case "publickey":
				cfg.PublicKey = val
			case "endpoint":
				cfg.Endpoint = val
			case "allowedips":
				for _, ip := range strings.Split(val, ",") {
					i := strings.TrimSpace(ip)
					if i != "" {
						cfg.AllowedIPs = append(cfg.AllowedIPs, i)
					}
				}
			case "persistentkeepalive", "persistent_keepalive", "persistent-keepalive", "persistentkeepaliveinterval", "persistent_keepalive_interval":
				if pka, err := strconv.Atoi(val); err == nil && pka > 0 {
					cfg.PersistentKeepalive = pka
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	// Default PersistentKeepalive:
	// WireGuard tunnels through NAT require periodic keepalives to prevent NAT state timeout.
	// For WireGuard servers behind typical router NATs, 25s can be too long, especially on port 500
	// where IPsec ALG / NAT helpers drop non-IPsec UDP states after 15-20 seconds.
	if cfg.PersistentKeepalive <= 0 {
		cfg.PersistentKeepalive = 10
	}
	if IsPort500Endpoint(cfg.Endpoint) && cfg.PersistentKeepalive > 10 {
		cfg.PersistentKeepalive = 5
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

	// Peer section
	if c.PublicKey != "" {
		pubBytes, err := base64.StdEncoding.DecodeString(c.PublicKey)
		if err != nil || len(pubBytes) != 32 {
			return "", fmt.Errorf("invalid PublicKey (must be 32-byte base64): %v", err)
		}

		sb.WriteString("replace_peers=true\n")
		sb.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(pubBytes)))

		if c.Endpoint != "" {
			sb.WriteString(fmt.Sprintf("endpoint=%s\n", c.Endpoint))
		}

		if len(c.AllowedIPs) > 0 {
			sb.WriteString("replace_allowed_ips=true\n")
			for _, aip := range c.AllowedIPs {
				sb.WriteString(fmt.Sprintf("allowed_ip=%s\n", aip))
			}
		}

		if c.PersistentKeepalive > 0 {
			sb.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", c.PersistentKeepalive))
		}
	}

	return sb.String(), nil
}
