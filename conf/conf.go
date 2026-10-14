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
	PreJunkSize int
	Socks5      string

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
		MTU: 1280,
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
			case "persistentkeepalive", "persistent_keepalive", "persistent-keepalive":
				if pka, err := strconv.Atoi(val); err == nil && pka > 0 {
					cfg.PersistentKeepalive = pka
				}
			case "socks5", "socks", "socks_proxy", "socks5_proxy":
				cfg.Socks5 = val
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
				peers[i].PersistentKeepalive = 10
			}
		}
		if IsPort500Endpoint(peers[i].Endpoint) && peers[i].PersistentKeepalive > 10 {
			peers[i].PersistentKeepalive = 5
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
			cfg.PersistentKeepalive = 10
		}
		if IsPort500Endpoint(cfg.Endpoint) && cfg.PersistentKeepalive > 10 {
			cfg.PersistentKeepalive = 5
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
				sb.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint))
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
