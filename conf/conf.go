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
	"net"
	"os"
	"os/exec"
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

	cfg := &Config{
		MTU: 1280,
	}

	scanner := bufio.NewScanner(file)
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
	// For Cloudflare WARP and typical router NATs, 25s can be too long, especially on port 500
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

// ApplyNetworkConfig applies IP addresses and MTU using system commands
func (c *Config) ApplyNetworkConfig(iface string) error {
	// Set MTU
	if c.MTU > 0 {
		_ = exec.Command("ip", "link", "set", "mtu", strconv.Itoa(c.MTU), "dev", iface).Run()
	}

	// Add IP addresses
	for _, addr := range c.Addresses {
		if !strings.Contains(addr, "/") {
			if strings.Contains(addr, ":") {
				addr += "/128"
			} else {
				addr += "/32"
			}
		}
		cmd := exec.Command("ip", "address", "replace", addr, "dev", iface)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ip address replace %s dev %s failed: %v (%s)", addr, iface, err, string(out))
		}
	}

	// Set link UP
	cmd := exec.Command("ip", "link", "set", "up", "dev", iface)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up dev %s failed: %v (%s)", iface, err, string(out))
	}

	// Apply routes for AllowedIPs (preventing routing loops for Endpoint)
	if err := c.ApplyRoutes(iface); err != nil {
		return fmt.Errorf("failed to apply routes for %s: %w", iface, err)
	}

	return nil
}

// ApplyRoutes configures system routing table for AllowedIPs
func (c *Config) ApplyRoutes(iface string) error {
	if len(c.AllowedIPs) == 0 {
		return nil
	}

	// 1. If we have an Endpoint, resolve its IP and add a host route via default gateway
	// to prevent routing loops when routing 0.0.0.0/0 into the WireGuard interface.
	if c.Endpoint != "" {
		endpointHost := c.Endpoint
		if h, _, err := net.SplitHostPort(c.Endpoint); err == nil {
			endpointHost = h
		}
		ips, err := net.LookupIP(endpointHost)
		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					// Find default gateway for this IPv4
					gw, gwDev, err := getDefaultGateway()
					if err == nil && gw != "" && gwDev != iface {
						_ = exec.Command("ip", "-4", "route", "add", ip4.String()+"/32", "via", gw, "dev", gwDev).Run()
					}
				}
			}
		}
	}

	// 2. Add routes for AllowedIPs
	for _, aip := range c.AllowedIPs {
		aip = strings.TrimSpace(aip)
		if aip == "" {
			continue
		}
		if aip == "0.0.0.0/0" {
			// wg-quick style: split into two /1 subnets to override default route without destroying it
			_ = exec.Command("ip", "-4", "route", "add", "0.0.0.0/1", "dev", iface).Run()
			_ = exec.Command("ip", "-4", "route", "add", "128.0.0.0/1", "dev", iface).Run()
		} else if aip == "::/0" {
			_ = exec.Command("ip", "-6", "route", "add", "::/1", "dev", iface).Run()
			_ = exec.Command("ip", "-6", "route", "add", "8000::/1", "dev", iface).Run()
		} else {
			family := "-4"
			if strings.Contains(aip, ":") {
				family = "-6"
			}
			_ = exec.Command("ip", family, "route", "add", aip, "dev", iface).Run()
		}
	}

	return nil
}

// CleanupRoutes removes added routes and endpoint host routes
func (c *Config) CleanupRoutes(iface string) {
	if c.Endpoint != "" {
		endpointHost := c.Endpoint
		if h, _, err := net.SplitHostPort(c.Endpoint); err == nil {
			endpointHost = h
		}
		ips, err := net.LookupIP(endpointHost)
		if err == nil {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					_ = exec.Command("ip", "-4", "route", "del", ip4.String()+"/32").Run()
				}
			}
		}
	}

	for _, aip := range c.AllowedIPs {
		aip = strings.TrimSpace(aip)
		if aip == "0.0.0.0/0" {
			_ = exec.Command("ip", "-4", "route", "del", "0.0.0.0/1", "dev", iface).Run()
			_ = exec.Command("ip", "-4", "route", "del", "128.0.0.0/1", "dev", iface).Run()
		} else if aip == "::/0" {
			_ = exec.Command("ip", "-6", "route", "del", "::/1", "dev", iface).Run()
			_ = exec.Command("ip", "-6", "route", "del", "8000::/1", "dev", iface).Run()
		} else if aip != "" {
			family := "-4"
			if strings.Contains(aip, ":") {
				family = "-6"
			}
			_ = exec.Command("ip", family, "route", "del", aip, "dev", iface).Run()
		}
	}
}

// getDefaultGateway discovers the current IPv4 default route gateway and device
func getDefaultGateway() (string, string, error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", "", err
	}
	// Example: "default via 192.168.0.1 dev enp3s0 proto dhcp ..."
	fields := strings.Fields(string(out))
	var gw, dev string
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "via" {
			gw = fields[i+1]
		}
		if fields[i] == "dev" {
			dev = fields[i+1]
		}
	}
	if gw != "" && dev != "" {
		return gw, dev, nil
	}
	return "", "", fmt.Errorf("no default gateway found in: %s", string(out))
}
