//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conf

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ApplyNetworkConfig applies IP addresses, MTU, DNS, and routes using system commands
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

	// Apply routes for AllowedIPs (preventing routing loops for Endpoints)
	if err := c.ApplyRoutes(iface); err != nil {
		return fmt.Errorf("failed to apply routes for %s: %w", iface, err)
	}

	// Configure DNS if specified
	if len(c.DNS) > 0 {
		_ = applyDNSLinux(iface, c.DNS)
	}

	return nil
}

// ApplyRoutes configures system routing table for AllowedIPs across all peers
func (c *Config) ApplyRoutes(iface string) error {
	peers := c.Peers
	if len(peers) == 0 && c.PublicKey != "" {
		peers = []PeerConfig{{
			PublicKey:  c.PublicKey,
			Endpoint:   c.Endpoint,
			AllowedIPs: c.AllowedIPs,
		}}
	}

	// 1. For each Peer with an Endpoint, resolve IP and add direct host route via physical gateway
	for _, peer := range peers {
		if peer.Endpoint != "" {
			endpointHost := peer.Endpoint
			if h, _, err := net.SplitHostPort(peer.Endpoint); err == nil {
				endpointHost = h
			}
			ips, err := net.LookupIP(endpointHost)
			if err == nil && len(ips) > 0 {
				for _, ip := range ips {
					if ip4 := ip.To4(); ip4 != nil {
						gw, gwDev, err := getDefaultGateway()
						if err == nil && gw != "" && gwDev != iface {
							_ = exec.Command("ip", "-4", "route", "replace", ip4.String()+"/32", "via", gw, "dev", gwDev).Run()
						}
					}
				}
			}
		}
	}

	// 2. Add routes for AllowedIPs across all peers
	var allAllowedIPs []string
	for _, peer := range peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
	}
	if len(allAllowedIPs) == 0 {
		allAllowedIPs = c.AllowedIPs
	}

	for _, aip := range allAllowedIPs {
		aip = strings.TrimSpace(aip)
		if aip == "" {
			continue
		}
		if aip == "0.0.0.0/0" {
			// wg-quick style: split into two /1 subnets to override default route without destroying it
			_ = exec.Command("ip", "-4", "route", "replace", "0.0.0.0/1", "dev", iface).Run()
			_ = exec.Command("ip", "-4", "route", "replace", "128.0.0.0/1", "dev", iface).Run()
		} else if aip == "::/0" {
			_ = exec.Command("ip", "-6", "route", "replace", "::/1", "dev", iface).Run()
			_ = exec.Command("ip", "-6", "route", "replace", "8000::/1", "dev", iface).Run()
		} else {
			family := "-4"
			if strings.Contains(aip, ":") {
				family = "-6"
			}
			_ = exec.Command("ip", family, "route", "replace", aip, "dev", iface).Run()
		}
	}

	return nil
}

// CleanupRoutes removes added routes and endpoint host routes
func (c *Config) CleanupRoutes(iface string) {
	cleanupDNSLinux(iface)

	peers := c.Peers
	if len(peers) == 0 && c.PublicKey != "" {
		peers = []PeerConfig{{
			PublicKey:  c.PublicKey,
			Endpoint:   c.Endpoint,
			AllowedIPs: c.AllowedIPs,
		}}
	}

	for _, peer := range peers {
		if peer.Endpoint != "" {
			endpointHost := peer.Endpoint
			if h, _, err := net.SplitHostPort(peer.Endpoint); err == nil {
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
	}

	var allAllowedIPs []string
	for _, peer := range peers {
		allAllowedIPs = append(allAllowedIPs, peer.AllowedIPs...)
	}
	if len(allAllowedIPs) == 0 {
		allAllowedIPs = c.AllowedIPs
	}

	for _, aip := range allAllowedIPs {
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

const resolvBakPath = "/etc/resolv.conf.travonet_bak"

func applyDNSLinux(iface string, dnsServers []string) error {
	if _, err := exec.LookPath("resolvectl"); err == nil {
		args := append([]string{"dns", iface}, dnsServers...)
		if err := exec.Command("resolvectl", args...).Run(); err == nil {
			_ = exec.Command("resolvectl", "domain", iface, "~.").Run()
			return nil
		}
	}

	if _, err := exec.LookPath("resolvconf"); err == nil {
		var lines []string
		for _, d := range dnsServers {
			lines = append(lines, "nameserver "+d)
		}
		cmd := exec.Command("resolvconf", "-a", "tun."+iface)
		cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	// Fallback to /etc/resolv.conf
	if _, err := os.Stat(resolvBakPath); os.IsNotExist(err) {
		if content, err := os.ReadFile("/etc/resolv.conf"); err == nil {
			_ = os.WriteFile(resolvBakPath, content, 0644)
		}
	}

	var sb strings.Builder
	sb.WriteString("# Generated by TravonetWG\n")
	for _, d := range dnsServers {
		sb.WriteString("nameserver " + d + "\n")
	}
	return os.WriteFile("/etc/resolv.conf", []byte(sb.String()), 0644)
}

func cleanupDNSLinux(iface string) {
	if _, err := exec.LookPath("resolvectl"); err == nil {
		_ = exec.Command("resolvectl", "revert", iface).Run()
	}
	if _, err := exec.LookPath("resolvconf"); err == nil {
		_ = exec.Command("resolvconf", "-d", "tun."+iface).Run()
	}
	if _, err := os.Stat(resolvBakPath); err == nil {
		if content, err := os.ReadFile(resolvBakPath); err == nil {
			_ = os.WriteFile("/etc/resolv.conf", content, 0644)
		}
		_ = os.Remove(resolvBakPath)
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
