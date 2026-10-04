//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conf

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

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
