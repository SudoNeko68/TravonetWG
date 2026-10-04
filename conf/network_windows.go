//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conf

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

// ApplyNetworkConfig applies IP addresses, MTU, DNS, and routes on Windows (requires Administrator)
func (c *Config) ApplyNetworkConfig(iface string) error {
	// 1. Set MTU
	if c.MTU > 0 {
		_ = exec.Command("netsh", "interface", "ipv4", "set", "subinterface", iface, fmt.Sprintf("mtu=%d", c.MTU), "store=active").Run()
	}

	// 2. Add IP addresses
	for i, addr := range c.Addresses {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			if ip, err2 := netip.ParseAddr(addr); err2 == nil {
				if ip.Is4() {
					prefix = netip.PrefixFrom(ip, 32)
				} else {
					prefix = netip.PrefixFrom(ip, 128)
				}
			} else {
				continue
			}
		}

		if prefix.Addr().Is4() {
			mask := net.CIDRMask(prefix.Bits(), 32)
			maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
			if i == 0 {
				cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
					fmt.Sprintf("name=%s", iface), "source=static",
					fmt.Sprintf("address=%s", prefix.Addr().String()),
					fmt.Sprintf("mask=%s", maskStr))
				if out, err := cmd.CombinedOutput(); err != nil {
					return fmt.Errorf("netsh set address failed: %v (%s)", err, string(out))
				}
			} else {
				_ = exec.Command("netsh", "interface", "ipv4", "add", "address",
					fmt.Sprintf("name=%s", iface),
					fmt.Sprintf("address=%s", prefix.Addr().String()),
					fmt.Sprintf("mask=%s", maskStr)).Run()
			}
		} else if prefix.Addr().Is6() {
			_ = exec.Command("netsh", "interface", "ipv6", "add", "address",
				fmt.Sprintf("interface=%s", iface),
				fmt.Sprintf("address=%s/%d", prefix.Addr().String(), prefix.Bits())).Run()
		}
	}

	// 3. Configure DNS
	for i, dns := range c.DNS {
		dns = strings.TrimSpace(dns)
		if dns == "" {
			continue
		}
		if i == 0 {
			_ = exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
				fmt.Sprintf("name=%s", iface), "source=static",
				fmt.Sprintf("address=%s", dns), "register=primary").Run()
		} else {
			_ = exec.Command("netsh", "interface", "ipv4", "add", "dnsservers",
				fmt.Sprintf("name=%s", iface),
				fmt.Sprintf("address=%s", dns), "index=2").Run()
		}
	}

	// 4. Apply Routes
	return c.ApplyRoutes(iface)
}

// ApplyRoutes configures Windows routing table for AllowedIPs
func (c *Config) ApplyRoutes(iface string) error {
	if len(c.AllowedIPs) == 0 {
		return nil
	}

	// Prevent routing loops for Endpoint
	if c.Endpoint != "" {
		endpointHost := c.Endpoint
		if h, _, err := net.SplitHostPort(c.Endpoint); err == nil {
			endpointHost = h
		}
		ips, err := net.LookupIP(endpointHost)
		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					_ = exec.Command("route", "add", ip4.String(), "mask", "255.255.255.255", "0.0.0.0", "metric", "1").Run()
				}
			}
		}
	}

	// Add routes for AllowedIPs
	for _, aip := range c.AllowedIPs {
		aip = strings.TrimSpace(aip)
		if aip == "" {
			continue
		}
		if aip == "0.0.0.0/0" {
			_ = exec.Command("netsh", "interface", "ipv4", "add", "route", "0.0.0.0/1", fmt.Sprintf("interface=%s", iface), "metric=1").Run()
			_ = exec.Command("netsh", "interface", "ipv4", "add", "route", "128.0.0.0/1", fmt.Sprintf("interface=%s", iface), "metric=1").Run()
		} else if aip == "::/0" {
			_ = exec.Command("netsh", "interface", "ipv6", "add", "route", "::/1", fmt.Sprintf("interface=%s", iface), "metric=1").Run()
			_ = exec.Command("netsh", "interface", "ipv6", "add", "route", "8000::/1", fmt.Sprintf("interface=%s", iface), "metric=1").Run()
		} else {
			if strings.Contains(aip, ":") {
				_ = exec.Command("netsh", "interface", "ipv6", "add", "route", aip, fmt.Sprintf("interface=%s", iface), "metric=1").Run()
			} else {
				_ = exec.Command("netsh", "interface", "ipv4", "add", "route", aip, fmt.Sprintf("interface=%s", iface), "metric=1").Run()
			}
		}
	}

	return nil
}

// CleanupRoutes removes added routes on Windows
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
					_ = exec.Command("route", "delete", ip4.String()).Run()
				}
			}
		}
	}

	for _, aip := range c.AllowedIPs {
		aip = strings.TrimSpace(aip)
		if aip == "0.0.0.0/0" {
			_ = exec.Command("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", fmt.Sprintf("interface=%s", iface)).Run()
			_ = exec.Command("netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", fmt.Sprintf("interface=%s", iface)).Run()
		} else if aip == "::/0" {
			_ = exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/1", fmt.Sprintf("interface=%s", iface)).Run()
			_ = exec.Command("netsh", "interface", "ipv6", "delete", "route", "8000::/1", fmt.Sprintf("interface=%s", iface)).Run()
		} else if aip != "" {
			if strings.Contains(aip, ":") {
				_ = exec.Command("netsh", "interface", "ipv6", "delete", "route", aip, fmt.Sprintf("interface=%s", iface)).Run()
			} else {
				_ = exec.Command("netsh", "interface", "ipv4", "delete", "route", aip, fmt.Sprintf("interface=%s", iface)).Run()
			}
		}
	}
}
