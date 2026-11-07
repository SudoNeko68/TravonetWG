/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conf

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// AmneziaContainer holds container settings inside an Amnezia config.
type AmneziaContainer struct {
	Container string         `json:"container"`
	AWG       map[string]any `json:"awg"`
	WireGuard map[string]any `json:"wireguard"`
}

// AmneziaRoot represents the top-level JSON structure in an Amnezia VPN export.
type AmneziaRoot struct {
	HostName         string             `json:"hostName"`
	Description      string             `json:"description"`
	DefaultContainer string             `json:"defaultContainer"`
	DNS1             string             `json:"dns1"`
	DNS2             string             `json:"dns2"`
	Containers       []AmneziaContainer `json:"containers"`
}

// ParseVPNURL decodes an Amnezia "vpn://" URL, extracts the AmneziaWG/WireGuard configuration,
// and returns the standard WireGuard/AmneziaWG INI config text along with the suggested profile name.
// Supports both official Amnezia JSON containers and 3X-UI raw Base64 INI exports.
func ParseVPNURL(vpnURL string) (configText string, profileName string, err error) {
	trimmed := strings.TrimSpace(vpnURL)
	if !strings.HasPrefix(strings.ToLower(trimmed), "vpn://") {
		return "", "", errors.New("url does not start with vpn://")
	}

	payload := strings.TrimSpace(trimmed[6:])
	// Trim trailing punctuation (e.g. dots, commas, query params, slashes, whitespace)
	payload = strings.TrimRight(payload, ".\r\n\t ,;/?#")
	if payload == "" {
		return "", "", errors.New("vpn:// payload is empty")
	}

	rawBytes, err := decodeBase64Payload(payload)
	if err != nil {
		return "", "", fmt.Errorf("base64 decode: %w", err)
	}

	// 1. Direct check: is rawBytes an uncompressed WireGuard/AmneziaWG INI config?
	rawStr := strings.TrimSpace(string(rawBytes))
	if isWireGuardINI(rawStr) {
		name := extractProfileNameFromINI(rawStr)
		return rawStr, name, nil
	}

	// 2. Try decompression (Qt qCompress, raw zlib, raw gzip)
	decompressed, err := decompressAmneziaPayload(rawBytes)
	if err == nil {
		decompStr := strings.TrimSpace(string(decompressed))
		if isWireGuardINI(decompStr) {
			name := extractProfileNameFromINI(decompStr)
			return decompStr, name, nil
		}
		// If decompressed is JSON, parse as Amnezia JSON
		if strings.HasPrefix(decompStr, "{") || strings.HasPrefix(decompStr, "[") {
			return parseAmneziaJSON(decompressed)
		}
	}

	// If decompress failed or didn't match, try parsing rawBytes as JSON
	if strings.HasPrefix(rawStr, "{") || strings.HasPrefix(rawStr, "[") {
		return parseAmneziaJSON(rawBytes)
	}

	return "", "", errors.New("unrecognized vpn:// payload format")
}

func isWireGuardINI(s string) bool {
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "{") {
		return false
	}
	return strings.Contains(trimmed, "[Interface]") && (strings.Contains(trimmed, "PrivateKey") || strings.Contains(trimmed, "[Peer]"))
}

func extractProfileNameFromINI(iniText string) string {
	var explicitName string
	var commentName string
	var endpointHost string

	scanner := bufio.NewScanner(strings.NewReader(iniText))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			comment := strings.TrimSpace(strings.TrimLeft(line, "#; "))
			lower := strings.ToLower(comment)
			if strings.HasPrefix(lower, "name:") || strings.HasPrefix(lower, "name=") {
				explicitName = strings.TrimSpace(comment[5:])
			} else if strings.HasPrefix(lower, "profile:") || strings.HasPrefix(lower, "profile=") {
				explicitName = strings.TrimSpace(comment[8:])
			} else if commentName == "" && comment != "" && !strings.HasPrefix(lower, "spdx-") {
				commentName = comment
			}
			continue
		}

		if eq := strings.Index(line, "="); eq >= 0 {
			key := strings.ToLower(strings.TrimSpace(line[:eq]))
			val := strings.TrimSpace(line[eq+1:])
			if key == "endpoint" && endpointHost == "" {
				host, _, err := net.SplitHostPort(val)
				if err == nil && host != "" {
					endpointHost = host
				} else if val != "" {
					endpointHost = val
				}
			}
		}
	}

	if explicitName != "" {
		return explicitName
	}
	if commentName != "" && endpointHost != "" {
		if strings.EqualFold(commentName, "AmneziaWG") || strings.EqualFold(commentName, "WireGuard") {
			return fmt.Sprintf("%s (%s)", commentName, endpointHost)
		}
		return commentName
	}
	if commentName != "" {
		return commentName
	}
	if endpointHost != "" {
		return endpointHost
	}
	return "AmneziaWG"
}

func decodeBase64Payload(payload string) ([]byte, error) {
	// Strip any whitespace
	payload = strings.ReplaceAll(payload, "\r", "")
	payload = strings.ReplaceAll(payload, "\n", "")
	payload = strings.ReplaceAll(payload, " ", "")
	payload = strings.ReplaceAll(payload, "\t", "")

	// Handle URL percent-encoding if present (%2B, %2F, %3D etc.)
	if strings.Contains(payload, "%") {
		if unescaped, err := url.QueryUnescape(payload); err == nil {
			payload = unescaped
		}
	}

	// Try standard and URL-safe base64 decoders
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}

	for _, enc := range encodings {
		if data, err := enc.DecodeString(payload); err == nil && len(data) > 0 {
			return data, nil
		}
	}

	// Try with added padding if missing
	if rem := len(payload) % 4; rem != 0 {
		padded := payload + strings.Repeat("=", 4-rem)
		for _, enc := range encodings {
			if data, err := enc.DecodeString(padded); err == nil && len(data) > 0 {
				return data, nil
			}
		}
	}

	return nil, errors.New("invalid base64 encoding")
}

func decompressAmneziaPayload(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty payload")
	}

	// 1. Check for Qt qCompress format: 4-byte big-endian expected length followed by zlib stream
	if len(data) > 4 {
		expectedLen := binary.BigEndian.Uint32(data[:4])
		// Reasonable bounds check for uncompressed config text (up to 4MB)
		if expectedLen > 0 && expectedLen < 4*1024*1024 {
			if r, err := zlib.NewReader(bytes.NewReader(data[4:])); err == nil {
				uncompressed, err := io.ReadAll(r)
				_ = r.Close()
				if err == nil && len(uncompressed) > 0 {
					return uncompressed, nil
				}
			}
		}
	}

	// 2. Direct zlib stream
	if r, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
		uncompressed, err := io.ReadAll(r)
		_ = r.Close()
		if err == nil && len(uncompressed) > 0 {
			return uncompressed, nil
		}
	}

	// 3. Direct gzip stream
	if r, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
		uncompressed, err := io.ReadAll(r)
		_ = r.Close()
		if err == nil && len(uncompressed) > 0 {
			return uncompressed, nil
		}
	}

	// 4. Plain UTF-8 JSON (uncompressed)
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return data, nil
	}

	return nil, errors.New("unrecognized payload format (possibly encrypted with password)")
}

func parseAmneziaJSON(jsonData []byte) (configText string, profileName string, err error) {
	var root AmneziaRoot
	if err := json.Unmarshal(jsonData, &root); err != nil {
		// Fallback to generic map
		var rawMap map[string]any
		if errMap := json.Unmarshal(jsonData, &rawMap); errMap != nil {
			return "", "", fmt.Errorf("unmarshal JSON: %w", err)
		}
		return parseAmneziaMap(rawMap, "", "")
	}

	name := root.Description
	if name == "" {
		name = root.HostName
	}
	if name == "" {
		name = "Amnezia AWG"
	}

	// Search for amnezia-awg or amnezia-wireguard container
	for _, c := range root.Containers {
		cName := strings.ToLower(c.Container)
		if strings.Contains(cName, "awg") && c.AWG != nil {
			if cfg, err := extractConfigFromContainerMap(c.AWG, root.HostName, root.DNS1, root.DNS2); err == nil && cfg != "" {
				return cfg, name, nil
			}
		}
		if strings.Contains(cName, "wireguard") && c.WireGuard != nil {
			if cfg, err := extractConfigFromContainerMap(c.WireGuard, root.HostName, root.DNS1, root.DNS2); err == nil && cfg != "" {
				return cfg, name, nil
			}
		}
		if c.AWG != nil {
			if cfg, err := extractConfigFromContainerMap(c.AWG, root.HostName, root.DNS1, root.DNS2); err == nil && cfg != "" {
				return cfg, name, nil
			}
		}
		if c.WireGuard != nil {
			if cfg, err := extractConfigFromContainerMap(c.WireGuard, root.HostName, root.DNS1, root.DNS2); err == nil && cfg != "" {
				return cfg, name, nil
			}
		}
	}

	// If no container matched typed struct, try raw map parse
	var rawMap map[string]any
	_ = json.Unmarshal(jsonData, &rawMap)
	return parseAmneziaMap(rawMap, root.HostName, name)
}

func parseAmneziaMap(rawMap map[string]any, hostName, fallbackName string) (string, string, error) {
	if rawMap == nil {
		return "", "", errors.New("empty amnezia map")
	}

	name := fallbackName
	if desc, ok := rawMap["description"].(string); ok && desc != "" {
		name = desc
	} else if host, ok := rawMap["hostName"].(string); ok && host != "" {
		name = host
		if hostName == "" {
			hostName = host
		}
	}
	if name == "" {
		name = "Amnezia AWG"
	}

	dns1, _ := rawMap["dns1"].(string)
	dns2, _ := rawMap["dns2"].(string)

	// Check "containers" array
	if containers, ok := rawMap["containers"].([]any); ok {
		for _, item := range containers {
			cMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			for _, protoKey := range []string{"awg", "amnezia-awg", "wireguard", "amnezia-wireguard"} {
				if protoMap, ok := cMap[protoKey].(map[string]any); ok {
					if cfg, err := extractConfigFromContainerMap(protoMap, hostName, dns1, dns2); err == nil && cfg != "" {
						return cfg, name, nil
					}
				}
			}
		}
	}

	// Check top-level last_config or awg/wireguard
	for _, key := range []string{"last_config", "config"} {
		if rawCfg, ok := rawMap[key].(string); ok && rawCfg != "" {
			if strings.Contains(rawCfg, "[Interface]") {
				return rawCfg, name, nil
			}
		}
	}

	return "", "", errors.New("no amnezia-awg or wireguard configuration found in vpn:// payload")
}

func extractConfigFromContainerMap(protoMap map[string]any, hostName, dns1, dns2 string) (string, error) {
	if protoMap == nil {
		return "", errors.New("nil protoMap")
	}

	// If last_config is present
	if raw, ok := protoMap["last_config"]; ok {
		switch v := raw.(type) {
		case string:
			trimmed := strings.TrimSpace(v)
			if strings.HasPrefix(trimmed, "[") && strings.Contains(trimmed, "[Interface]") {
				return trimmed, nil
			}
			// If last_config is a nested JSON string
			var nested map[string]any
			if err := json.Unmarshal([]byte(trimmed), &nested); err == nil {
				return jsonConfigToWireGuardINI(nested, protoMap, hostName, dns1, dns2)
			}
		case map[string]any:
			return jsonConfigToWireGuardINI(v, protoMap, hostName, dns1, dns2)
		}
	}

	// If protoMap itself has WireGuard keys
	return jsonConfigToWireGuardINI(protoMap, protoMap, hostName, dns1, dns2)
}

func jsonConfigToWireGuardINI(cfg, parent map[string]any, hostName, dns1, dns2 string) (string, error) {
	// Look for direct config string
	if confStr, ok := cfg["config"].(string); ok && strings.Contains(confStr, "[Interface]") {
		return confStr, nil
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")

	privKey := getStringAny(cfg, "client_priv_key", "PrivateKey", "priv_key")
	if privKey != "" {
		sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", privKey))
	}

	clientIP := getStringAny(cfg, "client_ip", "Address", "ip")
	if clientIP != "" {
		if !strings.Contains(clientIP, "/") {
			clientIP += "/32"
		}
		sb.WriteString(fmt.Sprintf("Address = %s\n", clientIP))
	}

	// DNS
	dnsList := make([]string, 0, 2)
	if d := getStringAny(cfg, "dns", "DNS"); d != "" {
		dnsList = append(dnsList, d)
	} else {
		if dns1 != "" {
			dnsList = append(dnsList, dns1)
		}
		if dns2 != "" {
			dnsList = append(dnsList, dns2)
		}
	}
	if len(dnsList) > 0 {
		sb.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(dnsList, ", ")))
	}

	mtu := getStringAny(cfg, "mtu", "MTU")
	if mtu != "" {
		sb.WriteString(fmt.Sprintf("MTU = %s\n", mtu))
	}

	// AmneziaWG obfuscation parameters
	awgKeys := []struct {
		iniKey  string
		aliases []string
	}{
		{"Jc", []string{"Jc", "jc"}},
		{"Jmin", []string{"Jmin", "jmin"}},
		{"Jmax", []string{"Jmax", "jmax"}},
		{"S1", []string{"S1", "s1"}},
		{"S2", []string{"S2", "s2"}},
		{"S3", []string{"S3", "s3"}},
		{"S4", []string{"S4", "s4"}},
		{"H1", []string{"H1", "h1"}},
		{"H2", []string{"H2", "h2"}},
		{"H3", []string{"H3", "h3"}},
		{"H4", []string{"H4", "h4"}},
		{"I1", []string{"I1", "i1"}},
		{"I2", []string{"I2", "i2"}},
		{"I3", []string{"I3", "i3"}},
		{"I4", []string{"I4", "i4"}},
		{"I5", []string{"I5", "i5"}},
		{"HeaderProtectionKey", []string{"HeaderProtectionKey", "header_protection_key", "headerprotectionkey"}},
		{"ContentPaddingAddition", []string{"ContentPaddingAddition", "content_padding_addition", "contentpaddingaddition"}},
		{"RandomTrailers", []string{"RandomTrailers", "random_trailers", "randomtrailers"}},
		{"DisableCookies", []string{"DisableCookies", "disable_cookies", "disablecookies"}},
		{"RekeyAfterTime", []string{"RekeyAfterTime", "rekey_after_time", "rekeyaftertime"}},
		{"RekeyTimeout", []string{"RekeyTimeout", "rekey_timeout", "rekeytimeout"}},
		{"RejectAfterTime", []string{"RejectAfterTime", "reject_after_time", "rejectaftertime"}},
		{"KeepaliveTimeout", []string{"KeepaliveTimeout", "keepalive_timeout", "keepalivetimeout"}},
		{"MaxHandshakeAttempts", []string{"MaxHandshakeAttempts", "max_handshake_attempts", "maxhandshakeattempts"}},
	}
	for _, item := range awgKeys {
		if v := getStringAny(cfg, item.aliases...); v != "" {
			sb.WriteString(fmt.Sprintf("%s = %s\n", item.iniKey, v))
		}
	}

	sb.WriteString("\n[Peer]\n")

	pubKey := getStringAny(cfg, "server_pub_key", "PublicKey", "pub_key")
	if pubKey != "" {
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", pubKey))
	}

	psk := getStringAny(cfg, "psk_key", "PresharedKey", "psk")
	if psk != "" {
		sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", psk))
	}

	// Endpoint calculation
	endpoint := getStringAny(cfg, "endpoint", "Endpoint")
	if endpoint == "" {
		port := getStringAny(cfg, "port", "Port")
		if port == "" && parent != nil {
			port = getStringAny(parent, "port", "Port")
		}
		if port == "" {
			port = "51820"
		}
		host := hostName
		if host == "" {
			host = getStringAny(cfg, "host", "hostName", "server_ip")
		}
		if host != "" {
			endpoint = net.JoinHostPort(host, port)
		}
	}
	if endpoint != "" {
		sb.WriteString(fmt.Sprintf("Endpoint = %s\n", endpoint))
	}

	allowedIPs := getStringAny(cfg, "allowed_ips", "AllowedIPs")
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0, ::/0"
	}
	sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", allowedIPs))

	keepalive := getStringAny(cfg, "persistent_keep_alive", "PersistentKeepalive", "keepalive")
	if keepalive != "" {
		sb.WriteString(fmt.Sprintf("PersistentKeepalive = %s\n", keepalive))
	}

	res := sb.String()
	if !strings.Contains(res, "PrivateKey") || !strings.Contains(res, "PublicKey") {
		return "", errors.New("incomplete WireGuard configuration in Amnezia container")
	}

	return res, nil
}

func getStringAny(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if val, ok := m[k]; ok && val != nil {
			switch v := val.(type) {
			case string:
				if strings.TrimSpace(v) != "" {
					return strings.TrimSpace(v)
				}
			case float64:
				return strconv.Itoa(int(v))
			case int:
				return strconv.Itoa(v)
			case int64:
				return strconv.FormatInt(v, 10)
			case bool:
				if v {
					return "true"
				}
				return "false"
			}
		}
	}
	return ""
}
