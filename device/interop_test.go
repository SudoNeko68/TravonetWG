//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func createPingPacket(src, dst netip.Addr) []byte {
	pkt := make([]byte, 36)
	ip := pkt[:20]
	icmp := pkt[20:]

	// ICMP Echo Request
	icmp[0] = 8 // Echo Request
	icmp[1] = 0 // Code
	binary.BigEndian.PutUint16(icmp[4:6], 0x1234) // ID
	binary.BigEndian.PutUint16(icmp[6:8], 1)      // Sequence
	copy(icmp[8:], []byte("TESTPING"))
	icmpSum := ipChecksum(icmp)
	binary.BigEndian.PutUint16(icmp[2:4], icmpSum)

	// IPv4 Header
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(pkt)))
	ip[8] = 64
	ip[9] = 1 // ICMP
	copy(ip[12:16], src.AsSlice())
	copy(ip[16:20], dst.AsSlice())
	ipSum := ipChecksum(ip)
	binary.BigEndian.PutUint16(ip[10:12], ipSum)

	return pkt
}

func TestAmneziaWGServerInteroperability(t *testing.T) {
	serverBin := "/home/travonet/amneziawg-go/amneziawg-go"
	if _, err := os.Stat(serverBin); err != nil {
		t.Skipf("amneziawg-go binary not found at %s: %v", serverBin, err)
	}

	if os.Geteuid() != 0 {
		t.Skip("TestAmneziaWGServerInteroperability requires root (run with sudo go test)")
	}

	iface := "awgtest0"
	sockPath := fmt.Sprintf("/var/run/amneziawg/%s.sock", iface)

	// Clean up any stale state
	_ = exec.Command("sudo", "pkill", "-9", "-f", iface).Run()
	_ = exec.Command("sudo", "rm", "-f", sockPath).Run()
	_ = exec.Command("sudo", "ip", "link", "del", iface).Run()

	var serverKey, clientKey NoisePrivateKey
	if _, err := rand.Read(serverKey[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(clientKey[:]); err != nil {
		t.Fatal(err)
	}
	serverPub, clientPub := serverKey.publicKey(), clientKey.publicKey()

	hpKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	serverPort := 54321

	// Start amneziawg-go server
	cmd := exec.Command("sudo", "env", "LOG_LEVEL=debug", serverBin, "-f", iface)
	var serverOut bytes.Buffer
	cmd.Stdout = &serverOut
	cmd.Stderr = &serverOut
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start amneziawg-go server: %v", err)
	}

	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = exec.Command("sudo", "kill", fmt.Sprintf("%d", cmd.Process.Pid)).Run()
			_ = cmd.Process.Kill()
		}
		_ = exec.Command("sudo", "ip", "link", "del", iface).Run()
		_ = exec.Command("sudo", "rm", "-f", sockPath).Run()
	})

	// Wait for UAPI socket
	var connServer net.Conn
	var connErr error
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, statErr := os.Stat(sockPath); statErr == nil {
			connServer, connErr = net.Dial("unix", sockPath)
			if connErr == nil {
				break
			}
		}
	}
	if connErr != nil {
		t.Fatalf("could not connect to server UAPI socket %s: %v\nOutput: %s", sockPath, connErr, serverOut.String())
	}
	defer connServer.Close()

	// Configure server via UAPI
	serverUAPI := fmt.Sprintf(`set=1
private_key=%s
listen_port=%d
jc=3
jmin=30
jmax=60
s1=24
s2=20
s3=16
s4=16
h1=100000-100010
h2=200000
h3=300000
h4=400000
header_protection_key=%s
content_padding_addition=8-16
random_trailers=true
replace_peers=true
public_key=%s
replace_allowed_ips=true
allowed_ip=10.99.0.2/32

`, hex.EncodeToString(serverKey[:]), serverPort, hpKey, hex.EncodeToString(clientPub[:]))

	if _, err := connServer.Write([]byte(serverUAPI)); err != nil {
		t.Fatalf("failed to write server UAPI: %v", err)
	}

	// Bring up server interface with IP
	if err := exec.Command("sudo", "ip", "addr", "add", "10.99.0.1/24", "dev", iface).Run(); err != nil {
		t.Fatalf("failed to set server IP: %v", err)
	}
	if err := exec.Command("sudo", "ip", "link", "set", iface, "up").Run(); err != nil {
		t.Fatalf("failed to bring server iface up: %v", err)
	}

	// Setup travonetwg Client
	clientTUN := tuntest.NewChannelTUN()
	clientBind := conn.NewDefaultBind()
	clientLogger := NewLogger(LogLevelVerbose, "travonet-client: ")
	clientDev := NewDevice(clientTUN.TUN(), clientBind, clientLogger)
	t.Cleanup(clientDev.Close)

	clientUAPI := fmt.Sprintf(`private_key=%s
listen_port=0
jc=3
jmin=30
jmax=60
s1=24
s2=20
s3=16
s4=16
h1=100000-100010
h2=200000
h3=300000
h4=400000
header_protection_key=%s
content_padding_addition=8-16
random_trailers=true
replace_peers=true
public_key=%s
endpoint=127.0.0.1:%d
replace_allowed_ips=true
allowed_ip=0.0.0.0/0
`, hex.EncodeToString(clientKey[:]), hpKey, hex.EncodeToString(serverPub[:]), serverPort)

	if err := clientDev.IpcSet(clientUAPI); err != nil {
		t.Fatalf("client IpcSet failed: %v", err)
	}
	if err := clientDev.Up(); err != nil {
		t.Fatalf("client Up failed: %v", err)
	}

	// Wait 200ms for sockets to initialize
	time.Sleep(200 * time.Millisecond)

	// Send ICMP ping from client (10.99.0.2) to server (10.99.0.1)
	clientIP := netip.MustParseAddr("10.99.0.2")
	serverIP := netip.MustParseAddr("10.99.0.1")
	ping := createPingPacket(clientIP, serverIP)

	t.Logf("Sending ping to amneziawg-go server...")

	// Send pings periodically until reply is received or timeout
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				clientTUN.Outbound <- ping
				time.Sleep(500 * time.Millisecond)
			}
		}
	}()

	// Expect ICMP echo reply back from server kernel
	select {
	case reply := <-clientTUN.Inbound:
		close(done)
		t.Logf("Received reply from amneziawg-go server! (%d bytes)", len(reply))
		if len(reply) < 20 {
			t.Fatalf("reply too short: %d bytes", len(reply))
		}
		// Check that it's an IPv4 ICMP packet
		if reply[0]>>4 != 4 || reply[9] != 1 {
			t.Fatalf("reply is not IPv4 ICMP: %x", reply[:20])
		}
		// ICMP Echo Reply type is 0
		if reply[20] != 0 {
			t.Fatalf("ICMP type is %d, want 0 (Echo Reply)", reply[20])
		}
		t.Logf("SUCCESS: Full handshake, header protection, content padding, and ICMP Echo Reply confirmed with amneziawg-go server!")
	case <-time.After(10 * time.Second):
		close(done)
		t.Fatalf("timed out waiting for ICMP reply from amneziawg-go server. Server logs:\n%s", serverOut.String())
	}
}
