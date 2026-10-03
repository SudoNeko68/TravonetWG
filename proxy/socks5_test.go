/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKS5Server(t *testing.T) {
	// 1. Setup local echo target
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen echo: %v", err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Setup SOCKS5 server pointing to net.Dialer
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	srv := NewSOCKS5Server("127.0.0.1:0", dialer.DialContext)

	go func() {
		_ = srv.ListenAndServe()
	}()
	defer srv.Close()

	// Wait for server to bind
	var srvAddr net.Addr
	for i := 0; i < 20; i++ {
		srvAddr = srv.Addr()
		if srvAddr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srvAddr == nil {
		t.Fatalf("server failed to bind")
	}

	// 3. Connect to SOCKS5 server as a client
	conn, err := net.Dial("tcp", srvAddr.String())
	if err != nil {
		t.Fatalf("failed to dial SOCKS5 server: %v", err)
	}
	defer conn.Close()

	// Handshake: VER 5, 1 method, NO AUTH (0x00)
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	handshakeResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, handshakeResp); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if handshakeResp[0] != 0x05 || handshakeResp[1] != 0x00 {
		t.Fatalf("unexpected handshake response: %v", handshakeResp)
	}

	// Request: CONNECT to echoListener
	host, portStr, _ := net.SplitHostPort(echoListener.Addr().String())
	ip := net.ParseIP(host).To4()
	port := uint16(echoListener.Addr().(*net.TCPAddr).Port)
	_ = portStr

	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port&0xFF))

	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp[1] != repSuccess {
		t.Fatalf("expected success, got reply code: 0x%02x", resp[1])
	}

	// Send message through SOCKS5 tunnel
	msg := []byte("Hello, TravonetWG Userspace SOCKS5!")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write msg: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	if string(buf) != string(msg) {
		t.Errorf("echo mismatch: got %q, want %q", string(buf), string(msg))
	}
}
