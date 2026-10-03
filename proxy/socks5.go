/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	socksVersion5 = 0x05

	authNone = 0x00

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess                 = 0x00
	repGeneralFailure          = 0x01
	repConnectionNotAllowed    = 0x02
	repNetworkUnreachable      = 0x03
	repHostUnreachable         = 0x04
	repConnectionRefused       = 0x05
	repTTLExpired              = 0x06
	repCommandNotSupported     = 0x07
	repAddressTypeNotSupported = 0x08
)

// DialContextFunc matches net.Dialer.DialContext
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// SOCKS5Server is an in-process RFC 1928 SOCKS5 proxy server
type SOCKS5Server struct {
	addr     string
	dialCtx  DialContextFunc
	listener net.Listener
	mu       sync.Mutex
	closed   bool
	wg       sync.WaitGroup
	Debug    bool
	conns    map[net.Conn]struct{}
}

// NewSOCKS5Server creates a new SOCKS5 proxy server
func NewSOCKS5Server(addr string, dialCtx DialContextFunc) *SOCKS5Server {
	return &SOCKS5Server{
		addr:    addr,
		dialCtx: dialCtx,
		conns:   make(map[net.Conn]struct{}),
	}
}

// ListenAndServe starts accepting incoming SOCKS5 connections
func (s *SOCKS5Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.addr, err)
	}

	s.mu.Lock()
	if s.closed {
		l.Close()
		s.mu.Unlock()
		return errors.New("server is closed")
	}
	s.listener = l
	s.mu.Unlock()

	for {
		conn, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return nil
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()

		s.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
				s.wg.Done()
			}()
			s.handleConnection(c)
		}(conn)
	}
}

// Close gracefully stops the SOCKS5 server
func (s *SOCKS5Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = make(map[net.Conn]struct{})
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
	}

	return err
}

// Addr returns the bound address of the server
func (s *SOCKS5Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *SOCKS5Server) handleConnection(client net.Conn) {
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	// 1. Negotiation Phase
	// Client sends: VER | NMETHODS | METHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return
	}

	if header[0] != socksVersion5 {
		return
	}

	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	// We only require NO AUTH (0x00)
	hasNoAuth := false
	for _, m := range methods {
		if m == authNone {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		// 0xFF = No acceptable methods
		_, _ = client.Write([]byte{socksVersion5, 0xFF})
		return
	}

	// Server reply: VER (5) | METHOD (0: NO AUTH)
	if _, err := client.Write([]byte{socksVersion5, authNone}); err != nil {
		return
	}

	// 2. Request Phase
	// Client sends: VER (1) | CMD (1) | RSV (1) | ATYP (1) | DST.ADDR | DST.PORT (2)
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}

	if req[0] != socksVersion5 {
		return
	}

	cmd := req[1]
	atyp := req[3]

	if cmd != cmdConnect {
		// Only CONNECT is currently supported for TCP proxying
		sendReply(client, repCommandNotSupported, nil, 0)
		return
	}

	var targetHost string
	switch atyp {
	case atypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		targetHost = net.IP(ip).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, lenBuf); err != nil {
			return
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(client, domainBuf); err != nil {
			return
		}
		targetHost = string(domainBuf)

	case atypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		targetHost = net.IP(ip).String()

	default:
		sendReply(client, repAddressTypeNotSupported, nil, 0)
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	// 3. Dial through userspace network stack
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	remote, err := s.dialCtx(ctx, "tcp", targetAddr)
	if err != nil {
		sendReply(client, repConnectionRefused, nil, 0)
		return
	}
	defer remote.Close()

	// 4. Send Success Response
	if err := sendReply(client, repSuccess, net.ParseIP("0.0.0.0"), 0); err != nil {
		return
	}

	// Clear deadlines for data transfer
	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})

	// 5. Bidirectional copy (pipe)
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(remote, client)
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(done)
	}()

	_, _ = io.Copy(client, remote)
	if cw, ok := client.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}

	<-done
}

func sendReply(w io.Writer, rep byte, bindIP net.IP, bindPort uint16) error {
	reply := []byte{socksVersion5, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if len(bindIP) == 4 {
		copy(reply[4:8], bindIP)
	}
	binary.BigEndian.PutUint16(reply[8:10], bindPort)
	_, err := w.Write(reply)
	return err
}
