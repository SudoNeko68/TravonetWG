/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

// Command warp-relay performs Cloudflare WARP registration on behalf of the
// Android client. It is meant to be deployed on a host where
// api.cloudflareclient.com is not filtered by SNI, for networks where no
// direct transport works.
//
// The relay never sees the device private key: the client sends only its
// public key, and the private key stays on the phone.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/warp"
)

const maxBodyBytes = 4 * 1024

type server struct {
	token    string
	inFlight chan struct{}
	rateMu   sync.Mutex
	lastSeen map[string]time.Time
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "address to listen on")
	path := flag.String("path", "/register", "HTTP path for registration")
	flag.Parse()

	token := strings.TrimSpace(os.Getenv("RELAY_TOKEN"))
	if token == "" {
		log.Printf("WARNING: RELAY_TOKEN is empty, the relay is open to anyone")
	}

	srv := &server{
		token:    token,
		inFlight: make(chan struct{}, 16),
		lastSeen: make(map[string]time.Time),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(*path, srv.handleRegister)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      40 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("WARP relay listening on %s%s", *listen, *path)
	log.Fatal(httpServer.ListenAndServe())
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.token != "" {
		provided := r.Header.Get("X-Relay-Token")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid relay token")
			return
		}
	}

	remote := clientIP(r)
	if !s.allow(remote) {
		writeError(w, http.StatusTooManyRequests, "too many requests")
		return
	}

	select {
	case s.inFlight <- struct{}{}:
		defer func() { <-s.inFlight }()
	default:
		writeError(w, http.StatusServiceUnavailable, "relay is busy")
		return
	}

	var request warp.RelayRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	publicKey := strings.TrimSpace(request.PublicKey)
	if err := validatePublicKey(publicKey); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	body, err := warp.Register(ctx, publicKey, request.Locale, request.Model)
	if err != nil {
		log.Printf("registration failed for %s: %v", remote, err)
		writeError(w, http.StatusBadGateway, "Cloudflare registration failed")
		return
	}

	log.Printf("registration ok for %s", remote)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// allow limits each address to one request per three seconds. This is not a
// security boundary, just a guard against a script turning the relay into a
// registration farm.
func (s *server) allow(remote string) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	now := time.Now()
	if previous, ok := s.lastSeen[remote]; ok && now.Sub(previous) < 3*time.Second {
		return false
	}
	s.lastSeen[remote] = now

	if len(s.lastSeen) > 4096 {
		for key, seen := range s.lastSeen {
			if now.Sub(seen) > 10*time.Minute {
				delete(s.lastSeen, key)
			}
		}
	}
	return true
}

func validatePublicKey(value string) error {
	if value == "" {
		return errors.New("public_key is required")
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return errors.New("public_key is not valid base64")
	}
	if len(decoded) != 32 {
		return errors.New("public_key must be 32 bytes")
	}
	return nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	// Behind a reverse proxy (Caddy/nginx) every request arrives from a
	// loopback address. Trust X-Forwarded-For only in that case so that the
	// rate limiter sees real clients; a direct remote cannot spoof it.
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			first, _, _ := strings.Cut(forwarded, ",")
			if candidate := strings.TrimSpace(first); net.ParseIP(candidate) != nil {
				return candidate
			}
		}
	}
	return host
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: message})
}
