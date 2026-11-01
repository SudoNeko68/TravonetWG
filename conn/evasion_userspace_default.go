//go:build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"errors"
)

var errCmsgNotSupported = errors.New("per-packet cmsg send not supported on this platform")

func sendUDPWithTTL(fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int) error {
	return errCmsgNotSupported
}

func sendUDPWithTTLAndOptions(fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int, ipOptions []byte) error {
	return errCmsgNotSupported
}

func sendUDPWithControl(fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int, ipOptions []byte, pmtuDisc int) error {
	return errCmsgNotSupported
}

func sendUDPJumbo(fd int, dstIP [4]byte, dstPort int, payload []byte, ttl int) error {
	return errCmsgNotSupported
}

func sendUDP6WithControl(fd int, dstIP [16]byte, dstPort int, payload []byte, hopLimit int) error {
	return errCmsgNotSupported
}
