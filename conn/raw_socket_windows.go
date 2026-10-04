//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package conn

import (
	"errors"
)

func initRawSocket() (int, error) {
	return -1, errors.New("raw socket injection is not supported on Windows without WinDivert; using userspace UDP desync")
}

func closeRawSocket(rawFd int) error {
	return nil
}

func sendRawPacket(rawFd int, dstIP []byte, packet []byte) error {
	return errors.New("raw socket sending is not supported on Windows without WinDivert")
}
