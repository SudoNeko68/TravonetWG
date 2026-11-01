//go:build android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"time"

	"golang.zx2c4.com/wireguard/warp"
)

// wgGenerateKeypair returns a JSON object with a fresh WireGuard key pair.
//
//export wgGenerateKeypair
func wgGenerateKeypair() *C.char {
	keypair, err := warp.GenerateKeypair()
	if err != nil {
		return C.CString("ERROR: " + err.Error())
	}
	encoded, err := json.Marshal(keypair)
	if err != nil {
		return C.CString("ERROR: " + err.Error())
	}
	return C.CString(string(encoded))
}

// wgRegisterWarp registers an anonymous WARP device and returns the raw
// Cloudflare JSON response. relayURL and relayToken may be empty, in which
// case only direct transports are used.
//
//export wgRegisterWarp
func wgRegisterWarp(publicKey, locale, model, relayURL, relayToken *C.char) *C.char {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	body, err := warp.RegisterWithFallback(
		ctx,
		C.GoString(publicKey),
		C.GoString(locale),
		C.GoString(model),
		C.GoString(relayURL),
		C.GoString(relayToken),
	)
	if err != nil {
		return C.CString("ERROR: " + err.Error())
	}
	return C.CString(string(body))
}
