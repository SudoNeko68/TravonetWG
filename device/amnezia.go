/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 TravonetWG Contributors.
 *
 * AmneziaWG interoperability layer.
 *
 * AmneziaWG obfuscates the vanilla WireGuard wire format in four ways:
 *
 *   - Jc/Jmin/Jmax: random junk datagrams sent before every handshake;
 *   - S1..S4:       random padding prepended to handshake/transport messages;
 *   - H1..H4:       arbitrary 32-bit values (or ranges) used instead of the
 *                   well-known WireGuard message type numbers;
 *   - I1..I5:       optional custom signature packets sent before a handshake.
 *
 * The functions below implement the classic (AWG 1.5/2.0) semantics, which is
 * what AmneziaWG servers expect from a client.  The layer is per-device, so a
 * single process can run both a vanilla WireGuard peer and an AmneziaWG peer.
 */

package device

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20"
)

const (
	HeaderCipherKeySize   = 32
	HeaderCipherNonceSize = 12
)

type HeaderCipherKey [HeaderCipherKeySize]byte

func (key HeaderCipherKey) IsZero() bool {
	var zero HeaderCipherKey
	return key.Equals(zero)
}

func (key HeaderCipherKey) Equals(tar HeaderCipherKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *HeaderCipherKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key *HeaderCipherKey) FromString(src string) error {
	src = strings.TrimSpace(src)
	if len(src) == 64 {
		return key.FromHex(src)
	}
	b, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return err
	}
	if len(b) != HeaderCipherKeySize {
		return errors.New("header protection key must be 32 bytes")
	}
	copy(key[:], b)
	return nil
}

func (key HeaderCipherKey) Hex() string {
	return hex.EncodeToString(key[:])
}

func (key HeaderCipherKey) Base64() string {
	return base64.StdEncoding.EncodeToString(key[:])
}

// UintRange is an inclusive range of uint32 values, packed as hi<<32|lo.
// It mirrors the range syntax accepted by AmneziaWG ("123" or "123-456").
type UintRange uint64

func (r UintRange) Lo() uint32 {
	return uint32(r)
}

func (r UintRange) Hi() uint32 {
	return uint32(r >> 32)
}

func (r UintRange) Overlap(tar UintRange) bool {
	if r.IsZero() || tar.IsZero() {
		return false
	}
	lo1, hi1 := r.Lo(), r.Hi()
	lo2, hi2 := tar.Lo(), tar.Hi()
	return max(lo1, lo2) <= min(hi1, hi2)
}

func (r *UintRange) FromUint32(lo, hi uint32) {
	*r = UintRange(uint64(hi)<<32 | uint64(lo))
}

func (r *UintRange) FromString(str string) error {
	parts := strings.Split(str, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return errors.New("wrong format")
	}

	lo, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil {
		return err
	}

	hi := lo
	if len(parts) > 1 {
		hi, err = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil {
			return err
		}
	}

	if hi < lo {
		return errors.New("wrong range specified")
	}

	r.FromUint32(uint32(lo), uint32(hi))
	return nil
}

func (r UintRange) Contains(num uint32) bool {
	lo, hi := uint32(r), uint32(r>>32)
	return lo <= num && num <= hi
}

func (r UintRange) IsZero() bool {
	return r == 0
}

// PickOne returns a random value from the range.  AmneziaWG uses this to make
// message headers less predictable when a range is configured.
func (r UintRange) PickOne() uint32 {
	lo, hi := uint32(r), uint32(r>>32)
	if hi <= lo {
		return lo
	}
	return lo + mrand.Uint32N(hi-lo+1)
}

func (r UintRange) String() string {
	lo, hi := uint32(r), uint32(r>>32)
	if lo == hi {
		return strconv.FormatUint(uint64(lo), 10)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

// AtomicUintRange is an atomically accessible UintRange.
type AtomicUintRange struct {
	value atomic.Uint64
}

func (r *AtomicUintRange) Store(v UintRange) {
	r.value.Store(uint64(v))
}

func (r *AtomicUintRange) Load() UintRange {
	return UintRange(r.value.Load())
}

func (r *AtomicUintRange) Contains(num uint32) bool {
	return r.Load().Contains(num)
}

func (r *AtomicUintRange) PickOne() uint32 {
	return r.Load().PickOne()
}

type signaturePartKind byte

const (
	signatureBytes     signaturePartKind = 'b'
	signatureRandom    signaturePartKind = 'r'
	signatureChars     signaturePartKind = 'c'
	signatureDigits    signaturePartKind = 'd'
	signatureTimestamp signaturePartKind = 't'
)

const (
	signatureChars52  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	signatureDigits10 = "0123456789"
)

type signaturePart struct {
	kind signaturePartKind
	data []byte
	n    int
}

// signaturePacket is a template for one of the I1..I5 signature packets.
// Templates are expanded on every handshake because they may contain random
// data and timestamps.
type signaturePacket struct {
	spec  string
	parts []signaturePart
	size  int
}

func newSignaturePacket(spec string) (*signaturePacket, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	packet := &signaturePacket{spec: spec}
	remaining := spec
	for {
		start := strings.IndexByte(remaining, '<')
		if start == -1 {
			break
		}
		end := strings.IndexByte(remaining[start:], '>')
		if end == -1 {
			return nil, errors.New("missing enclosing >")
		}
		end += start

		tag := remaining[start+1 : end]
		fields := strings.Fields(tag)
		remaining = remaining[end+1:]

		if len(fields) == 0 {
			return nil, errors.New("empty tag")
		}

		key := fields[0]
		arg := ""
		if len(fields) > 1 {
			arg = fields[1]
		}

		switch key {
		case "b":
			raw := strings.TrimPrefix(arg, "0x")
			if raw == "" {
				return nil, errors.New("empty <b> argument")
			}
			if len(raw)%2 != 0 {
				return nil, errors.New("odd amount of symbols in <b> argument")
			}
			data, err := hex.DecodeString(raw)
			if err != nil {
				return nil, err
			}
			packet.parts = append(packet.parts, signaturePart{kind: signatureBytes, data: data})
			packet.size += len(data)

		case "r", "rc", "rd":
			n, err := strconv.Atoi(arg)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid <%s> length %q", key, arg)
			}
			kind := signatureRandom
			switch key {
			case "rc":
				kind = signatureChars
			case "rd":
				kind = signatureDigits
			}
			packet.parts = append(packet.parts, signaturePart{kind: kind, n: n})
			packet.size += n

		case "t":
			packet.parts = append(packet.parts, signaturePart{kind: signatureTimestamp})
			packet.size += 4

		case "d", "ds":
			// These tags encode the packet payload. Signature packets carry no
			// payload, so they expand to nothing (matching AmneziaWG).
			continue

		case "dz":
			n, err := strconv.Atoi(arg)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid <dz> length %q", arg)
			}
			packet.parts = append(packet.parts, signaturePart{kind: signatureBytes, data: make([]byte, n)})
			packet.size += n

		default:
			return nil, fmt.Errorf("unknown tag <%s>", key)
		}
	}

	if len(packet.parts) == 0 {
		return nil, nil
	}
	return packet, nil
}

// Build renders a fresh packet from the template.
func (p *signaturePacket) Build() []byte {
	if p == nil {
		return nil
	}

	out := make([]byte, p.size)
	off := 0
	for _, part := range p.parts {
		switch part.kind {
		case signatureBytes:
			copy(out[off:], part.data)
			off += len(part.data)
		case signatureRandom:
			rand.Read(out[off : off+part.n])
			off += part.n
		case signatureChars:
			rand.Read(out[off : off+part.n])
			for i := off; i < off+part.n; i++ {
				out[i] = signatureChars52[int(out[i])%len(signatureChars52)]
			}
			off += part.n
		case signatureDigits:
			rand.Read(out[off : off+part.n])
			for i := off; i < off+part.n; i++ {
				out[i] = signatureDigits10[int(out[i])%len(signatureDigits10)]
			}
			off += part.n
		case signatureTimestamp:
			binary.BigEndian.PutUint32(out[off:], uint32(time.Now().Unix()))
			off += 4
		}
	}
	return out
}

// initAmnezia installs the vanilla WireGuard message types.  Keeping the
// defaults in the device (rather than in the packet hot path) means the code
// behaves exactly like WireGuard when no AmneziaWG options are configured.
func (device *Device) initAmnezia() {
	var r UintRange
	r.FromUint32(MessageInitiationType, MessageInitiationType)
	device.amnezia.headers.init.Store(r)
	r.FromUint32(MessageResponseType, MessageResponseType)
	device.amnezia.headers.response.Store(r)
	r.FromUint32(MessageCookieReplyType, MessageCookieReplyType)
	device.amnezia.headers.cookie.Store(r)
	r.FromUint32(MessageTransportType, MessageTransportType)
	device.amnezia.headers.transport.Store(r)
}

// junkPacketCount returns the configured Jc value.
func (device *Device) junkPacketCount() int {
	return int(device.amnezia.junk.count.Load())
}

// randomJunkSize returns a size in [Jmin, Jmax].  If the configured values
// are inconsistent we degrade to Jmin (or zero).
func (device *Device) randomJunkSize() int {
	min := int(device.amnezia.junk.min.Load())
	max := int(device.amnezia.junk.max.Load())
	if max < min {
		max = min
	}
	if max <= min {
		return min
	}
	return min + mrand.IntN(max-min+1)
}

// handshakePrelude returns the packets that AmneziaWG sends immediately before
// a handshake: the custom signature packets (I1..I5) followed by Jc junk
// datagrams of random length.  The server simply discards all of them.
func (device *Device) handshakePrelude() [][]byte {
	var packets [][]byte

	for i := range device.amnezia.signatures {
		if packet := device.amnezia.signatures[i].Load(); packet != nil {
			packets = append(packets, packet.Build())
		}
	}

	for i := 0; i < device.junkPacketCount(); i++ {
		junk := make([]byte, device.randomJunkSize())
		rand.Read(junk)
		packets = append(packets, junk)
	}

	return packets
}

// addMessagePadding prepends Sx random bytes to a marshalled message.
func addMessagePadding(packet []byte, padding int) []byte {
	if padding <= 0 {
		return packet
	}
	padded := make([]byte, padding+len(packet))
	rand.Read(padded[:padding])
	copy(padded[padding:], packet)
	return padded
}

func (device *Device) HeaderProtectionCipher(salt []byte) (*chacha20.Cipher, error) {
	device.amnezia.headerProtection.RLock()
	defer device.amnezia.headerProtection.RUnlock()

	if device.amnezia.headerProtection.key.IsZero() {
		return nil, nil
	}
	if len(salt) < HeaderCipherNonceSize {
		return nil, errors.New("salt too short for header protection cipher")
	}

	return chacha20.NewUnauthenticatedCipher(device.amnezia.headerProtection.key[:], salt[:HeaderCipherNonceSize])
}

func applyHash(dst, src, hash []byte) {
	for i := range dst {
		dst[i] = src[i] ^ hash[i]
	}
}

func (device *Device) randomTrailer(packetSize int) int {
	if !device.amnezia.randomTrailers.Load() {
		return -1
	}
	if DefaultUdpWindow < packetSize {
		return 0
	}
	return int(mrand.Uint32N(uint32(DefaultUdpWindow - packetSize + 1)))
}

func (peer *Peer) randomTrailer(packetSize int) int {
	if !peer.device.amnezia.randomTrailers.Load() {
		return -1
	}
	udpWindow := int(peer.udpWindow.Load())
	if udpWindow < packetSize {
		return 0
	}
	return int(mrand.Uint32N(uint32(udpWindow - packetSize + 1)))
}

func (peer *Peer) randomPaddingAddition(packetSize int) int {
	addition := peer.device.amnezia.contentPaddingAddition.Load()
	if addition.IsZero() {
		return -1
	}
	udpWindow := int(peer.udpWindow.Load())
	if udpWindow < packetSize {
		return 0
	}
	add := int(addition.PickOne())
	space := udpWindow - packetSize
	if add > space {
		add = space
	}
	return add
}

func (peer *Peer) retransmitHandshakeTimeout() time.Duration {
	timeout := RekeyTimeout
	if t := peer.device.amnezia.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		timeout = time.Duration(t.PickOne()) * time.Second
	}
	return timeout
}

func (peer *Peer) sendKeepaliveTimeout() time.Duration {
	timeout := KeepaliveTimeout
	if t := peer.device.amnezia.timings.keepaliveTimeoutSec.Load(); !t.IsZero() {
		timeout = time.Duration(t.PickOne()) * time.Second
	}
	return timeout
}

func (peer *Peer) newHandshakeTimeout() time.Duration {
	keepaliveTimeout := KeepaliveTimeout
	rekeyTimeout := RekeyTimeout
	if t := peer.device.amnezia.timings.keepaliveTimeoutSec.Load(); !t.IsZero() {
		keepaliveTimeout = time.Duration(t.Hi()) * time.Second
	}
	if t := peer.device.amnezia.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		rekeyTimeout = time.Duration(t.PickOne()) * time.Second
	}
	return keepaliveTimeout + rekeyTimeout
}

func (device *Device) keyRefreshTimeoutSending() time.Duration {
	rekeyAfterTime := RekeyAfterTime
	if t := device.amnezia.timings.rekeyAfterTimeSec.Load(); !t.IsZero() {
		rekeyAfterTime = time.Duration(t.PickOne()) * time.Second
	}
	return rekeyAfterTime
}

func (device *Device) keyRefreshTimeoutReceiving() time.Duration {
	rejectAfterTime := RejectAfterTime
	keepaliveTimeout := KeepaliveTimeout
	rekeyTimeout := RekeyTimeout
	if t := device.amnezia.timings.rejectAfterTimeSec.Load(); !t.IsZero() {
		rejectAfterTime = time.Duration(t.PickOne()) * time.Second
	}
	if t := device.amnezia.timings.keepaliveTimeoutSec.Load(); !t.IsZero() {
		keepaliveTimeout = time.Duration(t.Lo()) * time.Second
	}
	if t := device.amnezia.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		rekeyTimeout = time.Duration(t.Lo()) * time.Second
	}
	return max(0, rejectAfterTime-keepaliveTimeout-rekeyTimeout)
}

func (device *Device) keychainExpireTime() time.Duration {
	rejectAfterTime := RejectAfterTime
	if t := device.amnezia.timings.rejectAfterTimeSec.Load(); !t.IsZero() {
		rejectAfterTime = time.Duration(t.Hi()) * time.Second
	}
	return rejectAfterTime
}

func (device *Device) rekeyMinTimeout() time.Duration {
	rekeyTimeout := RekeyTimeout
	if t := device.amnezia.timings.rekeyTimeoutSec.Load(); !t.IsZero() {
		rekeyTimeout = time.Duration(t.Lo()) * time.Second
	}
	return rekeyTimeout
}

func (device *Device) maxHandshakeAttempts() uint32 {
	res := uint32(MaxTimerHandshakes)
	if t := device.amnezia.timings.maxHandshakeAttemps.Load(); !t.IsZero() {
		res = t.PickOne()
	}
	return res
}

// determinePacketTypeAndPadding classifies an incoming datagram using the
// configured S1..S4 paddings and H1..H4 headers.  Without AmneziaWG options
// this is equivalent to reading the first uint32 of the packet.
func (device *Device) determinePacketTypeAndPadding(packet []byte, typeHash []byte) (payload []byte, msgType uint32, padding int, ok bool) {
	var headerBytes [4]byte
	size := len(packet)
	randomTrailers := device.amnezia.randomTrailers.Load()

	initPadding := int(device.amnezia.paddings.init.Load())
	expectedInit := initPadding + MessageInitiationSize
	if size == expectedInit || (size > expectedInit && randomTrailers) {
		applyHash(headerBytes[:], packet[initPadding:initPadding+4], typeHash)
		if device.amnezia.headers.init.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return packet[initPadding:], MessageInitiationType, initPadding, true
		}
	}

	responsePadding := int(device.amnezia.paddings.response.Load())
	expectedResp := responsePadding + MessageResponseSize
	if size >= expectedResp {
		applyHash(headerBytes[:], packet[responsePadding:responsePadding+4], typeHash)
		if device.amnezia.headers.response.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return packet[responsePadding:], MessageResponseType, responsePadding, true
		}
	}

	cookiePadding := int(device.amnezia.paddings.cookie.Load())
	expectedCookie := cookiePadding + MessageCookieReplySize
	if size >= expectedCookie {
		applyHash(headerBytes[:], packet[cookiePadding:cookiePadding+4], typeHash)
		if device.amnezia.headers.cookie.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return packet[cookiePadding:], MessageCookieReplyType, cookiePadding, true
		}
	}

	transportPadding := int(device.amnezia.paddings.transport.Load())
	expectedTransport := transportPadding + MessageTransportSize
	if size >= expectedTransport {
		applyHash(headerBytes[:], packet[transportPadding:transportPadding+4], typeHash)
		if device.amnezia.headers.transport.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return packet[transportPadding:], MessageTransportType, transportPadding, true
		}
	}

	return nil, 0, 0, false
}
