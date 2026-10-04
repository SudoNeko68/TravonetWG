package device

import (
	"testing"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func TestPersistentKeepaliveTimerResilience(t *testing.T) {
	// Create dummy device with mock tun and mock bind
	tunDev := tuntest.NewChannelTUN()
	binds := bindtest.NewChannelBinds()
	logger := NewLogger(LogLevelError, "test: ")

	dev := NewDevice(tunDev.TUN(), binds[0], logger)
	defer dev.Close()

	var dummyKey NoisePrivateKey
	dev.SetPrivateKey(dummyKey)

	var peerKey NoisePublicKey
	peerKey[0] = 42

	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("Failed to create peer: %v", err)
	}

	// Set keepalive to 1 second
	peer.persistentKeepaliveInterval.Store(1)

	// Verify that starting timers arms the persistent keepalive timer
	peer.timersStart()

	if !peer.timers.persistentKeepalive.IsPending() {
		t.Fatalf("expected persistentKeepalive timer to be pending after timersStart()")
	}

	// Trigger expiredPersistentKeepalive directly
	// It should call peer.SendKeepalive() and re-arm the timer so it doesn't die!
	expiredPersistentKeepalive(peer)

	if !peer.timers.persistentKeepalive.IsPending() {
		t.Fatalf("expected persistentKeepalive timer to remain pending (re-armed) after expiredPersistentKeepalive()")
	}

	// Stop timers
	peer.timersStop()
	if peer.timers.persistentKeepalive.IsPending() {
		t.Fatalf("expected persistentKeepalive timer to NOT be pending after timersStop()")
	}
}

func TestPersistentKeepaliveUAPIUpdate(t *testing.T) {
	tunDev := tuntest.NewChannelTUN()
	binds := bindtest.NewChannelBinds()
	logger := NewLogger(LogLevelError, "test: ")

	dev := NewDevice(tunDev.TUN(), binds[0], logger)
	defer dev.Close()

	var dummyKey NoisePrivateKey
	dev.SetPrivateKey(dummyKey)

	var peerKey NoisePublicKey
	peerKey[0] = 99

	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatalf("Failed to create peer: %v", err)
	}

	dev.Up()
	defer dev.Down()

	// Initial keepalive is 0
	if peer.persistentKeepaliveInterval.Load() != 0 {
		t.Fatalf("initial interval should be 0")
	}

	// Simulate UAPI setting persistent_keepalive_interval = 2
	ipcPeer := &ipcSetPeer{
		Peer: peer,
	}

	if err := dev.handlePeerLine(ipcPeer, "persistent_keepalive_interval", "2"); err != nil {
		t.Fatalf("handlePeerLine error: %v", err)
	}

	if peer.persistentKeepaliveInterval.Load() != 2 {
		t.Fatalf("expected interval 2, got %d", peer.persistentKeepaliveInterval.Load())
	}

	// Verify timer is active/pending
	if !peer.timers.persistentKeepalive.IsPending() {
		t.Fatalf("expected persistentKeepalive timer to be pending after UAPI configuration")
	}
}
