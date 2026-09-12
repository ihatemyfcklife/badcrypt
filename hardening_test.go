package crypto

import (
	"bytes"
	"math"
	"testing"
)

// TestHardening_NonceRollover verifies that when the 64-bit counter reaches MaxUint64,
// the system refuses to rollover/wrap to prevent catastrophic two-time pad key compromise.
func TestHardening_NonceRollover(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	aead, err := NewShardAEAD(key)
	if err != nil {
		t.Fatalf("NewShardAEAD failed: %v", err)
	}

	// Fast-forward counter to MaxUint64 - 1
	aead.SetCounterForTesting(math.MaxUint64 - 1)

	plaintext := make([]byte, DefaultPlaintextFrameSize)
	copy(plaintext, []byte("Nonce rollover boundary test"))

	// Packet at MaxUint64 should succeed
	frame := aead.SealFrame(nil, plaintext)
	if len(frame) != ConstantWireFrameSize {
		t.Fatalf("Expected valid frame at MaxUint64, got len=%d", len(frame))
	}

	// Next packet would overflow counter to 0! Must panic with key exhaustion protection.
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Expected panic on 64-bit nonce counter overflow, but operation succeeded without panic!")
		}
		t.Logf("Nonce rollover protection validated successfully: caught expected panic: %v", r)
	}()

	_ = aead.SealFrame(nil, plaintext)
}

// TestHardening_CrossDirectionReplay verifies that a packet sent from Client to Server (c2s)
// CANNOT be decrypted by a receiver expecting Server to Client (s2c) traffic, and vice-versa.
func TestHardening_CrossDirectionReplay(t *testing.T) {
	masterSecret := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(i + 10)
	}

	c2sKey, s2cKey := DeriveDirectionalAEADKeys(masterSecret)

	clientSend, _ := NewShardAEAD(c2sKey)
	serverRecv, _ := NewShardAEAD(c2sKey)

	serverSend, _ := NewShardAEAD(s2cKey)
	clientRecv, _ := NewShardAEAD(s2cKey)

	payload := make([]byte, DefaultPlaintextFrameSize)
	copy(payload, []byte("Confidential Client Message"))

	// 1. Client creates a valid frame intended for Server
	c2sFrame := clientSend.SealFrame(nil, payload)

	// Server properly decrypts it
	decrypted, err := serverRecv.OpenFrame(nil, c2sFrame)
	if err != nil || !bytes.Equal(decrypted, payload) {
		t.Fatalf("Legitimate c2s decryption failed: %v", err)
	}

	// 2. Attacker replays this exact c2s frame back to the Client (pretending it's from Server)
	_, err = clientRecv.OpenFrame(nil, c2sFrame)
	if err != ErrInvalidAEADAuth {
		t.Fatalf("Expected ErrInvalidAEADAuth when replaying c2s packet to clientRecv (s2c key), got %v", err)
	}
	t.Log("[+] Cross-direction replay (c2s replayed into s2c) successfully rejected by AEAD tag")

	// 3. Server creates a frame intended for Client
	s2cFrame := serverSend.SealFrame(nil, payload)

	// Client properly decrypts it
	decryptedServer, err := clientRecv.OpenFrame(nil, s2cFrame)
	if err != nil || !bytes.Equal(decryptedServer, payload) {
		t.Fatalf("Legitimate s2c decryption failed: %v", err)
	}

	// 4. Attacker replays this exact s2c frame back to Server
	_, err = serverRecv.OpenFrame(nil, s2cFrame)
	if err != ErrInvalidAEADAuth {
		t.Fatalf("Expected ErrInvalidAEADAuth when replaying s2c packet to serverRecv (c2s key), got %v", err)
	}
	t.Log("[+] Cross-direction replay (s2c replayed into c2s) successfully rejected by AEAD tag")
}

// TestHardening_CrossSessionReplay verifies that frames cannot be cross-replayed between different sessions.
func TestHardening_CrossSessionReplay(t *testing.T) {
	secretA := make([]byte, 32)
	secretB := make([]byte, 32)
	for i := range secretA {
		secretA[i] = byte(i + 1)
		secretB[i] = byte(i + 2)
	}

	c2sKeyA, _ := DeriveDirectionalAEADKeys(secretA)
	c2sKeyB, _ := DeriveDirectionalAEADKeys(secretB)

	sessionASender, _ := NewShardAEAD(c2sKeyA)
	sessionBReceiver, _ := NewShardAEAD(c2sKeyB)

	payload := make([]byte, DefaultPlaintextFrameSize)
	copy(payload, []byte("Top secret for Session A"))

	frameA := sessionASender.SealFrame(nil, payload)

	// Attempt to inject frameA into Session B's receiver
	_, err := sessionBReceiver.OpenFrame(nil, frameA)
	if err != ErrInvalidAEADAuth {
		t.Fatalf("Expected ErrInvalidAEADAuth when injecting Session A packet into Session B, got %v", err)
	}
	t.Log("[+] Cross-session injection successfully rejected by cryptographic authentication")
}

// TestHardening_ReconnectionForwardSecrecy verifies that successive handshakes produce distinct
// ephemeral keys and cannot decrypt previous session traffic.
func TestHardening_ReconnectionForwardSecrecy(t *testing.T) {
	validTokens := map[string]bool{"client-auth-token": true}

	// Handshake 1
	hello1, priv1, decaps1, nonce1, _ := GenerateClientHello("client-auth-token")
	resp1, secret1, _, err := ProcessClientHello(hello1, validTokens, 0x1111)
	if err != nil {
		t.Fatalf("Handshake 1 ProcessClientHello failed: %v", err)
	}
	_, clientSecret1, _ := ProcessServerHello(resp1, priv1, decaps1, nonce1)

	// Handshake 2 (Reconnection after disconnect)
	hello2, priv2, decaps2, nonce2, _ := GenerateClientHello("client-auth-token")
	resp2, secret2, _, err := ProcessClientHello(hello2, validTokens, 0x2222)
	if err != nil {
		t.Fatalf("Handshake 2 ProcessClientHello failed: %v", err)
	}
	_, clientSecret2, _ := ProcessServerHello(resp2, priv2, decaps2, nonce2)

	// Verify secrets are strictly unique (Forward Secrecy)
	if bytes.Equal(secret1[:], secret2[:]) {
		t.Fatal("Forward secrecy violation: sequential sessions derived identical secrets!")
	}
	if bytes.Equal(clientSecret1[:], clientSecret2[:]) {
		t.Fatal("Client derived identical secrets across reconnections!")
	}

	// Verify session 1 key cannot decrypt session 2 traffic
	c2s1, _ := DeriveDirectionalAEADKeys(secret1[:])
	c2s2, _ := DeriveDirectionalAEADKeys(secret2[:])
	sender1, _ := NewShardAEAD(c2s1)
	recv2, _ := NewShardAEAD(c2s2)

	payload := make([]byte, DefaultPlaintextFrameSize)
	copy(payload, []byte("Session 1 Historical Traffic"))
	frame1 := sender1.SealFrame(nil, payload)

	_, err = recv2.OpenFrame(nil, frame1)
	if err != ErrInvalidAEADAuth {
		t.Fatalf("Session 2 receiver accepted historical frame from Session 1: %v", err)
	}
	t.Log("[+] Reconnection Forward Secrecy verified: historic session frames cannot be opened by new session")
}

// TestHardening_HandshakeTranscriptTampering injects targeted bit flips and corruptions
// into ML-KEM-768 and X25519 handshake messages to ensure prompt and silent rejection.
func TestHardening_HandshakeTranscriptTampering(t *testing.T) {
	validTokens := map[string]bool{"tamper-test-token": true}

	hello, clientPriv, decapsKey, nonce, err := GenerateClientHello("tamper-test-token")
	if err != nil {
		t.Fatalf("GenerateClientHello failed: %v", err)
	}

	// 1. Tamper with ClientHello Magic Header
	t.Run("TamperClientHelloMagic", func(t *testing.T) {
		corruptHello := make([]byte, len(hello))
		copy(corruptHello, hello)
		corruptHello[0] ^= 0xFF // Break magic header

		_, _, _, err := ProcessClientHello(corruptHello, validTokens, 0x9999)
		if err == nil {
			t.Fatal("Expected error on tampered ClientHello magic, got nil")
		}
	})

	// 2. Tamper with ClientHello PQC ML-KEM public key
	t.Run("TamperClientHelloMLKEMKey", func(t *testing.T) {
		corruptHello := make([]byte, len(hello))
		copy(corruptHello, hello)
		// Offset 93 is start of ML-KEM key (1184 bytes)
		corruptHello[100] ^= 0x55

		// In ML-KEM-768, an altered encapsulation key must produce either decapsulation failure
		// or derived secret divergence (implicit rejection)
		resp, serverSecret, _, err := ProcessClientHello(corruptHello, validTokens, 0x9999)
		if err == nil {
			// If encapsulation succeeded with corrupted public key, client decapsulation MUST fail
			// or derive an entirely different secret
			_, clientSecret, decErr := ProcessServerHello(resp, clientPriv, decapsKey, nonce)
			if decErr == nil && bytes.Equal(clientSecret[:], serverSecret[:]) {
				t.Fatal("ML-KEM key tampering was undetected: client and server arrived at same secret!")
			}
		}
	})

	// 3. Tamper with ServerHello Ciphertext Tag
	t.Run("TamperServerHelloTag", func(t *testing.T) {
		helloFresh, privFresh, decapsFresh, nonceFresh, _ := GenerateClientHello("tamper-test-token")
		resp, serverSecret, _, err := ProcessClientHello(helloFresh, validTokens, 0x9999)
		if err != nil {
			t.Fatalf("ProcessClientHello failed: %v", err)
		}

		corruptResp := make([]byte, len(resp))
		copy(corruptResp, resp)
		// Flip bit in last byte (tag / ciphertext)
		corruptResp[len(corruptResp)-1] ^= 0x01

		_, clientSecret, decErr := ProcessServerHello(corruptResp, privFresh, decapsFresh, nonceFresh)
		// Per FIPS 203 / RFC 9180, ML-KEM employs implicit rejection:
		// either Decapsulate errors or derives a divergent pseudo-random secret.
		if decErr == nil && bytes.Equal(clientSecret[:], serverSecret[:]) {
			t.Fatal("ML-KEM ciphertext tampering was undetected: client and server derived identical secrets!")
		}
		t.Log("[+] ServerHello ML-KEM tampering correctly rejected via FIPS 203 implicit rejection (derived secret divergence)")
	})
}
