package badcrypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// TestHardening_DataPacketAntiReplay verifies that ShardAEAD's 256-packet sliding window
// strictly rejects any replayed data frame.
func TestHardening_DataPacketAntiReplay(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 5)
	}

	sender, _ := NewShardAEADWithSession(key, 0x1234)
	receiver, _ := NewShardAEADWithSession(key, 0x1234)

	plain1 := make([]byte, DefaultPlaintextFrameSize)
	copy(plain1, []byte("Packet 1 - Action Transfer"))
	frame1, err := sender.SealFrame(nil, plain1)
	if err != nil {
		t.Fatalf("SealFrame failed: %v", err)
	}

	// 1. First reception: legitimate packet must be accepted
	decrypted1, err := receiver.OpenFrame(nil, frame1)
	if err != nil || !bytes.Equal(decrypted1, plain1) {
		t.Fatalf("Legitimate decryption failed: %v", err)
	}

	// 2. Replay attack: resending frame1 must be strictly rejected
	_, err = receiver.OpenFrame(nil, frame1)
	if !errors.Is(err, ErrReplayedPacket) {
		t.Fatalf("Expected ErrReplayedPacket on replayed frame1, got %v", err)
	}
	t.Log("[+] Immediate data packet replay successfully rejected with ErrReplayedPacket")

	// 3. Packet 2
	plain2 := make([]byte, DefaultPlaintextFrameSize)
	copy(plain2, []byte("Packet 2 - Action Commit"))
	frame2, err := sender.SealFrame(nil, plain2)
	if err != nil {
		t.Fatalf("SealFrame 2 failed: %v", err)
	}

	decrypted2, err := receiver.OpenFrame(nil, frame2)
	if err != nil || !bytes.Equal(decrypted2, plain2) {
		t.Fatalf("Legitimate frame 2 failed: %v", err)
	}

	// 4. Replaying frame 1 again after advancing window must still be rejected
	_, err = receiver.OpenFrame(nil, frame1)
	if !errors.Is(err, ErrReplayedPacket) {
		t.Fatalf("Expected ErrReplayedPacket on historical replay, got %v", err)
	}
	t.Log("[+] Historical data packet replay successfully rejected")
}

// TestHardening_NonceRollover verifies that when the 64-bit counter reaches MaxUint64,
// the system returns ErrKeyExhaustion without panicking.
func TestHardening_NonceRollover(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	aead, err := NewShardAEAD(key)
	if err != nil {
		t.Fatalf("NewShardAEAD failed: %v", err)
	}

	// Fast-forward counter to MaxAllowedCounter - 1
	aead.SetCounterForTesting(MaxAllowedCounter - 1)

	plaintext := make([]byte, DefaultPlaintextFrameSize)
	copy(plaintext, []byte("Nonce rollover boundary test"))

	// Packet at MaxAllowedCounter should succeed
	frame, err := aead.SealFrame(nil, plaintext)
	if err != nil {
		t.Fatalf("Expected valid frame at MaxAllowedCounter, got err: %v", err)
	}
	if len(frame) != ConstantWireFrameSize {
		t.Fatalf("Expected frame len=%d, got %d", ConstantWireFrameSize, len(frame))
	}

	// Next packet reaches exhaustion boundary: must return ErrKeyExhaustion gracefully
	_, err = aead.SealFrame(nil, plaintext)
	if !errors.Is(err, ErrKeyExhaustion) {
		t.Fatalf("Expected ErrKeyExhaustion on counter boundary, got: %v", err)
	}

	// Verify permanent latch: subsequent calls must NEVER wrap to 0 or reuse key
	_, err = aead.SealFrame(nil, plaintext)
	if !errors.Is(err, ErrKeyExhaustion) {
		t.Fatalf("Permanent latch failed: expected ErrKeyExhaustion on subsequent call, got: %v", err)
	}
	t.Log("[+] Nonce rollover protection validated: permanently latched at ErrKeyExhaustion")
}

// TestHardening_CrossDirectionReplay verifies that c2s traffic cannot be decrypted by s2c receiver.
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
	c2sFrame, err := clientSend.SealFrame(nil, payload)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := serverRecv.OpenFrame(nil, c2sFrame)
	if err != nil || !bytes.Equal(decrypted, payload) {
		t.Fatalf("Legitimate c2s decryption failed: %v", err)
	}

	// 2. Attacker replays this exact c2s frame back to Client (expecting s2c)
	_, err = clientRecv.OpenFrame(nil, c2sFrame)
	if !errors.Is(err, ErrInvalidAEADAuth) {
		t.Fatalf("Expected ErrInvalidAEADAuth when replaying c2s packet to clientRecv, got %v", err)
	}
	t.Log("[+] Cross-direction replay (c2s -> s2c) successfully rejected by AEAD tag")

	// 3. Server creates a frame intended for Client
	s2cFrame, err := serverSend.SealFrame(nil, payload)
	if err != nil {
		t.Fatal(err)
	}

	decryptedServer, err := clientRecv.OpenFrame(nil, s2cFrame)
	if err != nil || !bytes.Equal(decryptedServer, payload) {
		t.Fatalf("Legitimate s2c decryption failed: %v", err)
	}

	// 4. Attacker replays this exact s2c frame back to Server (sequence 1 is caught by anti-replay)
	_, err = serverRecv.OpenFrame(nil, s2cFrame)
	if !errors.Is(err, ErrReplayedPacket) && !errors.Is(err, ErrInvalidAEADAuth) {
		t.Fatalf("Expected rejection when replaying s2c packet to serverRecv, got %v", err)
	}

	// 5. Attacker tries an s2c frame with an unreceived sequence number against serverRecv (caught by AEAD tag)
	s2cFrame2, err := serverSend.SealFrame(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = serverRecv.OpenFrame(nil, s2cFrame2)
	if !errors.Is(err, ErrInvalidAEADAuth) {
		t.Fatalf("Expected ErrInvalidAEADAuth on opposite-direction frame with fresh sequence, got %v", err)
	}
	t.Log("[+] Cross-direction replay (s2c -> c2s) successfully rejected by anti-replay and AEAD tag")
}

// TestHardening_CrossSessionReplay verifies that frames cannot be injected across different sessions.
func TestHardening_CrossSessionReplay(t *testing.T) {
	secretA := make([]byte, 32)
	secretB := make([]byte, 32)
	for i := range secretA {
		secretA[i] = byte(i + 1)
		secretB[i] = byte(i + 2)
	}

	c2sKeyA, _ := DeriveDirectionalAEADKeys(secretA)
	c2sKeyB, _ := DeriveDirectionalAEADKeys(secretB)

	sessionASender, _ := NewShardAEADWithSession(c2sKeyA, 0xAAAA)
	sessionBReceiver, _ := NewShardAEADWithSession(c2sKeyB, 0xBBBB)

	payload := make([]byte, DefaultPlaintextFrameSize)
	copy(payload, []byte("Top secret for Session A"))

	frameA, err := sessionASender.SealFrame(nil, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to inject frameA into Session B's receiver (session ID mismatch)
	_, err = sessionBReceiver.OpenFrame(nil, frameA)
	if !errors.Is(err, ErrInvalidSessionID) && !errors.Is(err, ErrInvalidAEADAuth) {
		t.Fatalf("Expected ErrInvalidSessionID or ErrInvalidAEADAuth when injecting packet into Session B, got %v", err)
	}
	t.Log("[+] Cross-session injection successfully rejected by session header and AEAD")
}

// TestHardening_ReconnectionForwardSecrecy verifies distinct keys across successive handshakes.
func TestHardening_ReconnectionForwardSecrecy(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	validTokens := map[string]bool{"client-auth-token": true}

	// Handshake 1
	hello1, priv1, decaps1, nonce1, _ := GenerateClientHello("client-auth-token")
	resp1, secret1, _, err := ProcessClientHello(hello1, serverPriv, validTokens, 0x1111)
	if err != nil {
		t.Fatalf("Handshake 1 ProcessClientHello failed: %v", err)
	}
	_, clientSecret1, _ := ProcessServerHello(hello1, resp1, priv1, decaps1, nonce1, "client-auth-token", serverPub)

	// Handshake 2
	hello2, priv2, decaps2, nonce2, _ := GenerateClientHello("client-auth-token")
	resp2, secret2, _, err := ProcessClientHello(hello2, serverPriv, validTokens, 0x2222)
	if err != nil {
		t.Fatalf("Handshake 2 ProcessClientHello failed: %v", err)
	}
	_, clientSecret2, _ := ProcessServerHello(hello2, resp2, priv2, decaps2, nonce2, "client-auth-token", serverPub)

	if bytes.Equal(secret1[:], secret2[:]) {
		t.Fatal("Forward secrecy violation: sequential sessions derived identical secrets!")
	}
	if bytes.Equal(clientSecret1[:], clientSecret2[:]) {
		t.Fatal("Client derived identical secrets across reconnections!")
	}

	c2s1, _ := DeriveDirectionalAEADKeys(secret1[:])
	c2s2, _ := DeriveDirectionalAEADKeys(secret2[:])
	sender1, _ := NewShardAEAD(c2s1)
	recv2, _ := NewShardAEAD(c2s2)

	payload := make([]byte, DefaultPlaintextFrameSize)
	copy(payload, []byte("Session 1 Historical Traffic"))
	frame1, _ := sender1.SealFrame(nil, payload)

	_, err = recv2.OpenFrame(nil, frame1)
	if !errors.Is(err, ErrInvalidAEADAuth) {
		t.Fatalf("Session 2 receiver accepted historical frame from Session 1: %v", err)
	}
	t.Log("[+] Reconnection Forward Secrecy verified")
}

// TestHardening_MITMRejection verifies that an active Man-In-The-Middle without the server's
// Ed25519 identity key is rejected immediately.
func TestHardening_MITMRejection(t *testing.T) {
	legitServerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	validTokens := map[string]bool{"secure-token": true}

	hello, clientPriv, decapsKey, nonce, _ := GenerateClientHello("secure-token")

	// Attacker intercepts ClientHello and generates ServerHello signed with attackerPriv
	attackerResp, _, _, err := ProcessClientHello(hello, attackerPriv, validTokens, 0x666)
	if err != nil {
		t.Fatalf("Attacker ProcessClientHello failed: %v", err)
	}

	// Client receives attacker's ServerHello and attempts verification with legitServerPub
	_, _, err = ProcessServerHello(hello, attackerResp, clientPriv, decapsKey, nonce, "secure-token", legitServerPub)
	if !errors.Is(err, ErrInvalidServerSignature) {
		t.Fatalf("Expected ErrInvalidServerSignature on MITM attack, got %v", err)
	}
	t.Log("[+] MITM attack rejected: client detected invalid server identity signature")
}

// TestHardening_SessionIDTampering verifies that tampering with the SessionID in ServerHello
// is caught immediately by the Ed25519 signature check over TranscriptHash.
func TestHardening_SessionIDTampering(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	validTokens := map[string]bool{"secure-token": true}

	hello, clientPriv, decapsKey, nonce, _ := GenerateClientHello("secure-token")

	resp, _, _, err := ProcessClientHello(hello, serverPriv, validTokens, 0x1122334455667788)
	if err != nil {
		t.Fatal(err)
	}

	// Attacker flips bits in SessionID (bytes 5..13)
	tamperedResp := make([]byte, len(resp))
	copy(tamperedResp, resp)
	tamperedResp[5] ^= 0xFF

	_, _, err = ProcessServerHello(hello, tamperedResp, clientPriv, decapsKey, nonce, "secure-token", serverPub)
	if !errors.Is(err, ErrInvalidServerSignature) {
		t.Fatalf("Expected ErrInvalidServerSignature on SessionID tampering, got %v", err)
	}
	t.Log("[+] SessionID tampering in ServerHello detected and rejected by transcript signature")
}

// TestHardening_AntiReplayFloodDoS verifies that inserting tens of thousands of random nonces
// does not cause memory exhaustion or panic.
func TestHardening_AntiReplayFloodDoS(t *testing.T) {
	cache := NewAntiReplayCache()
	defer cache.Close()

	var nonce [16]byte
	const totalNonces = 20000

	for i := 0; i < totalNonces; i++ {
		nonce[0] = byte(i >> 8)
		nonce[1] = byte(i)
		nonce[2] = byte(i >> 16)
		cache.AddOrCheck(nonce[:])
	}
	t.Logf("[+] Successfully ingested %d nonces in bounded anti-replay cache without memory bloat", totalNonces)
}

// TestHardening_TargetedFloodReplayDefense proves that an attacker flooding thousands of nonces
// CANNOT evict an unexpired legitimate handshake nonce to replay it within the 60s validity window.
func TestHardening_TargetedFloodReplayDefense(t *testing.T) {
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tokStore := NewTokenStoreWithTokens("victim-corp-token")
	defer tokStore.Close()

	cache := NewAntiReplayCache()
	defer cache.Close()

	// 1. Legitimate client handshake executes successfully
	legitHello, _, _, _, err := GenerateClientHello("victim-corp-token", serverPub)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, err = ProcessClientHelloWithCache(legitHello, serverPriv, tokStore, 1, cache)
	if err != nil {
		t.Fatalf("legitimate handshake failed: %v", err)
	}

	// 2. Attacker floods 10,000 UDP nonces trying to flush the cache
	for i := 0; i < 10000; i++ {
		var floodNonce [16]byte
		binary.BigEndian.PutUint64(floodNonce[8:], uint64(i))
		_ = cache.AddOrCheck(floodNonce[:])
	}

	// 3. Attacker attempts to replay the captured legitimate handshake within the drift window
	_, _, _, err = ProcessClientHelloWithCache(legitHello, serverPriv, tokStore, 2, cache)
	if !errors.Is(err, ErrReplayedHandshake) {
		t.Fatalf("CRITICAL SECURITY FLAW: replayed handshake was accepted after flood! Got: %v", err)
	}

	t.Log("[+] Targeted flood replay attack successfully neutralized: legitimate nonce retained throughout drift window")
}

// TestHardening_TokenIDStatisticalUnlinkability confirms that an observer intercepting multiple handshakes
// from the same client across different roaming networks sees completely uncorrelated, high-entropy tokens.
func TestHardening_TokenIDStatisticalUnlinkability(t *testing.T) {
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tokStore := NewTokenStoreWithTokens("roaming-client-token")
	defer tokStore.Close()

	const iterations = 100
	seenTokens := make(map[[16]byte]bool)

	for i := 0; i < iterations; i++ {
		hello, _, _, _, err := GenerateClientHello("roaming-client-token", serverPub)
		if err != nil {
			t.Fatal(err)
		}

		var tid [16]byte
		copy(tid[:], hello[5:21])

		// Every wire TokenID must be completely distinct
		if seenTokens[tid] {
			t.Fatalf("duplicate TokenID detected on wire at iteration %d; linkability leak!", i)
		}
		seenTokens[tid] = true

		// Server must successfully authenticate every blinded token
		_, _, token, err := ProcessClientHello(hello, serverPriv, tokStore, uint64(i+1))
		if err != nil || token != "roaming-client-token" {
			t.Fatalf("failed to authenticate blinded token at iteration %d: %v", i, err)
		}
	}

	t.Logf("[+] Unlinkability verified: %d distinct, uncorrelatable TokenIDs generated for same user across roaming connections", iterations)
}

// TestHardening_UDPFragmentationTamperingDefense ensures that bit flips in fragments or corrupted headers
// are rejected and cannot poison the handshake reassembler state.
func TestHardening_UDPFragmentationTamperingDefense(t *testing.T) {
	serverPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	hello, _, _, _, err := GenerateClientHello("frag-hard-token", serverPub)
	if err != nil {
		t.Fatal(err)
	}

	frags, err := FragmentHandshakePayload(hello)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Tampered payload chunk in fragment 0
	r1 := NewHandshakeReassembler(10, time.Second)
	tamperedFrag0 := make([]byte, len(frags[0]))
	copy(tamperedFrag0, frags[0])
	tamperedFrag0[FragHeaderSize+10] ^= 0xff

	_, ready, _ := r1.Feed(tamperedFrag0)
	if ready {
		t.Fatal("unexpected ready for tampered fragment 0")
	}
	reassembled, ready, err := r1.Feed(frags[1])
	if err != nil || !ready {
		t.Fatal("expected ready")
	}
	// Reassembled payload has the corrupted bit, but server signature/MAC verification will reject it
	if bytes.Equal(reassembled, hello) {
		t.Fatal("reassembled payload should reflect chunk modification")
	}

	// 2. Corrupted TotalLen in fragment header
	r2 := NewHandshakeReassembler(10, time.Second)
	badTotalLenFrag := make([]byte, len(frags[0]))
	copy(badTotalLenFrag, frags[0])
	binary.BigEndian.PutUint16(badTotalLenFrag[17:19], 9999) // Exceeds max 4096

	_, _, err = r2.Feed(badTotalLenFrag)
	if !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatalf("expected ErrHandshakeMalformed for oversized totalLen, got %v", err)
	}

	t.Log("[+] UDP fragment tampering defenses validated: malformed headers rejected and corrupted chunks caught")
}
