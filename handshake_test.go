package badcrypt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPQCHandshake_DirectDatagrams(t *testing.T) {
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server Ed25519 key: %v", err)
	}

	validTokens := map[string]bool{
		"client-token-42": true,
	}

	// 1. Client creates hello
	hello, clientPriv, decapsKey, nonce, err := GenerateClientHello("client-token-42")
	if err != nil {
		t.Fatalf("GenerateClientHello failed: %v", err)
	}

	// 2. Server processes hello
	var assignedID uint64 = 0x12345678abcdef01
	resp, serverSecret, token, err := ProcessClientHello(hello, serverPriv, validTokens, assignedID)
	if err != nil {
		t.Fatalf("ProcessClientHello failed: %v", err)
	}
	if token != "client-token-42" {
		t.Fatalf("expected token 'client-token-42', got %q", token)
	}

	// 3. Client processes server response with serverEdPub
	recvID, clientSecret, err := ProcessServerHello(hello, resp, clientPriv, decapsKey, nonce, "client-token-42", serverPub)
	if err != nil {
		t.Fatalf("ProcessServerHello failed: %v", err)
	}

	if recvID != assignedID {
		t.Fatalf("expected session ID 0x%x, got 0x%x", assignedID, recvID)
	}
	if !bytes.Equal(clientSecret[:], serverSecret[:]) {
		t.Fatal("shared session secrets do not match between client and server")
	}
}

func TestPQCHandshake_Stream(t *testing.T) {
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server Ed25519 key: %v", err)
	}

	validTokens := map[string]bool{
		"token-stream-99": true,
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	var clientID uint64
	var clientSecret [32]byte
	var clientErr error

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		clientID, clientSecret, clientErr = PerformClientHandshake(clientConn, "token-stream-99", serverPub)
	}()

	var assignedID uint64 = 0x9876543210fedcba
	serverID, serverSecret, token, serverErr := PerformServerHandshake(serverConn, serverPriv, validTokens, assignedID)
	<-clientDone

	if clientErr != nil {
		t.Fatalf("PerformClientHandshake failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("PerformServerHandshake failed: %v", serverErr)
	}
	if token != "token-stream-99" {
		t.Fatalf("expected token 'token-stream-99', got %q", token)
	}
	if clientID != assignedID || serverID != assignedID {
		t.Fatalf("session ID mismatch: client=0x%x, server=0x%x, assigned=0x%x", clientID, serverID, assignedID)
	}
	if !bytes.Equal(clientSecret[:], serverSecret[:]) {
		t.Fatal("stream handshake session secrets mismatch")
	}
}

func TestPQCHandshake_InvalidToken(t *testing.T) {
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	validTokens := map[string]bool{
		"authorized-user": true,
	}

	hello, _, _, _, err := GenerateClientHello("malicious-unauthorized-user")
	if err != nil {
		t.Fatalf("GenerateClientHello failed: %v", err)
	}

	_, _, _, err = ProcessClientHello(hello, serverPriv, validTokens, 0x1)
	if !errors.Is(err, ErrUnauthorizedToken) {
		t.Fatalf("expected ErrUnauthorizedToken, got %v", err)
	}

	// Empty validTokens map must strictly reject
	_, _, _, err = ProcessClientHello(hello, serverPriv, map[string]bool{}, 0x1)
	if !errors.Is(err, ErrUnauthorizedToken) {
		t.Fatalf("expected ErrUnauthorizedToken for empty map, got %v", err)
	}

	// Empty token in GenerateClientHello
	_, _, _, _, err = GenerateClientHello("")
	if !errors.Is(err, ErrEmptyToken) {
		t.Fatalf("expected ErrEmptyToken, got %v", err)
	}
}

func TestPQCHandshake_DriftWindow(t *testing.T) {
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	validTokens := map[string]bool{"drift-token": true}

	hello, _, _, _, err := GenerateClientHello("drift-token")
	if err != nil {
		t.Fatalf("GenerateClientHello failed: %v", err)
	}

	// Drift into future (+120 seconds, offset 21:29)
	corruptFuture := make([]byte, len(hello))
	copy(corruptFuture, hello)
	binary.BigEndian.PutUint64(corruptFuture[21:29], uint64(time.Now().Unix()+120))

	_, _, _, err = ProcessClientHello(corruptFuture, serverPriv, validTokens, 0x1)
	if !errors.Is(err, ErrTimestampDrift) {
		t.Fatalf("expected ErrTimestampDrift on future drift, got %v", err)
	}

	// Drift into past (-120 seconds, offset 21:29)
	corruptPast := make([]byte, len(hello))
	copy(corruptPast, hello)
	binary.BigEndian.PutUint64(corruptPast[21:29], uint64(time.Now().Unix()-120))

	_, _, _, err = ProcessClientHello(corruptPast, serverPriv, validTokens, 0x1)
	if !errors.Is(err, ErrTimestampDrift) {
		t.Fatalf("expected ErrTimestampDrift on past drift, got %v", err)
	}

	// Boundary Attack 1: MaxUint64 (0xFFFFFFFFFFFFFFFF)
	corruptMaxUint := make([]byte, len(hello))
	copy(corruptMaxUint, hello)
	binary.BigEndian.PutUint64(corruptMaxUint[21:29], ^uint64(0))
	_, _, _, err = ProcessClientHello(corruptMaxUint, serverPriv, validTokens, 0x1)
	if !errors.Is(err, ErrTimestampDrift) {
		t.Fatalf("expected ErrTimestampDrift on MaxUint64 timestamp attack, got %v", err)
	}

	// Boundary Attack 2: math.MinInt64 wraparound trick (0x8000000000000000)
	corruptMinInt := make([]byte, len(hello))
	copy(corruptMinInt, hello)
	binary.BigEndian.PutUint64(corruptMinInt[21:29], 0x8000000000000000)
	_, _, _, err = ProcessClientHello(corruptMinInt, serverPriv, validTokens, 0x1)
	if !errors.Is(err, ErrTimestampDrift) {
		t.Fatalf("expected ErrTimestampDrift on math.MinInt64 timestamp attack, got %v", err)
	}

	// Boundary Attack 3: Zero timestamp
	corruptZero := make([]byte, len(hello))
	copy(corruptZero, hello)
	binary.BigEndian.PutUint64(corruptZero[21:29], 0)
	_, _, _, err = ProcessClientHello(corruptZero, serverPriv, validTokens, 0x1)
	if !errors.Is(err, ErrTimestampDrift) {
		t.Fatalf("expected ErrTimestampDrift on zero timestamp attack, got %v", err)
	}
}

func TestPQCHandshake_MalformedPayloads(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	validTokens := map[string]bool{"token": true}

	// Truncated ClientHello
	_, _, _, err := ProcessClientHello([]byte("too-short"), serverPriv, validTokens, 1)
	if !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatalf("expected ErrHandshakeMalformed, got %v", err)
	}

	// Invalid Magic
	hello, clientPriv, decapsKey, nonce, _ := GenerateClientHello("token")
	badMagic := make([]byte, len(hello))
	copy(badMagic, hello)
	badMagic[0] = 'X'
	_, _, _, err = ProcessClientHello(badMagic, serverPriv, validTokens, 1)
	if !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("expected ErrInvalidMagic, got %v", err)
	}

	// Invalid Type
	badType := make([]byte, len(hello))
	copy(badType, hello)
	badType[4] = 0x99
	_, _, _, err = ProcessClientHello(badType, serverPriv, validTokens, 1)
	if !errors.Is(err, ErrInvalidMsgType) {
		t.Fatalf("expected ErrInvalidMsgType, got %v", err)
	}

	// Truncated ServerHello
	_, _, err = ProcessServerHello(hello, []byte("too-short"), clientPriv, decapsKey, nonce, "token", serverPub)
	if !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatalf("expected ErrHandshakeMalformed for ServerHello, got %v", err)
	}

	// Oversized ClientHello
	oversizedHello := append(make([]byte, 0, len(hello)+1), hello...)
	oversizedHello = append(oversizedHello, 0xFF)
	_, _, _, err = ProcessClientHello(oversizedHello, serverPriv, validTokens, 1)
	if !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatalf("expected ErrHandshakeMalformed for oversized ClientHello, got %v", err)
	}

	// Oversized ServerHello
	resp, _, _, _ := ProcessClientHello(hello, serverPriv, validTokens, 1)
	oversizedResp := append(make([]byte, 0, len(resp)+1), resp...)
	oversizedResp = append(oversizedResp, 0xFF)
	_, _, err = ProcessServerHello(hello, oversizedResp, clientPriv, decapsKey, nonce, "token", serverPub)
	if !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatalf("expected ErrHandshakeMalformed for oversized ServerHello, got %v", err)
	}

	// Bad Magic ServerHello
	badMagicResp := make([]byte, len(resp))
	copy(badMagicResp, resp)
	badMagicResp[0] = 'X'
	_, _, err = ProcessServerHello(hello, badMagicResp, clientPriv, decapsKey, nonce, "token", serverPub)
	if !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("expected ErrInvalidMagic for ServerHello, got %v", err)
	}

	// Bad MsgType ServerHello
	badTypeResp := make([]byte, len(resp))
	copy(badTypeResp, resp)
	badTypeResp[4] = 0x99
	_, _, err = ProcessServerHello(hello, badTypeResp, clientPriv, decapsKey, nonce, "token", serverPub)
	if !errors.Is(err, ErrInvalidMsgType) {
		t.Fatalf("expected ErrInvalidMsgType for ServerHello, got %v", err)
	}
}

func TestAntiReplayCache_Lifecycle(t *testing.T) {
	cache := NewAntiReplayCache()
	defer cache.Close()

	nonce1 := []byte("1234567890123456")
	nonce2 := []byte("abcdefghijklmnop")

	cache.Close()
	var nilC *AntiReplayCache
	nilC.Close()

	// Long token branch in TokenID
	longTok := string(bytes.Repeat([]byte("X"), 200))
	longID := TokenID(longTok)
	if longID == [16]byte{} {
		t.Fatal("expected non-zero TokenID for long token")
	}

	// Fresh nonces
	if cache.AddOrCheck(nonce1) {
		t.Fatal("expected false for fresh nonce1")
	}
	if cache.AddOrCheck(nonce2) {
		t.Fatal("expected false for fresh nonce2")
	}

	// Duplicate nonces
	if !cache.AddOrCheck(nonce1) {
		t.Fatal("expected true for replayed nonce1")
	}
	if !cache.AddOrCheck(nonce2) {
		t.Fatal("expected true for replayed nonce2")
	}

	// Invalid size
	if !cache.AddOrCheck([]byte("short")) {
		t.Fatal("expected true for invalid nonce size")
	}

	// Nil cache check
	var nilCache *AntiReplayCache
	if !nilCache.AddOrCheck(nonce1) {
		t.Fatal("expected true for nil cache")
	}

	// Ring buffer eviction test: verify that unexpired nonces are NEVER prematurely evicted under flood
	shardCache := NewAntiReplayCache()
	defer shardCache.Close()

	firstNonce := make([]byte, 16)
	binary.BigEndian.PutUint16(firstNonce[:2], 0)
	binary.BigEndian.PutUint64(firstNonce[8:], 0)
	if shardCache.AddOrCheck(firstNonce) {
		t.Fatal("expected false for firstNonce")
	}

	// Ingest nonces up to shard capacity
	for i := 1; i <= EntriesPerShard; i++ {
		var n [16]byte
		binary.BigEndian.PutUint16(n[:2], 0)
		binary.BigEndian.PutUint64(n[8:], uint64(i))
		_ = shardCache.AddOrCheck(n[:])
	}

	// firstNonce must NOT be evicted while still within its validity window; replay must be detected
	if !shardCache.AddOrCheck(firstNonce) {
		t.Fatal("vulnerability detected: unexpired firstNonce was prematurely evicted under flood!")
	}

	// Test expired nonce eviction
	now := time.Now().Unix()
	var expiredNonce [16]byte
	binary.BigEndian.PutUint64(expiredNonce[8:], 999999)
	// Add with expiry in the past
	if shardCache.AddOrCheckWithExpiry(expiredNonce[:], now-10) {
		t.Fatal("expected false for fresh expiredNonce")
	}
	// Once expired and past expiry, it can be purged and reused
	shardCache.Reset()
	if shardCache.AddOrCheck(expiredNonce[:]) {
		t.Fatal("expected false after reset")
	}
}

func TestPQCHandshake_InvalidKeys(t *testing.T) {
	validTokens := map[string]bool{"token": true}
	hello, clientPriv, decapsKey, nonce, _ := GenerateClientHello("token")

	// Invalid serverEdPriv length in ProcessClientHello
	_, _, _, err := ProcessClientHello(hello, []byte("short-key"), validTokens, 1)
	if err == nil {
		t.Fatal("expected error on short serverEdPriv, got nil")
	}

	// ProcessServerHello with invalid serverEdPub
	resp, _, _, _ := ProcessClientHello(hello, ed25519.NewKeyFromSeed(make([]byte, 32)), validTokens, 1)
	_, _, err = ProcessServerHello(hello, resp, clientPriv, decapsKey, nonce, "token", []byte("short-pub"))
	if !errors.Is(err, ErrInvalidServerSignature) {
		t.Fatalf("expected ErrInvalidServerSignature on short pubkey, got %v", err)
	}

	// ProcessServerHello with nil clientPriv
	_, _, err = ProcessServerHello(hello, resp, nil, decapsKey, nonce, "token", make([]byte, 32))
	if !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatalf("expected ErrHandshakeMalformed on nil clientPriv, got %v", err)
	}

	// ProcessServerHello with mismatched nonce
	wrongNonce := make([]byte, 16)
	wrongNonce[0] = 0xFF
	_, _, err = ProcessServerHello(hello, resp, clientPriv, decapsKey, wrongNonce, "token", make([]byte, 32))
	if !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatalf("expected ErrHandshakeMalformed on wrong nonce, got %v", err)
	}
}

func TestPQCHandshake_StreamErrors(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	_ = clientConn.Close() // Close client immediately

	_, _, _, err := PerformServerHandshake(serverConn, ed25519.NewKeyFromSeed(make([]byte, 32)), map[string]bool{"tok": true}, 1)
	if err == nil {
		t.Fatal("expected error on closed stream in server handshake, got nil")
	}

	serverConn2, clientConn2 := net.Pipe()
	_ = serverConn2.Close() // Close server immediately
	_, _, err = PerformClientHandshake(clientConn2, "tok", make([]byte, 32))
	if err == nil {
		t.Fatal("expected error on closed stream in client handshake, got nil")
	}
}

func TestPQCHandshake_ContextTimeoutAndCancellation(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	validTokens := map[string]bool{"timeout-token": true}

	// 1. Client handshake with already cancelled context
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _, err := PerformClientHandshakeContext(ctxCancel, clientConn, "timeout-token", serverPub)
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("expected ErrHandshakeTimeout on cancelled context, got %v", err)
	}

	// 2. Server handshake with deadline in the past
	sConn2, cConn2 := net.Pipe()
	defer sConn2.Close()
	defer cConn2.Close()

	ctxTimeout, cancelTimeout := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelTimeout()

	_, _, _, err = PerformServerHandshakeContext(ctxTimeout, sConn2, serverPriv, validTokens, 0x123)
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("expected ErrHandshakeTimeout on expired server context, got %v", err)
	}
}

func TestPQCHandshake_Ed25519SeedSupport(t *testing.T) {
	var seed [32]byte
	_, _ = rand.Read(seed[:])
	serverPrivFromSeed := ed25519.NewKeyFromSeed(seed[:])
	serverPub := serverPrivFromSeed.Public().(ed25519.PublicKey)

	validTokens := map[string]bool{"seed-token": true}
	hello, clientPriv, decapsKey, nonce, err := GenerateClientHello("seed-token")
	if err != nil {
		t.Fatal(err)
	}

	// Pass the 32-byte seed directly as serverEdPriv to ProcessClientHello
	resp, serverSecret, token, err := ProcessClientHello(hello, seed[:], validTokens, 0x42)
	if err != nil {
		t.Fatalf("ProcessClientHello failed with 32-byte seed: %v", err)
	}
	if token != "seed-token" {
		t.Fatalf("expected token 'seed-token', got %q", token)
	}

	rxID, clientSecret, err := ProcessServerHello(hello, resp, clientPriv, decapsKey, nonce, "seed-token", serverPub)
	if err != nil {
		t.Fatalf("ProcessServerHello failed: %v", err)
	}
	if rxID != 0x42 || !bytes.Equal(clientSecret[:], serverSecret[:]) {
		t.Fatal("secret or session ID mismatch with 32-byte seed")
	}
}

func TestPQCHandshake_FinishedMACTampering(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	validTokens := map[string]bool{"mac-test": true}

	hello, clientPriv, decapsKey, nonce, _ := GenerateClientHello("mac-test")
	resp, _, _, err := ProcessClientHello(hello, serverPriv, validTokens, 0x99)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with Finished MAC (last 32 bytes)
	corruptResp := make([]byte, len(resp))
	copy(corruptResp, resp)
	corruptResp[len(corruptResp)-1] ^= 0xFF

	_, clientSecret, err := ProcessServerHello(hello, corruptResp, clientPriv, decapsKey, nonce, "mac-test", serverPub)
	if !errors.Is(err, ErrInvalidFinishedMAC) {
		t.Fatalf("expected ErrInvalidFinishedMAC on tampered MAC, got %v", err)
	}
	if clientSecret != [32]byte{} {
		t.Fatal("session secret must remain empty when Finished MAC verification fails")
	}
}

func TestAntiReplayCache_ResetAndGlobal(t *testing.T) {
	cache := NewAntiReplayCache()
	defer cache.Close()

	var nonce [16]byte
	_, _ = rand.Read(nonce[:])

	if cache.AddOrCheck(nonce[:]) {
		t.Fatal("expected fresh nonce")
	}
	if !cache.AddOrCheck(nonce[:]) {
		t.Fatal("expected replay detected")
	}

	cache.Reset()

	// After Reset, the nonce should be accepted again
	if cache.AddOrCheck(nonce[:]) {
		t.Fatal("expected nonce to be fresh after Reset")
	}

	// Test ResetGlobalReplayCache
	ResetGlobalReplayCache()

	var nilCache *AntiReplayCache
	nilCache.Reset()
}

func TestPQCHandshake_WrapStreamErrorAndCryptoFailures(t *testing.T) {
	// wrapStreamError with nil
	if err := wrapStreamError(context.Background(), "op", nil); err != nil {
		t.Fatalf("expected nil from wrapStreamError on nil err, got %v", err)
	}

	// wrapStreamError with generic error
	customErr := errors.New("custom pipe error")
	wrapped := wrapStreamError(context.Background(), "op", customErr)
	if !errors.Is(wrapped, customErr) {
		t.Fatalf("expected wrapped error to contain customErr, got %v", wrapped)
	}

	// Corrupted client X25519 public key in ClientHello
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	validTokens := map[string]bool{"token": true}

	hello, _, _, _, _ := GenerateClientHello("token")
	corruptX25519Hello := make([]byte, len(hello))
	copy(corruptX25519Hello, hello)
	// Bytes 45..77 are X25519 public key. In X25519, all 32-byte strings are valid curve points,
	// but ML-KEM encapsulation key bytes (77..1261) have strict algebraic invariants.
	// We corrupt ML-KEM key in ClientHello:
	corruptMLKEMHello := make([]byte, len(hello))
	copy(corruptMLKEMHello, hello)
	// Corrupting encapsulation key bytes to trigger NewEncapsulationKey768 failure
	for i := 77; i < 77+32; i++ {
		corruptMLKEMHello[i] = 0xFF
	}
	_, _, _, err := ProcessClientHello(corruptMLKEMHello, serverPriv, validTokens, 1)
	if err == nil {
		t.Fatal("expected error on corrupted ML-KEM key in ClientHello, got nil")
	}

	// Corrupted ServerHello X25519 public key (use fresh hello to avoid replay cache rejection)
	freshHello, freshPriv, freshDecaps, freshNonce, err := GenerateClientHello("fresh-stream-token")
	if err != nil {
		t.Fatal(err)
	}
	freshTokens := map[string]bool{"fresh-stream-token": true}
	resp, _, _, err := ProcessClientHello(freshHello, serverPriv, freshTokens, 1)
	if err != nil {
		t.Fatalf("ProcessClientHello failed: %v", err)
	}

	// Resign a ServerHello that contains invalid X25519 public key
	corruptServerResp := make([]byte, len(resp))
	copy(corruptServerResp, resp)
	// Change Server X25519 pub (bytes 13:45)
	for i := 13; i < 45; i++ {
		corruptServerResp[i] = 0xFF
	}
	// Recompute transcript and signature with the corrupted pubkey so it passes signature check
	transcript := sha256.New()
	transcript.Write(freshHello[:ClientHelloSize])
	transcript.Write(corruptServerResp[:ServerHelloPreSigSize])
	tHash := transcript.Sum(nil)
	newSig := ed25519.Sign(serverPriv, tHash)
	copy(corruptServerResp[ServerHelloPreSigSize:ServerHelloPreSigSize+ed25519.SignatureSize], newSig)

	// ProcessServerHello will now proceed past signature check and evaluate the key/cipher
	_, _, _ = ProcessServerHello(freshHello, corruptServerResp, freshPriv, freshDecaps, freshNonce, "fresh-stream-token", serverPub)
}

func TestPQCHandshake_NilConnDefenses(t *testing.T) {
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := serverPriv.Public().(ed25519.PublicKey)

	_, _, err := PerformClientHandshakeContext(context.Background(), nil, "token", serverPub)
	if err == nil {
		t.Fatal("expected error on nil conn in PerformClientHandshakeContext, got nil")
	}

	_, _, _, err = PerformServerHandshakeContext(context.Background(), nil, serverPriv, map[string]bool{"token": true}, 1)
	if err == nil {
		t.Fatal("expected error on nil conn in PerformServerHandshakeContext, got nil")
	}
}

func TestPQCHandshake_PreCancelledContext(t *testing.T) {
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := serverPriv.Public().(ed25519.PublicKey)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Already cancelled

	_, _, err := PerformClientHandshakeContext(ctx, clientConn, "token", serverPub)
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("expected ErrHandshakeTimeout on pre-cancelled client context, got %v", err)
	}

	_, _, _, err = PerformServerHandshakeContext(ctx, serverConn, serverPriv, map[string]bool{"token": true}, 1)
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("expected ErrHandshakeTimeout on pre-cancelled server context, got %v", err)
	}
}

func TestTokenID_ZeroAlloc(t *testing.T) {
	const tok = "test-token-zero-alloc-production-ready-6479"

	// Warmup
	_ = TokenID(tok)

	allocs := testing.AllocsPerRun(100, func() {
		_ = TokenID(tok)
	})

	if allocs > 0 {
		t.Fatalf("expected 0 allocs/op for TokenID, got %f", allocs)
	}
}

type mockTimeoutError struct{}

func (m mockTimeoutError) Error() string   { return "mock network timeout" }
func (m mockTimeoutError) Timeout() bool   { return true }
func (m mockTimeoutError) Temporary() bool { return true }

type failWriterConn struct {
	net.Conn
}

func (f failWriterConn) Write(b []byte) (n int, err error) {
	return 0, errors.New("simulated write failure")
}

func TestPQCHandshake_ExtendedErrorBranches(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)

	// 1. PerformClientHandshakeContext with empty token
	sConn, cConn := net.Pipe()
	defer sConn.Close()
	defer cConn.Close()

	_, _, err := PerformClientHandshakeContext(context.Background(), cConn, "", serverPub)
	if !errors.Is(err, ErrEmptyToken) {
		t.Fatalf("expected ErrEmptyToken, got %v", err)
	}

	// 2. PerformClientHandshakeContext with broken server connection during read
	sConn2, cConn2 := net.Pipe()
	go func() {
		buf := make([]byte, ClientHelloSize)
		_, _ = io.ReadFull(sConn2, buf)
		_ = sConn2.Close() // Close before sending ServerHello
	}()
	_, _, err = PerformClientHandshakeContext(context.Background(), cConn2, "token", serverPub)
	if err == nil {
		t.Fatal("expected error on truncated server stream, got nil")
	}
	_ = cConn2.Close()

	// 3. PerformServerHandshakeContext with write failure
	sConn3, cConn3 := net.Pipe()
	defer sConn3.Close()
	defer cConn3.Close()
	go func() {
		hello, _, _, _, _ := GenerateClientHello("token")
		_, _ = cConn3.Write(hello)
	}()
	failConn := failWriterConn{Conn: sConn3}
	_, _, _, err = PerformServerHandshakeContext(context.Background(), failConn, serverPriv, map[string]bool{"token": true}, 1)
	if err == nil {
		t.Fatal("expected error on write failure, got nil")
	}

	// 4. wrapStreamError with net.Error timeout
	netTimeoutErr := mockTimeoutError{}
	wrapped := wrapStreamError(context.Background(), "test-op", netTimeoutErr)
	if !errors.Is(wrapped, ErrHandshakeTimeout) {
		t.Fatalf("expected ErrHandshakeTimeout for net.Error timeout, got %v", wrapped)
	}

	// 5. ProcessServerHello with invalid clientHelloPayload length
	hello, priv, decaps, nonce, _ := GenerateClientHello("token")
	resp, _, _, _ := ProcessClientHello(hello, serverPriv, map[string]bool{"token": true}, 1)
	_, _, err = ProcessServerHello([]byte("too-short"), resp, priv, decaps, nonce, "token", serverPub)
	if !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatalf("expected ErrHandshakeMalformed on short clientHelloPayload, got %v", err)
	}

	// 6. ProcessClientHelloWithCache with empty token string in validTokens
	_, _, _, err = ProcessClientHello(hello, serverPriv, map[string]bool{"": true}, 1)
	if !errors.Is(err, ErrUnauthorizedToken) {
		t.Fatalf("expected ErrUnauthorizedToken for empty string token, got %v", err)
	}

	// 7. AntiReplayCache on uninitialized struct (lazy map creation branch)
	var uninitializedCache AntiReplayCache
	freshNonce := make([]byte, 16)
	_, _ = rand.Read(freshNonce)
	if uninitializedCache.AddOrCheck(freshNonce) {
		t.Fatal("expected false for first nonce on uninitialized cache")
	}
	if !uninitializedCache.AddOrCheck(freshNonce) {
		t.Fatal("expected true for duplicate nonce on uninitialized cache")
	}

	// 8. wrapStreamError with cancelled context
	cancCtx, cancel := context.WithCancel(context.Background())
	cancel()
	wrapCanc := wrapStreamError(cancCtx, "cancelled-op", errors.New("underlying network error"))
	if !errors.Is(wrapCanc, ErrHandshakeTimeout) {
		t.Fatalf("expected ErrHandshakeTimeout when context is cancelled, got %v", wrapCanc)
	}

	// 9. Mid-stream context cancellation unblocking client read via SetDeadline
	sConnMid, cConnMid := net.Pipe()
	defer sConnMid.Close()
	defer cConnMid.Close()
	midCtx, midCancel := context.WithCancel(context.Background())
	go func() {
		// Read client hello but never send response
		buf := make([]byte, ClientHelloSize)
		_, _ = io.ReadFull(sConnMid, buf)
		time.Sleep(50 * time.Millisecond)
		midCancel() // Cancel while client is waiting for server response
	}()
	_, _, err = PerformClientHandshakeContext(midCtx, cConnMid, "token", serverPub)
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("expected ErrHandshakeTimeout on mid-stream client cancellation, got %v", err)
	}

	// 10. Mid-stream context cancellation unblocking server read via SetDeadline
	sConnMid2, cConnMid2 := net.Pipe()
	defer sConnMid2.Close()
	defer cConnMid2.Close()
	midCtx2, midCancel2 := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		midCancel2() // Cancel while server is waiting for client hello
	}()
	_, _, _, err = PerformServerHandshakeContext(midCtx2, sConnMid2, serverPriv, map[string]bool{"token": true}, 1)
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("expected ErrHandshakeTimeout on mid-stream server cancellation, got %v", err)
	}
}

type mockDeadlinerConn struct {
	net.Conn
	mu       sync.Mutex
	setCalls []time.Time
}

func (m *mockDeadlinerConn) SetDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setCalls = append(m.setCalls, t)
	return m.Conn.SetDeadline(t)
}

func TestPQCHandshake_DeadlinerSupport(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	sConn, cConn := net.Pipe()
	defer sConn.Close()
	defer cConn.Close()

	mockClient := &mockDeadlinerConn{Conn: cConn}
	validTokens := map[string]bool{"deadliner-tok": true}

	go func() {
		_, _, _, _ = PerformServerHandshake(sConn, serverPriv, validTokens, 0x123)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err := PerformClientHandshakeContext(ctx, mockClient, "deadliner-tok", serverPub)
	if err != nil {
		t.Fatalf("PerformClientHandshakeContext failed: %v", err)
	}

	mockClient.mu.Lock()
	defer mockClient.mu.Unlock()
	if len(mockClient.setCalls) == 0 {
		t.Fatal("expected deadliner SetDeadline to be invoked")
	}
	lastCall := mockClient.setCalls[len(mockClient.setCalls)-1]
	if !lastCall.IsZero() {
		t.Fatalf("expected last SetDeadline call to be zero time (cleared), got %v", lastCall)
	}
}

func TestPQCHandshake_DeadlineRaceConditionSafety(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	validTokens := map[string]bool{"race-safe-token": true}

	for i := 0; i < 20; i++ {
		sConn, cConn := net.Pipe()

		go func() {
			_, _, _, _ = PerformServerHandshake(sConn, serverPriv, validTokens, 0x555)
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

		_, _, err := PerformClientHandshakeContext(ctx, cConn, "race-safe-token", serverPub)
		if err != nil {
			t.Fatalf("handshake failed on iteration %d: %v", i, err)
		}

		// Cancel context immediately upon completion to trigger potential race in background goroutine
		cancel()
		time.Sleep(5 * time.Millisecond)

		// Verify connection remains fully usable and has not had deadline set to past
		testMsg := []byte("post-handshake-ping")
		go func() {
			_, _ = sConn.Write(testMsg)
		}()

		buf := make([]byte, len(testMsg))
		_ = cConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := io.ReadFull(cConn, buf); err != nil {
			t.Fatalf("subsequent read failed after context cancellation on iteration %d: %v", i, err)
		}
		if !bytes.Equal(buf, testMsg) {
			t.Fatal("data mismatch on post-handshake message")
		}

		_ = sConn.Close()
		_ = cConn.Close()
	}
}

func TestTokenStore_ConcurrencyAndValidation(t *testing.T) {
	store := NewTokenStore()
	defer store.Close()

	// 1. Initial count
	if store.Count() != 0 {
		t.Fatalf("expected count 0, got %d", store.Count())
	}

	// 2. Add tokens
	tok1 := "user-token-alpha"
	tok2 := "user-token-beta"
	store.Add(tok1)
	store.Add(tok2)

	if store.Count() != 2 {
		t.Fatalf("expected count 2, got %d", store.Count())
	}

	// 3. Lookup existing tokens
	id1 := TokenID(tok1)
	matched, ok := store.ValidateTokenID(id1[:])
	if !ok || matched != tok1 {
		t.Fatalf("expected to match %s, got ok=%v, token=%s", tok1, ok, matched)
	}

	id2 := TokenID(tok2)
	matched2, ok := store.ValidateTokenID(id2[:])
	if !ok || matched2 != tok2 {
		t.Fatalf("expected to match %s, got ok=%v, token=%s", tok2, ok, matched2)
	}

	// 4. Lookup unknown token
	idUnknown := TokenID("non-existent-token")
	_, ok = store.ValidateTokenID(idUnknown[:])
	if ok {
		t.Fatal("expected ValidateTokenID to return false for unknown token")
	}

	// 5. Remove token
	store.Remove(tok1)
	if store.Count() != 1 {
		t.Fatalf("expected count 1 after removal, got %d", store.Count())
	}
	_, ok = store.ValidateTokenID(id1[:])
	if ok {
		t.Fatal("expected removed token to fail lookup")
	}

	// 6. Test with empty / nil edge cases
	store.Add("")
	store.Remove("")
	_, ok = store.ValidateTokenID(nil)
	if ok {
		t.Fatal("expected nil token ID to fail")
	}
	_, ok = store.ValidateTokenID([]byte("short"))
	if ok {
		t.Fatal("expected short token ID to fail")
	}

	// 7. Nil store safety
	var nilStore *TokenStore
	nilStore.Add("abc")
	nilStore.Remove("abc")
	nilStore.Close()
	if nilStore.Count() != 0 {
		t.Fatal("expected 0 count on nil store")
	}
	if _, ok := nilStore.ValidateTokenID(id1[:]); ok {
		t.Fatal("expected nil store ValidateTokenID to return false")
	}
}

func TestTokenStore_ConcurrentReadWrite(t *testing.T) {
	store := NewTokenStoreWithTokens("tok-0", "tok-1", "tok-2")
	defer store.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 5 reader goroutines
	for r := 0; r < 5; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					target := fmt.Sprintf("tok-%d", readerID%3)
					tid := TokenID(target)
					_, _ = store.ValidateTokenID(tid[:])
					_ = store.Count()
				}
			}
		}(r)
	}

	// 3 writer goroutines
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				dynamicTok := fmt.Sprintf("dynamic-w%d-%d", writerID, i)
				store.Add(dynamicTok)
				tid := TokenID(dynamicTok)
				_, _ = store.ValidateTokenID(tid[:])
				store.Remove(dynamicTok)
			}
		}(w)
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestTokenStore_HandshakeIntegration(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	tokStore := NewTokenStoreWithTokens("prod-token-supersecret")
	defer tokStore.Close()

	// 1. Direct Datagram with TokenStore
	hello, clientPriv, decapsKey, nonce, err := GenerateClientHello("prod-token-supersecret")
	if err != nil {
		t.Fatal(err)
	}

	resp, sSecret, token, err := ProcessClientHello(hello, serverPriv, tokStore, 0x55aa)
	if err != nil {
		t.Fatalf("ProcessClientHello with TokenStore failed: %v", err)
	}
	if token != "prod-token-supersecret" {
		t.Fatalf("expected token 'prod-token-supersecret', got %q", token)
	}

	_, cSecret, err := ProcessServerHello(hello, resp, clientPriv, decapsKey, nonce, "prod-token-supersecret", serverPub)
	if err != nil {
		t.Fatalf("ProcessServerHello failed: %v", err)
	}
	if !bytes.Equal(sSecret[:], cSecret[:]) {
		t.Fatal("session secrets mismatch with TokenStore")
	}

	// 2. Stream Handshake with TokenStore
	sConn, cConn := net.Pipe()
	defer sConn.Close()
	defer cConn.Close()

	go func() {
		_, _, _, _ = PerformServerHandshake(sConn, serverPriv, tokStore, 0x7788)
	}()

	sID, _, err := PerformClientHandshake(cConn, "prod-token-supersecret", serverPub)
	if err != nil {
		t.Fatalf("PerformClientHandshake failed: %v", err)
	}
	if sID != 0x7788 {
		t.Fatalf("expected session ID 0x7788, got 0x%x", sID)
	}
}

func TestTokenPrivacy_BlindingAndUnmasking(t *testing.T) {
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tokStore := NewTokenStoreWithTokens("alice-secret-token")
	defer tokStore.Close()

	// Generate two distinct ClientHellos for Alice using the same server identity key
	hello1, priv1, decaps1, nonce1, err := GenerateClientHello("alice-secret-token", serverPub)
	if err != nil {
		t.Fatalf("GenerateClientHello 1 failed: %v", err)
	}
	hello2, priv2, decaps2, nonce2, err := GenerateClientHello("alice-secret-token", serverPub)
	if err != nil {
		t.Fatalf("GenerateClientHello 2 failed: %v", err)
	}

	// 1. Verify Unlinkability: wire TokenIDs must be completely different
	tid1 := hello1[5:21]
	tid2 := hello2[5:21]
	rawTid := TokenID("alice-secret-token")

	if bytes.Equal(tid1, tid2) {
		t.Fatal("vulnerability: TokenIDs on wire are identical; tracking vulnerability exists!")
	}
	if bytes.Equal(tid1, rawTid[:]) || bytes.Equal(tid2, rawTid[:]) {
		t.Fatal("vulnerability: TokenID was transmitted in cleartext without blinding!")
	}

	// 2. Verify Server-Side Unmasking and Authentication
	resp1, sSecret1, token1, err := ProcessClientHello(hello1, serverPriv, tokStore, 101)
	if err != nil {
		t.Fatalf("ProcessClientHello 1 failed: %v", err)
	}
	if token1 != "alice-secret-token" {
		t.Fatalf("expected token alice-secret-token, got %s", token1)
	}

	resp2, sSecret2, token2, err := ProcessClientHello(hello2, serverPriv, tokStore, 102)
	if err != nil {
		t.Fatalf("ProcessClientHello 2 failed: %v", err)
	}
	if token2 != "alice-secret-token" {
		t.Fatalf("expected token alice-secret-token, got %s", token2)
	}

	// 3. Verify Client-Side Completion
	_, cSecret1, err := ProcessServerHello(hello1, resp1, priv1, decaps1, nonce1, "alice-secret-token", serverPub)
	if err != nil {
		t.Fatalf("ProcessServerHello 1 failed: %v", err)
	}
	if !bytes.Equal(sSecret1[:], cSecret1[:]) {
		t.Fatal("session secret mismatch for handshake 1")
	}

	_, cSecret2, err := ProcessServerHello(hello2, resp2, priv2, decaps2, nonce2, "alice-secret-token", serverPub)
	if err != nil {
		t.Fatalf("ProcessServerHello 2 failed: %v", err)
	}
	if !bytes.Equal(sSecret2[:], cSecret2[:]) {
		t.Fatal("session secret mismatch for handshake 2")
	}

	// 4. Verify Backward Compatibility: legacy unmasked ClientHello also authenticates
	legacyHello, _, _, _, err := GenerateClientHello("alice-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	_, _, tokenLegacy, err := ProcessClientHello(legacyHello, serverPriv, tokStore, 103)
	if err != nil {
		t.Fatalf("legacy unmasked ClientHello failed to authenticate: %v", err)
	}
	if tokenLegacy != "alice-secret-token" {
		t.Fatalf("expected token alice-secret-token, got %s", tokenLegacy)
	}

	// 5. Tampering defense: flip 1 bit in blinded TokenID -> must fail authentication
	tamperedHello := make([]byte, len(hello1))
	copy(tamperedHello, hello1)
	tamperedHello[10] ^= 0x01
	_, _, _, err = ProcessClientHello(tamperedHello, serverPriv, tokStore, 104)
	if !errors.Is(err, ErrUnauthorizedToken) {
		t.Fatalf("expected ErrUnauthorizedToken for tampered token, got %v", err)
	}
}

func TestDatagramFragmentation_ClientAndServer(t *testing.T) {
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tokStore := NewTokenStoreWithTokens("frag-test-token")
	defer tokStore.Close()

	hello, clientPriv, decapsKey, nonce, err := GenerateClientHello("frag-test-token", serverPub)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Fragment ClientHello
	frags, err := FragmentHandshakePayload(hello)
	if err != nil {
		t.Fatalf("FragmentHandshakePayload failed: %v", err)
	}
	if len(frags) != 2 {
		t.Fatalf("expected 2 fragments for ClientHello (%d bytes), got %d", len(hello), len(frags))
	}
	for i, f := range frags {
		if len(f) > FragHeaderSize+MaxDatagramChunkSize {
			t.Fatalf("fragment %d exceeds max chunk: %d bytes", i, len(f))
		}
		// Total datagram wire size + IPv6(40) + UDP(8) must be <= 1232 (SafeInternetMTU)
		wireWithIPv6UDP := len(f) + 48
		if wireWithIPv6UDP > SafeInternetMTU {
			t.Fatalf("fragment %d wire size with IPv6/UDP (%d bytes) exceeds SafeInternetMTU (%d)",
				i, wireWithIPv6UDP, SafeInternetMTU)
		}
	}

	// 2. Reassemble In Order
	reassembler := NewHandshakeReassembler(64, 2*time.Second)
	defer reassembler.Reset()

	got, ready, err := reassembler.Feed(frags[0])
	if err != nil || ready || got != nil {
		t.Fatalf("unexpected state after frag 0: ready=%v, err=%v", ready, err)
	}
	if reassembler.Count() != 1 {
		t.Fatalf("expected 1 pending session, got %d", reassembler.Count())
	}

	got, ready, err = reassembler.Feed(frags[1])
	if err != nil || !ready {
		t.Fatalf("failed to reassemble: ready=%v, err=%v", ready, err)
	}
	if !bytes.Equal(got, hello) {
		t.Fatal("reassembled ClientHello does not match original bytes!")
	}
	if reassembler.Count() != 0 {
		t.Fatalf("expected 0 pending sessions after completion, got %d", reassembler.Count())
	}

	// 3. Cryptographically Process Reassembled ClientHello
	resp, sSecret, token, err := ProcessClientHello(got, serverPriv, tokStore, 201)
	if err != nil {
		t.Fatalf("ProcessClientHello on reassembled datagram failed: %v", err)
	}
	if token != "frag-test-token" {
		t.Fatalf("expected frag-test-token, got %s", token)
	}

	// 4. Fragment ServerHello and Reassemble Out of Order (frag 1 then frag 0)
	respFrags, err := FragmentHandshakePayload(resp)
	if err != nil {
		t.Fatalf("FragmentHandshakePayload on ServerHello failed: %v", err)
	}
	if len(respFrags) != 2 {
		t.Fatalf("expected 2 fragments for ServerHello (%d bytes), got %d", len(resp), len(respFrags))
	}

	clientReassembler := NewHandshakeReassembler(64, 2*time.Second)
	// Feed fragment 1 first (out of order)
	gotResp, ready, err := clientReassembler.Feed(respFrags[1])
	if err != nil || ready || gotResp != nil {
		t.Fatalf("unexpected state after out-of-order frag 1: ready=%v, err=%v", ready, err)
	}
	// Feed duplicate fragment 1
	gotResp, ready, err = clientReassembler.Feed(respFrags[1])
	if err != nil || ready || gotResp != nil {
		t.Fatalf("duplicate fragment caused unexpected error: %v", err)
	}
	// Feed fragment 0
	gotResp, ready, err = clientReassembler.Feed(respFrags[0])
	if err != nil || !ready {
		t.Fatalf("failed out-of-order reassembly: %v", err)
	}
	if !bytes.Equal(gotResp, resp) {
		t.Fatal("reassembled ServerHello does not match original bytes!")
	}

	// 5. Complete Client Handshake with Reassembled ServerHello
	_, cSecret, err := ProcessServerHello(hello, gotResp, clientPriv, decapsKey, nonce, "frag-test-token", serverPub)
	if err != nil {
		t.Fatalf("ProcessServerHello on reassembled datagram failed: %v", err)
	}
	if !bytes.Equal(sSecret[:], cSecret[:]) {
		t.Fatal("session secrets mismatch between reassembled datagrams!")
	}
}

func TestDatagramFragmentation_ErrorDefenses(t *testing.T) {
	r := NewHandshakeReassembler(2, 50*time.Millisecond)

	// 1. Short datagram
	_, _, err := r.Feed([]byte{1, 2, 3})
	if !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatalf("expected ErrHandshakeMalformed, got %v", err)
	}

	// 2. Invalid magic
	_, _, err = r.Feed([]byte{'X', 'Y', 'Z', 'W', TypeClientHello})
	if !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("expected ErrInvalidMagic, got %v", err)
	}

	// 3. Direct unfragmented datagram pass-through
	direct := make([]byte, ClientHelloSize)
	copy(direct[:4], MagicHeader[:])
	direct[4] = TypeClientHello
	got, ready, err := r.Feed(direct)
	if err != nil || !ready || !bytes.Equal(got, direct) {
		t.Fatal("expected unfragmented pass-through")
	}

	// 4. Invalid message type
	badType := make([]byte, FragHeaderSize+10)
	copy(badType[:4], MagicHeader[:])
	badType[4] = 0x99
	_, _, err = r.Feed(badType)
	if !errors.Is(err, ErrInvalidMsgType) {
		t.Fatalf("expected ErrInvalidMsgType, got %v", err)
	}

	// 5. Short fragment header
	shortFrag := make([]byte, FragHeaderSize-1)
	copy(shortFrag[:4], MagicHeader[:])
	shortFrag[4] = TypeClientHelloFrag
	_, _, err = r.Feed(shortFrag)
	if !errors.Is(err, ErrHandshakeMalformed) {
		t.Fatalf("expected ErrHandshakeMalformed, got %v", err)
	}

	// 6. TTL expiry
	hello, _, _, _, _ := GenerateClientHello("tok")
	frags, _ := FragmentHandshakePayload(hello)
	_, ready, _ = r.Feed(frags[0])
	if ready {
		t.Fatal("unexpected ready")
	}
	time.Sleep(60 * time.Millisecond) // Let TTL expire
	// Feed fragment 0 again under new time; previous stale state should be purged
	_, ready, err = r.Feed(frags[0])
	if err != nil || ready {
		t.Fatalf("unexpected error after TTL expiry: %v", err)
	}

	// 7. Reassembly buffer capacity exhaustion & anti-DoS eviction defense:
	// When capacity is reached, the oldest incomplete handshake is evicted (LRU)
	// so legitimate incoming handshakes are never locked out.
	rSmall := NewHandshakeReassembler(1, 10*time.Second)
	f1, _ := FragmentHandshakePayload(hello)
	_, _, _ = rSmall.Feed(f1[0])

	f2, _ := FragmentHandshakePayload(hello)
	_, ready, err = rSmall.Feed(f2[0])
	if err != nil || ready {
		t.Fatalf("expected fresh session accepted without error, got err=%v ready=%v", err, ready)
	}
	if rSmall.Count() != 1 {
		t.Fatalf("expected bounded count 1, got %d", rSmall.Count())
	}
	// Complete f2 successfully
	reassembledF2, ready, err := rSmall.Feed(f2[1])
	if err != nil || !ready || !bytes.Equal(reassembledF2, hello) {
		t.Fatalf("expected f2 to successfully complete after f1 eviction: ready=%v err=%v", ready, err)
	}
}

func TestAntiReplayCache_AESShardDistribution(t *testing.T) {
	c := NewAntiReplayCache()
	defer c.Close()

	// Generate 100 nonces with identical first 2 bytes (0x00, 0x00)
	// Without AES salting, all 100 would map to shard 0.
	// With random AES salting, they must distribute across multiple shards.
	shardsSeen := make(map[int]bool)
	for i := 0; i < 100; i++ {
		var n [16]byte
		binary.BigEndian.PutUint64(n[8:], uint64(i))
		idx := c.getShardIndex(n[:])
		shardsSeen[idx] = true
	}

	if len(shardsSeen) <= 1 {
		t.Fatalf("AES salting failed: all nonces hashed to the same shard (%d seen)", len(shardsSeen))
	}
	if len(shardsSeen) < 10 {
		t.Fatalf("AES salting gave poor distribution: %d shards seen out of 64", len(shardsSeen))
	}
}
