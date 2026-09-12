package crypto

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestPQCHandshake_DirectDatagrams(t *testing.T) {
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
	resp, serverSecret, token, err := ProcessClientHello(hello, validTokens, assignedID)
	if err != nil {
		t.Fatalf("ProcessClientHello failed: %v", err)
	}
	if token != "client-token-42" {
		t.Fatalf("expected token 'client-token-42', got %q", token)
	}

	// 3. Client processes server response
	recvID, clientSecret, err := ProcessServerHello(resp, clientPriv, decapsKey, nonce)
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
		clientID, clientSecret, clientErr = PerformClientHandshake(clientConn, "token-stream-99")
	}()

	var assignedID uint64 = 0x9876543210fedcba
	serverID, serverSecret, token, serverErr := PerformServerHandshake(serverConn, validTokens, assignedID)
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
	validTokens := map[string]bool{
		"authorized-user": true,
	}

	hello, _, _, _, err := GenerateClientHello("malicious-unauthorized-user")
	if err != nil {
		t.Fatalf("GenerateClientHello failed: %v", err)
	}

	_, _, _, err = ProcessClientHello(hello, validTokens, 0x1)
	if err != ErrUnauthorizedToken {
		t.Fatalf("expected ErrUnauthorizedToken, got %v", err)
	}
}

func TestPQCHandshake_DriftWindow(t *testing.T) {
	validTokens := map[string]bool{"drift-token": true}

	hello, _, _, _, err := GenerateClientHello("drift-token")
	if err != nil {
		t.Fatalf("GenerateClientHello failed: %v", err)
	}

	// Drift into future (+120 seconds)
	corruptFuture := make([]byte, len(hello))
	copy(corruptFuture, hello)
	binary.BigEndian.PutUint64(corruptFuture[37:45], uint64(time.Now().Unix()+120))

	_, _, _, err = ProcessClientHello(corruptFuture, validTokens, 0x1)
	if err != ErrTimestampDrift {
		t.Fatalf("expected ErrTimestampDrift on future drift, got %v", err)
	}

	// Drift into past (-120 seconds)
	corruptPast := make([]byte, len(hello))
	copy(corruptPast, hello)
	binary.BigEndian.PutUint64(corruptPast[37:45], uint64(time.Now().Unix()-120))

	_, _, _, err = ProcessClientHello(corruptPast, validTokens, 0x1)
	if err != ErrTimestampDrift {
		t.Fatalf("expected ErrTimestampDrift on past drift, got %v", err)
	}
}

func TestPQCHandshake_MalformedPayloads(t *testing.T) {
	validTokens := map[string]bool{"token": true}

	// Truncated ClientHello
	_, _, _, err := ProcessClientHello([]byte("too-short"), validTokens, 1)
	if err != ErrHandshakeMalformed {
		t.Fatalf("expected ErrHandshakeMalformed, got %v", err)
	}

	// Invalid Magic
	hello, _, _, _, _ := GenerateClientHello("token")
	badMagic := make([]byte, len(hello))
	copy(badMagic, hello)
	badMagic[0] = 'X'
	_, _, _, err = ProcessClientHello(badMagic, validTokens, 1)
	if err != ErrInvalidMagic {
		t.Fatalf("expected ErrInvalidMagic, got %v", err)
	}

	// Invalid Type
	badType := make([]byte, len(hello))
	copy(badType, hello)
	badType[4] = 0x99
	_, _, _, err = ProcessClientHello(badType, validTokens, 1)
	if err != ErrInvalidMsgType {
		t.Fatalf("expected ErrInvalidMsgType, got %v", err)
	}

	// Truncated ServerHello
	_, _, err = ProcessServerHello([]byte("too-short"), nil, nil, nil)
	if err != ErrHandshakeMalformed {
		t.Fatalf("expected ErrHandshakeMalformed for ServerHello, got %v", err)
	}
}

func TestAntiReplayCache_Lifecycle(t *testing.T) {
	cache := NewAntiReplayCache()
	defer cache.Close()

	nonce1 := []byte("1234567890123456")
	nonce2 := []byte("abcdefghijklmnop")

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

	// Manual cleanup
	cache.Cleanup(time.Now().Add(10 * time.Second))
	if cache.Size() != 0 {
		t.Fatalf("expected cache size 0 after future cleanup, got %d", cache.Size())
	}
}
