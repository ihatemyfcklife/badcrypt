package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// FuzzFrameDecoder fuzzes AEAD OpenFrame with arbitrary ciphertext and nonces.
func FuzzFrameDecoder(f *testing.F) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	aead, _ := NewShardAEAD(key)

	// Seeds
	f.Add([]byte{})
	f.Add(make([]byte, ConstantWireFrameSize))

	validPlain := make([]byte, DefaultPlaintextFrameSize)
	validFrame, _ := aead.SealFrame(nil, validPlain)
	f.Add(validFrame)

	f.Fuzz(func(t *testing.T, data []byte) {
		recvAEAD, _ := NewShardAEAD(key)
		_, _ = recvAEAD.OpenFrame(nil, data)
	})
}

// FuzzHandshakeParser fuzzes ClientHello and ServerHello parsers with arbitrary datagram inputs.
func FuzzHandshakeParser(f *testing.F) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	validTokens := map[string]bool{"fuzz-token": true}

	f.Add([]byte{})
	f.Add(make([]byte, ClientHelloSize))

	hello, clientPriv, decapsKey, nonce, _ := GenerateClientHello("fuzz-token")
	f.Add(hello)

	resp, _, _, _ := ProcessClientHello(hello, serverPriv, validTokens, 0x1234)
	f.Add(resp)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test ClientHello parsing
		_, _, _, _ = ProcessClientHello(data, serverPriv, validTokens, 0x5678)

		// Test ServerHello parsing
		_, _, _ = ProcessServerHello(hello, data, clientPriv, decapsKey, nonce, "fuzz-token", serverPub)
	})
}

// FuzzReplayCache fuzzes AntiReplayCache with arbitrary nonces and rapid checks.
func FuzzReplayCache(f *testing.F) {
	f.Add([]byte("initial-nonce-1"))
	f.Add(make([]byte, 16))

	cache := NewAntiReplayCache()
	defer cache.Close()

	f.Fuzz(func(t *testing.T, nonce []byte) {
		_ = cache.AddOrCheck(nonce)
		if len(nonce) == 16 {
			replayed := cache.AddOrCheck(nonce)
			if !replayed {
				t.Fatalf("Expected replayed=true on second call for %x", nonce)
			}
		}
	})
}

// FuzzAntiReplayWindow fuzzes the sliding window with random sequences.
func FuzzAntiReplayWindow(f *testing.F) {
	f.Add(uint64(1))
	f.Add(uint64(100))
	f.Add(uint64(1000))

	f.Fuzz(func(t *testing.T, seq uint64) {
		w := &antiReplayWindow{}
		_ = w.check(seq)
		_ = w.mark(seq)
		// Second check must detect replay
		if seq != 0 {
			if err := w.check(seq); err == nil {
				t.Fatalf("expected replay detection for seq %d", seq)
			}
		}
	})
}

// FuzzSlidingWindowSequence fuzzes the sliding window with sequential byte streams as packet sequence numbers.
func FuzzSlidingWindowSequence(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5})
	f.Add([]byte{10, 5, 20, 15, 12, 10})
	f.Add([]byte{255, 1, 255, 0, 100})

	f.Fuzz(func(t *testing.T, data []byte) {
		w := &antiReplayWindow{}
		for _, b := range data {
			seq := uint64(b)
			errCheck := w.check(seq)
			errMark := w.mark(seq)
			if seq == 0 {
				if errCheck == nil || errMark == nil {
					t.Fatalf("expected error for seq=0")
				}
			}
		}
	})
}
