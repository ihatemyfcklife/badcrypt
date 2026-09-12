package crypto

import (
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
	validFrame := aead.SealFrame(nil, validPlain)
	f.Add(validFrame)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = aead.OpenFrame(nil, data)
	})
}

// FuzzHandshakeParser fuzzes ClientHello and ServerHello parsers with arbitrary datagram inputs.
func FuzzHandshakeParser(f *testing.F) {
	validTokens := map[string]bool{"fuzz-token": true}

	f.Add([]byte{})
	f.Add(make([]byte, ClientHelloSize))

	hello, clientPriv, decapsKey, nonce, _ := GenerateClientHello("fuzz-token")
	f.Add(hello)

	resp, _, _, _ := ProcessClientHello(hello, validTokens, 0x1234)
	f.Add(resp)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test ClientHello parsing
		_, _, _, _ = ProcessClientHello(data, validTokens, 0x5678)

		// Test ServerHello parsing
		_, _, _ = ProcessServerHello(data, clientPriv, decapsKey, nonce)
	})
}

// FuzzReplayCache fuzzes AntiReplayCache with arbitrary nonces and rapid checks.
func FuzzReplayCache(f *testing.F) {
	f.Add([]byte("initial-nonce-1"))
	f.Add(make([]byte, 16))

	f.Fuzz(func(t *testing.T, nonce []byte) {
		cache := NewAntiReplayCache()
		defer cache.Close()
		_ = cache.AddOrCheck(nonce)
		// Double check should detect replay for 16-byte nonces
		if len(nonce) == 16 {
			replayed := cache.AddOrCheck(nonce)
			if !replayed {
				t.Fatalf("Expected replayed=true on second call for %x", nonce)
			}
		}
	})
}
