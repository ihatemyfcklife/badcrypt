package crypto

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"
)

func TestShardAEAD_SealAndOpenFrame(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	aead, err := NewShardAEAD(key)
	if err != nil {
		t.Fatalf("NewShardAEAD failed: %v", err)
	}

	plaintext := make([]byte, DefaultPlaintextFrameSize)
	copy(plaintext, []byte("Vectis Zero-Loss High-Speed Network Engine"))

	dst := make([]byte, ConstantWireFrameSize)
	sealed := aead.SealFrame(dst, plaintext)
	if len(sealed) != ConstantWireFrameSize {
		t.Fatalf("expected sealed size %d, got %d", ConstantWireFrameSize, len(sealed))
	}

	openDst := make([]byte, DefaultPlaintextFrameSize)
	decrypted, err := aead.OpenFrame(openDst, sealed)
	if err != nil {
		t.Fatalf("OpenFrame failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted plaintext mismatch")
	}

	// Test OpenFrame with nil buffer
	decNil, err := aead.OpenFrame(nil, sealed)
	if err != nil || !bytes.Equal(decNil, plaintext) {
		t.Fatal("OpenFrame with nil buffer failed")
	}

	// Tamper test: flip one bit in ciphertext
	sealed[50] ^= 0x01
	_, err = aead.OpenFrame(nil, sealed)
	if err != ErrInvalidAEADAuth {
		t.Fatalf("expected ErrInvalidAEADAuth on tampered frame, got %v", err)
	}
}

func TestShardAEAD_Padding(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	aead, err := NewShardAEAD(key)
	if err != nil {
		t.Fatalf("NewShardAEAD failed: %v", err)
	}

	// Short plaintext: should be padded automatically to DefaultPlaintextFrameSize
	shortPlain := []byte("short payload requiring zero-padding")
	sealed := aead.SealFrame(nil, shortPlain)
	if len(sealed) != ConstantWireFrameSize {
		t.Fatalf("expected wire size %d, got %d", ConstantWireFrameSize, len(sealed))
	}

	decrypted, err := aead.OpenFrame(nil, sealed)
	if err != nil {
		t.Fatalf("OpenFrame on padded frame failed: %v", err)
	}
	if len(decrypted) != DefaultPlaintextFrameSize {
		t.Fatalf("expected decrypted size %d, got %d", DefaultPlaintextFrameSize, len(decrypted))
	}
	if !bytes.HasPrefix(decrypted, shortPlain) {
		t.Fatal("decrypted padded frame does not start with shortPlain")
	}
}

func TestShardAEAD_VariablePayload(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	aead, err := NewShardAEAD(key)
	if err != nil {
		t.Fatalf("NewShardAEAD failed: %v", err)
	}

	msg := []byte("arbitrary payload length test for production readiness")
	aad := []byte("metadata-context-id-42")

	sealed := aead.Seal(nil, msg, aad)
	if len(sealed) != NonceSize+len(msg)+Overhead {
		t.Fatalf("unexpected sealed length: %d", len(sealed))
	}

	decrypted, err := aead.Open(nil, sealed, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(decrypted, msg) {
		t.Fatalf("decrypted mismatch: expected %q, got %q", msg, decrypted)
	}

	// AAD mismatch
	_, err = aead.Open(nil, sealed, []byte("wrong-aad"))
	if err != ErrInvalidAEADAuth {
		t.Fatalf("expected ErrInvalidAEADAuth on wrong AAD, got %v", err)
	}
}

func TestShardAEAD_CorruptWireFrame(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, _ := NewShardAEAD(key)

	// Invalid wire frame sizes
	_, err := aead.OpenFrame(nil, []byte("too-short"))
	if err != ErrCorruptWireFrame {
		t.Fatalf("expected ErrCorruptWireFrame for short frame, got %v", err)
	}

	_, err = aead.Open(nil, []byte("short"), nil)
	if err != ErrCorruptWireFrame {
		t.Fatalf("expected ErrCorruptWireFrame for short packet, got %v", err)
	}
}

func TestShardAEAD_InvalidKey(t *testing.T) {
	_, err := NewShardAEAD([]byte("short-key"))
	if err == nil {
		t.Fatal("expected error on invalid key size, got nil")
	}
}

func TestShardAEAD_Derivations(t *testing.T) {
	secret := []byte("shared-secret-12345678901234567890")
	c2s, s2c := DeriveDirectionalAEADKeys(secret)
	if len(c2s) != 32 || len(s2c) != 32 {
		t.Fatalf("expected 32-byte directional keys, got %d and %d", len(c2s), len(s2c))
	}
	if bytes.Equal(c2s, s2c) {
		t.Fatal("c2s and s2c keys must be cryptographically distinct")
	}

	key1 := DeriveAEADKeyFromSecret(secret)
	key2 := DeriveAEADKeyFromSecret(secret)
	if !bytes.Equal(key1, key2) {
		t.Fatal("DeriveAEADKeyFromSecret must be deterministic")
	}

	seedKey := DeriveAEADKey(42)
	if len(seedKey) != 32 {
		t.Fatalf("expected 32-byte key from seed, got %d", len(seedKey))
	}
}

func TestShardAEAD_ConcurrentSealing(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, _ := NewShardAEAD(key)

	const goroutines = 20
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	plain := make([]byte, DefaultPlaintextFrameSize)
	copy(plain, []byte("concurrent payload"))

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				dst := make([]byte, ConstantWireFrameSize)
				sealed := aead.SealFrame(dst, plain)
				decrypted, err := aead.OpenFrame(nil, sealed)
				if err != nil || !bytes.Equal(decrypted, plain) {
					t.Errorf("concurrent seal/open failed: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()
	if aead.CurrentCounter() <= goroutines*iterations {
		t.Fatalf("expected counter > %d, got %d", goroutines*iterations, aead.CurrentCounter())
	}
}

func TestBufferPools(t *testing.T) {
	pBuf := GetPlaintextBuffer()
	if len(pBuf) != DefaultPlaintextFrameSize {
		t.Fatalf("unexpected plaintext buffer size %d", len(pBuf))
	}
	copy(pBuf, []byte("sensitive plaintext"))
	PutPlaintextBuffer(pBuf)

	wBuf := GetWireFrameBuffer()
	if len(wBuf) != ConstantWireFrameSize {
		t.Fatalf("unexpected wire buffer size %d", len(wBuf))
	}
	copy(wBuf, []byte("sensitive wire frame"))
	PutWireFrameBuffer(wBuf)
}
