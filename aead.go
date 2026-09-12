package crypto

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrInvalidAEADAuth is returned when ChaCha20-Poly1305 authentication fails.
	ErrInvalidAEADAuth = errors.New("crypto: AEAD authentication verification failed")

	// ErrCorruptWireFrame is returned when a wire frame has an invalid size or structure.
	ErrCorruptWireFrame = errors.New("crypto: wire frame corrupted or invalid size")

	// ErrKeyExhaustion is returned or logged when the 64-bit nonce counter reaches exhaustion.
	ErrKeyExhaustion = errors.New("crypto: AEAD 64-bit nonce counter overflow - key exhaustion protection")
)

// ShardAEAD provides authenticated encryption with associated data (AEAD)
// using ChaCha20-Poly1305 (RFC 8439) with deterministic monotonic nonces,
// constant wire framing (1372 bytes), and key exhaustion protection.
type ShardAEAD struct {
	aead    cipher.AEAD
	salt    [4]byte
	counter atomic.Uint64
}

// NewShardAEAD creates a new ChaCha20-Poly1305 AEAD cipher instance from a 32-byte key.
func NewShardAEAD(key []byte) (*ShardAEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("crypto: invalid key size for ChaCha20-Poly1305 (expected %d, got %d)",
			chacha20poly1305.KeySize, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to initialize ChaCha20-Poly1305: %w", err)
	}

	h := sha256.Sum256(key)
	var salt [4]byte
	copy(salt[:], h[:4])

	sa := &ShardAEAD{
		aead: aead,
		salt: salt,
	}
	sa.counter.Store(1)
	return sa, nil
}

// DeriveAEADKeyFromSecret derives a 32-byte ChaCha20-Poly1305 key from an arbitrary shared secret
// (such as a 256-bit Post-Quantum ML-KEM-768 / X25519 shared secret).
func DeriveAEADKeyFromSecret(secret []byte) []byte {
	h := sha256.New()
	h.Write([]byte("vectis-aead-chacha20-poly1305-v1-salt:"))
	h.Write(secret)
	return h.Sum(nil)
}

// DeriveDirectionalAEADKeys derives two independent 32-byte ChaCha20-Poly1305 keys from a shared secret:
// c2sKey for Client -> Server traffic and s2cKey for Server -> Client traffic.
// This prevents nonce collisions between peers communicating with identical counter sequences.
func DeriveDirectionalAEADKeys(secret []byte) (c2sKey, s2cKey []byte) {
	h1 := sha256.New()
	h1.Write([]byte("vectis-aead-c2s-v1:"))
	h1.Write(secret)
	c2sKey = h1.Sum(nil)

	h2 := sha256.New()
	h2.Write([]byte("vectis-aead-s2c-v1:"))
	h2.Write(secret)
	s2cKey = h2.Sum(nil)

	return c2sKey, s2cKey
}

// DeriveAEADKey derives a 32-byte ChaCha20-Poly1305 key from a 64-bit session seed.
func DeriveAEADKey(seed uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], seed)
	return DeriveAEADKeyFromSecret(buf[:])
}

// SealFrame encrypts and authenticates a 1344-byte plaintext into dst (1372 bytes).
// Format: [12 bytes Nonce (4B salt + 8B monotonic counter)] [1344 bytes Ciphertext] [16 bytes Poly1305 Tag].
// Zero OS system calls, zero kernel entropy pool contention.
func (a *ShardAEAD) SealFrame(dst, plaintext []byte) []byte {
	if len(plaintext) != DefaultPlaintextFrameSize {
		if len(plaintext) < DefaultPlaintextFrameSize {
			padBuf := GetPlaintextBuffer()
			copy(padBuf[:len(plaintext)], plaintext)
			Zeroize(padBuf[len(plaintext):DefaultPlaintextFrameSize])
			plaintext = padBuf[:DefaultPlaintextFrameSize]
			defer PutPlaintextBuffer(padBuf)
		} else {
			plaintext = plaintext[:DefaultPlaintextFrameSize]
		}
	}

	if cap(dst) < ConstantWireFrameSize {
		dst = make([]byte, ConstantWireFrameSize)
	} else {
		dst = dst[:ConstantWireFrameSize]
	}

	nonce := dst[:chacha20poly1305.NonceSize]
	cnt := a.counter.Add(1)
	if cnt == 0 {
		panic("crypto: AEAD 64-bit nonce counter overflow - key exhaustion protection")
	}
	copy(nonce[0:4], a.salt[:])
	binary.BigEndian.PutUint64(nonce[4:12], cnt)

	return a.aead.Seal(dst[:chacha20poly1305.NonceSize], nonce, plaintext, nil)
}

// OpenFrame decrypts and authenticates a 1372-byte sealed wire frame into dst (1344 bytes).
func (a *ShardAEAD) OpenFrame(dst, wireFrame []byte) ([]byte, error) {
	if len(wireFrame) != ConstantWireFrameSize {
		return nil, ErrCorruptWireFrame
	}

	nonce := wireFrame[:chacha20poly1305.NonceSize]
	ciphertextAndTag := wireFrame[chacha20poly1305.NonceSize:]

	var out []byte
	if cap(dst) >= DefaultPlaintextFrameSize {
		out = dst[:0]
	}

	plaintext, err := a.aead.Open(out, nonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, ErrInvalidAEADAuth
	}
	if len(plaintext) != DefaultPlaintextFrameSize {
		return nil, ErrCorruptWireFrame
	}
	return plaintext, nil
}

// Seal encrypts and authenticates an arbitrary-length plaintext message.
// Wire format: [12 bytes Nonce (4B salt + 8B counter)] [Ciphertext] [16 bytes Tag].
func (a *ShardAEAD) Seal(dst, plaintext, additionalData []byte) []byte {
	totalLen := chacha20poly1305.NonceSize + len(plaintext) + chacha20poly1305.Overhead
	if cap(dst) < totalLen {
		dst = make([]byte, totalLen)
	} else {
		dst = dst[:totalLen]
	}

	nonce := dst[:chacha20poly1305.NonceSize]
	cnt := a.counter.Add(1)
	if cnt == 0 {
		panic("crypto: AEAD 64-bit nonce counter overflow - key exhaustion protection")
	}
	copy(nonce[0:4], a.salt[:])
	binary.BigEndian.PutUint64(nonce[4:12], cnt)

	return a.aead.Seal(dst[:chacha20poly1305.NonceSize], nonce, plaintext, additionalData)
}

// Open decrypts and authenticates a variable-length message previously sealed with Seal.
func (a *ShardAEAD) Open(dst, sealedPacket, additionalData []byte) ([]byte, error) {
	minLen := chacha20poly1305.NonceSize + chacha20poly1305.Overhead
	if len(sealedPacket) < minLen {
		return nil, ErrCorruptWireFrame
	}

	nonce := sealedPacket[:chacha20poly1305.NonceSize]
	ciphertextAndTag := sealedPacket[chacha20poly1305.NonceSize:]

	var out []byte
	if dst != nil {
		out = dst[:0]
	}

	plaintext, err := a.aead.Open(out, nonce, ciphertextAndTag, additionalData)
	if err != nil {
		return nil, ErrInvalidAEADAuth
	}
	return plaintext, nil
}

// CurrentCounter returns the current 64-bit nonce counter value.
func (a *ShardAEAD) CurrentCounter() uint64 {
	return a.counter.Load()
}

// Salt returns the 4-byte salt derived from the AEAD key.
func (a *ShardAEAD) Salt() [4]byte {
	return a.salt
}

// SetCounterForTesting allows testing rollover protection and edge cases.
func (a *ShardAEAD) SetCounterForTesting(val uint64) {
	a.counter.Store(val)
}
