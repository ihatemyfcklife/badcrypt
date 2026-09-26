package badcrypt

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var (
	// ErrInvalidAEADAuth is returned when ChaCha20-Poly1305 authentication fails.
	ErrInvalidAEADAuth = errors.New("badcrypt: AEAD authentication verification failed")

	// ErrCorruptWireFrame is returned when a wire frame has an invalid size or structure.
	ErrCorruptWireFrame = errors.New("badcrypt: wire frame corrupted or invalid size")

	// ErrKeyExhaustion is returned when the 64-bit nonce counter reaches exhaustion.
	ErrKeyExhaustion = errors.New("badcrypt: AEAD 64-bit nonce counter overflow - key exhaustion protection")

	// ErrPayloadTooLarge is returned when plaintext exceeds the constant frame size.
	ErrPayloadTooLarge = errors.New("badcrypt: plaintext payload exceeds maximum calibrated frame size")

	// ErrPayloadSizeMismatch is returned when SealFrame is called with a plaintext length
	// that does not exactly match DefaultPlaintextFrameSize (1344 bytes).
	// For variable-length data, use Seal / Open.
	ErrPayloadSizeMismatch = errors.New("badcrypt: plaintext payload must be exactly calibrated frame size (1344 bytes); use Seal/Open for variable-length payloads")

	// ErrReplayedPacket is returned when a duplicate or out-of-window packet sequence number is received.
	ErrReplayedPacket = errors.New("badcrypt: replayed or expired packet sequence number detected")

	// ErrInvalidSessionID is returned when a wire frame's session ID does not match the active session.
	ErrInvalidSessionID = errors.New("badcrypt: wire frame session ID mismatch")

	// ErrInvalidBufferOverlap is returned when dst and src slices overlap in memory inexactly,
	// violating the safety guarantees required to prevent memory corruption or panics.
	ErrInvalidBufferOverlap = errors.New("badcrypt: invalid buffer overlap between destination and source")

	// ErrNilAEAD is returned when an AEAD operation is called on a nil ShardAEAD instance.
	ErrNilAEAD = errors.New("badcrypt: nil ShardAEAD instance")
)

const (
	replayWindowSize = 256
	bitmapWords      = replayWindowSize / 64 // 4 words of 64-bits
)

// antiReplayWindow implements an RFC 6479 compliant 256-packet sliding window.
type antiReplayWindow struct {
	mu         sync.Mutex
	maxCounter uint64
	bitmap     [bitmapWords]uint64
}

// check verifies if seqNum is fresh and within the sliding window without modifying state.
func (w *antiReplayWindow) check(seqNum uint64) error {
	if w == nil || seqNum == 0 {
		return ErrReplayedPacket
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if seqNum > w.maxCounter {
		return nil // Fresh packet advancing the window
	}

	diff := w.maxCounter - seqNum
	if diff >= replayWindowSize {
		return ErrReplayedPacket // Too old, fallen off the window
	}

	word := diff / 64
	bit := diff % 64
	if (w.bitmap[word] & (uint64(1) << bit)) != 0 {
		return ErrReplayedPacket // Duplicate packet
	}

	return nil
}

// mark registers seqNum in the sliding window after successful cryptographic authentication.
// It returns ErrReplayedPacket if seqNum was already marked concurrently by another goroutine.
func (w *antiReplayWindow) mark(seqNum uint64) error {
	if w == nil || seqNum == 0 {
		return ErrReplayedPacket
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if seqNum > w.maxCounter {
		diff := seqNum - w.maxCounter
		if diff >= replayWindowSize {
			clear(w.bitmap[:])
		} else {
			w.shiftLeft(diff)
		}
		w.maxCounter = seqNum
		w.bitmap[0] |= 1 // offset 0
		return nil
	}

	diff := w.maxCounter - seqNum
	if diff >= replayWindowSize {
		return ErrReplayedPacket
	}

	word := diff / 64
	bit := diff % 64
	if (w.bitmap[word] & (uint64(1) << bit)) != 0 {
		return ErrReplayedPacket // Concurrent replay detected!
	}
	w.bitmap[word] |= (uint64(1) << bit)
	return nil
}

func (w *antiReplayWindow) shiftLeft(diff uint64) {
	if w == nil {
		return
	}
	words := int(diff / 64)
	bits := diff % 64

	if words > 0 {
		for i := bitmapWords - 1; i >= 0; i-- {
			if i >= words {
				w.bitmap[i] = w.bitmap[i-words]
			} else {
				w.bitmap[i] = 0
			}
		}
	}

	if bits > 0 {
		var carry uint64
		for i := 0; i < bitmapWords; i++ {
			newCarry := w.bitmap[i] >> (64 - bits)
			w.bitmap[i] = (w.bitmap[i] << bits) | carry
			carry = newCarry
		}
	}
}

// ShardAEAD provides authenticated encryption with associated data (AEAD)
// using ChaCha20-Poly1305 (RFC 8439), deterministic monotonic nonces,
// anti-replay sliding window verification, session multiplexing, and key exhaustion protection.
type ShardAEAD struct {
	aead       cipher.AEAD
	sessionID  atomic.Uint64
	counter    atomic.Uint64
	recvWindow antiReplayWindow
}

// NewShardAEAD creates a new ChaCha20-Poly1305 AEAD cipher instance from a 32-byte key.
func NewShardAEAD(key []byte) (*ShardAEAD, error) {
	return NewShardAEADWithSession(key, 0)
}

// NewShardAEADWithSession creates an AEAD instance bound to a specific session ID for network multiplexing.
func NewShardAEADWithSession(key []byte, sessionID uint64) (*ShardAEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("crypto: invalid key size for ChaCha20-Poly1305 (expected %d, got %d)",
			chacha20poly1305.KeySize, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to initialize ChaCha20-Poly1305: %w", err)
	}

	sa := &ShardAEAD{
		aead: aead,
	}
	sa.sessionID.Store(sessionID)
	sa.counter.Store(0)
	return sa, nil
}

// SetSessionID atomically updates the session identifier associated with this AEAD instance.
func (a *ShardAEAD) SetSessionID(sessionID uint64) {
	if a == nil {
		return
	}
	a.sessionID.Store(sessionID)
}

// SessionID atomically returns the current session identifier.
func (a *ShardAEAD) SessionID() uint64 {
	if a == nil {
		return 0
	}
	return a.sessionID.Load()
}

// Close securely wipes the AEAD instance, latches its counter to prevent reuse, and hermetically seals the replay window.
func (a *ShardAEAD) Close() {
	if a == nil {
		return
	}
	a.counter.Store(MaxAllowedCounter)
	a.sessionID.Store(0)
	a.recvWindow.mu.Lock()
	for i := range a.recvWindow.bitmap {
		a.recvWindow.bitmap[i] = math.MaxUint64
	}
	a.recvWindow.maxCounter = math.MaxUint64
	a.recvWindow.mu.Unlock()
}

// DeriveAEADKeyFromSecret derives a 32-byte ChaCha20-Poly1305 key using HKDF-SHA256 (RFC 5869).
func DeriveAEADKeyFromSecret(secret []byte) []byte {
	key := make([]byte, chacha20poly1305.KeySize)
	kdf := hkdf.New(sha256.New, secret, nil, []byte("badcrypt-aead-chacha20-poly1305-v1-salt"))
	_, _ = io.ReadFull(kdf, key)
	return key
}

// DeriveDirectionalAEADKeys derives two independent 32-byte ChaCha20-Poly1305 keys from a shared secret:
// c2sKey for Client -> Server traffic and s2cKey for Server -> Client traffic using HKDF-SHA256 (RFC 5869).
func DeriveDirectionalAEADKeys(secret []byte) (c2sKey, s2cKey []byte) {
	c2sKey = make([]byte, chacha20poly1305.KeySize)
	s2cKey = make([]byte, chacha20poly1305.KeySize)

	kdfC2S := hkdf.New(sha256.New, secret, nil, []byte("badcrypt-aead-c2s-v1"))
	_, _ = io.ReadFull(kdfC2S, c2sKey)

	kdfS2C := hkdf.New(sha256.New, secret, nil, []byte("badcrypt-aead-s2c-v1"))
	_, _ = io.ReadFull(kdfS2C, s2cKey)

	return c2sKey, s2cKey
}

// DeriveAEADKey derives a 32-byte ChaCha20-Poly1305 key from a 64-bit session seed using HKDF-SHA256.
func DeriveAEADKey(seed uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], seed)
	return DeriveAEADKeyFromSecret(buf[:])
}

// MaxAllowedCounter defines the strict upper limit for the 64-bit counter before exhaustion.
const MaxAllowedCounter = math.MaxUint64 - 1

// nextCounter atomically reserves the next sequence number or returns ErrKeyExhaustion.
// It latches permanently upon reaching MaxAllowedCounter to prevent two-time pad key compromise.
func (a *ShardAEAD) nextCounter() (uint64, error) {
	if a == nil {
		return 0, ErrNilAEAD
	}
	for {
		cur := a.counter.Load()
		if cur >= MaxAllowedCounter {
			return 0, ErrKeyExhaustion
		}
		if a.counter.CompareAndSwap(cur, cur+1) {
			return cur + 1, nil
		}
	}
}

// SealFrame encrypts and authenticates a calibrated plaintext payload into dst (1380 bytes).
// Wire format: [8B SessionID] [12B Nonce (4B zeros + 8B counter)] [1344B Ciphertext] [16B Poly1305 Tag].
// The SessionID is authenticated as Additional Authenticated Data (AAD).
//
// In-place encryption is fully supported: if &dst[0] == &plaintext[0] and cap(dst) >= ConstantWireFrameSize,
// the plaintext is shifted to dst[20:1364] via runtime memmove before sealing, preventing allocation.
// Slices with unaligned memory overlap return ErrInvalidBufferOverlap.
func (a *ShardAEAD) SealFrame(dst, plaintext []byte) ([]byte, error) {
	if a == nil {
		return nil, ErrNilAEAD
	}
	if len(plaintext) != DefaultPlaintextFrameSize {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d",
			ErrPayloadSizeMismatch, len(plaintext), DefaultPlaintextFrameSize)
	}

	headerOffset := SessionIDSize + chacha20poly1305.NonceSize

	var targetDst []byte
	if cap(dst) >= ConstantWireFrameSize {
		targetDst = dst[:ConstantWireFrameSize]
	} else if anyOverlap(dst, plaintext) {
		return nil, ErrInvalidBufferOverlap
	}

	overlap := checkBufferOverlap(targetDst, plaintext, headerOffset, true)
	switch overlap {
	case overlapDisjoint:
		if targetDst == nil {
			dst = make([]byte, ConstantWireFrameSize)
		} else {
			dst = targetDst
		}
	case overlapExactStart:
		// Plaintext is at dst[0:1344]. Shift plaintext to dst[20:1364] using runtime memmove
		// to leave room for the 20-byte wire header, then encrypt in-place.
		dst = targetDst
		copy(dst[headerOffset:headerOffset+DefaultPlaintextFrameSize], plaintext)
		plaintext = dst[headerOffset : headerOffset+DefaultPlaintextFrameSize]
	case overlapExactOffset:
		// Plaintext is already positioned at dst[20:1364]. Encrypt in-place directly.
		dst = targetDst
	case overlapUnaligned:
		return nil, ErrInvalidBufferOverlap
	}

	// 1. SessionID header (8 bytes)
	binary.BigEndian.PutUint64(dst[:SessionIDSize], a.sessionID.Load())
	aad := dst[:SessionIDSize]

	// 2. Nonce (12 bytes)
	nonce := dst[SessionIDSize:headerOffset]
	cnt, err := a.nextCounter()
	if err != nil {
		return nil, err
	}
	clear(nonce[0:4])
	binary.BigEndian.PutUint64(nonce[4:12], cnt)

	// 3. Seal with AAD bound to SessionID
	return a.aead.Seal(dst[:headerOffset], nonce, plaintext, aad), nil
}

// OpenFrame decrypts and authenticates a 1380-byte sealed wire frame into dst (1344 bytes).
// Replay protection: verifies sequence counter against the sliding window.
//
// In-place decryption is fully supported: if &dst[0] == &wireFrame[0] or &dst[0] == &wireFrame[20],
// the payload is decrypted directly in-place and aligned without heap allocations.
// Slices with unaligned memory overlap return ErrInvalidBufferOverlap.
func (a *ShardAEAD) OpenFrame(dst, wireFrame []byte) ([]byte, error) {
	if a == nil {
		return nil, ErrNilAEAD
	}
	if len(wireFrame) != ConstantWireFrameSize {
		return nil, ErrCorruptWireFrame
	}

	headerOffset := SessionIDSize + chacha20poly1305.NonceSize

	var targetDst []byte
	if cap(dst) >= DefaultPlaintextFrameSize {
		targetDst = dst[:DefaultPlaintextFrameSize]
	} else if anyOverlap(dst, wireFrame) {
		return nil, ErrInvalidBufferOverlap
	}

	overlap := checkBufferOverlap(targetDst, wireFrame, headerOffset, false)
	if overlap == overlapUnaligned {
		return nil, ErrInvalidBufferOverlap
	}

	rxSessionID := binary.BigEndian.Uint64(wireFrame[:SessionIDSize])
	if rxSessionID != a.sessionID.Load() {
		return nil, ErrInvalidSessionID
	}
	aad := wireFrame[:SessionIDSize]

	nonce := wireFrame[SessionIDSize:headerOffset]
	ciphertextAndTag := wireFrame[headerOffset:]

	// Validate nonce prefix in constant time (RFC 8439 / WireGuard 32-bit zero prefix)
	var zeroPrefix [4]byte
	if subtle.ConstantTimeCompare(nonce[:4], zeroPrefix[:]) != 1 {
		return nil, ErrInvalidAEADAuth
	}

	// Anti-replay check prior to decryption
	cnt := binary.BigEndian.Uint64(nonce[4:12])
	if err := a.recvWindow.check(cnt); err != nil {
		return nil, err
	}

	switch overlap {
	case overlapExactStart:
		// Decrypt in-place over ciphertext buffer at wireFrame[20:]
		plaintext, err := a.aead.Open(wireFrame[headerOffset:headerOffset], nonce, ciphertextAndTag, aad)
		if err != nil {
			return nil, ErrInvalidAEADAuth
		}
		if len(plaintext) != DefaultPlaintextFrameSize {
			Zeroize(plaintext)
			return nil, ErrCorruptWireFrame
		}
		if err := a.recvWindow.mark(cnt); err != nil {
			Zeroize(plaintext)
			return nil, err
		}
		// Shift decrypted plaintext back to targetDst (offset 0)
		copy(targetDst, plaintext)
		Zeroize(wireFrame[DefaultPlaintextFrameSize:])
		return targetDst, nil

	case overlapExactOffset:
		// Decrypt in-place into wireFrame[20:1364] directly
		plaintext, err := a.aead.Open(wireFrame[headerOffset:headerOffset], nonce, ciphertextAndTag, aad)
		if err != nil {
			return nil, ErrInvalidAEADAuth
		}
		if len(plaintext) != DefaultPlaintextFrameSize {
			Zeroize(plaintext)
			return nil, ErrCorruptWireFrame
		}
		if err := a.recvWindow.mark(cnt); err != nil {
			Zeroize(plaintext)
			return nil, err
		}
		Zeroize(wireFrame[headerOffset+DefaultPlaintextFrameSize:])
		return plaintext, nil

	default: // overlapDisjoint
		var out []byte
		if targetDst != nil {
			out = targetDst[:0]
		}
		plaintext, err := a.aead.Open(out, nonce, ciphertextAndTag, aad)
		if err != nil {
			return nil, ErrInvalidAEADAuth
		}
		if len(plaintext) != DefaultPlaintextFrameSize {
			Zeroize(plaintext)
			return nil, ErrCorruptWireFrame
		}
		if err := a.recvWindow.mark(cnt); err != nil {
			Zeroize(plaintext)
			return nil, err
		}
		return plaintext, nil
	}
}

// Seal encrypts and authenticates an arbitrary-length plaintext message.
// Wire format: [8B SessionID] [12B Nonce (4B zeros + 8B counter)] [Ciphertext] [16B Tag].
//
// In-place encryption is supported if &dst[0] == &plaintext[0] with sufficient capacity.
func (a *ShardAEAD) Seal(dst, plaintext, additionalData []byte) ([]byte, error) {
	if a == nil {
		return nil, ErrNilAEAD
	}
	headerOffset := SessionIDSize + chacha20poly1305.NonceSize
	totalLen := headerOffset + len(plaintext) + chacha20poly1305.Overhead

	checkDst := dst
	if len(checkDst) < totalLen && cap(checkDst) >= totalLen {
		checkDst = checkDst[:totalLen]
	}
	if anyOverlap(checkDst, additionalData) {
		return nil, ErrInvalidBufferOverlap
	}

	var targetDst []byte
	if cap(dst) >= totalLen {
		targetDst = dst[:totalLen]
	} else if anyOverlap(dst, plaintext) {
		return nil, ErrInvalidBufferOverlap
	}

	overlap := checkBufferOverlap(targetDst, plaintext, headerOffset, true)
	switch overlap {
	case overlapDisjoint:
		if targetDst == nil {
			dst = make([]byte, totalLen)
		} else {
			dst = targetDst
		}
	case overlapExactStart:
		dst = targetDst
		copy(dst[headerOffset:headerOffset+len(plaintext)], plaintext)
		plaintext = dst[headerOffset : headerOffset+len(plaintext)]
	case overlapExactOffset:
		dst = targetDst
	case overlapUnaligned:
		return nil, ErrInvalidBufferOverlap
	}

	binary.BigEndian.PutUint64(dst[:SessionIDSize], a.sessionID.Load())

	nonce := dst[SessionIDSize:headerOffset]
	cnt, err := a.nextCounter()
	if err != nil {
		return nil, err
	}
	clear(nonce[0:4])
	binary.BigEndian.PutUint64(nonce[4:12], cnt)

	// Combine SessionID with user additional data (zero-alloc via pooled buffer for metadata <= 120 bytes)
	var fullAAD []byte
	var aadBuf *[maxStackAADSize]byte
	if len(additionalData) == 0 {
		fullAAD = dst[:SessionIDSize]
	} else if len(additionalData) <= 120 {
		aadBuf = getAADBuffer()
		defer putAADBuffer(aadBuf)
		copy(aadBuf[:SessionIDSize], dst[:SessionIDSize])
		copy(aadBuf[SessionIDSize:], additionalData)
		fullAAD = aadBuf[:SessionIDSize+len(additionalData)]
	} else {
		fullAAD = make([]byte, SessionIDSize+len(additionalData))
		copy(fullAAD[:SessionIDSize], dst[:SessionIDSize])
		copy(fullAAD[SessionIDSize:], additionalData)
	}

	return a.aead.Seal(dst[:headerOffset], nonce, plaintext, fullAAD), nil
}

// Open decrypts and authenticates a variable-length message previously sealed with Seal.
// In-place decryption is supported if &dst[0] == &sealedPacket[0] or &dst[0] == &sealedPacket[20].
func (a *ShardAEAD) Open(dst, sealedPacket, additionalData []byte) ([]byte, error) {
	if a == nil {
		return nil, ErrNilAEAD
	}
	headerOffset := SessionIDSize + chacha20poly1305.NonceSize
	minLen := headerOffset + chacha20poly1305.Overhead
	if len(sealedPacket) < minLen {
		return nil, ErrCorruptWireFrame
	}

	expectedPlainLen := len(sealedPacket) - headerOffset - chacha20poly1305.Overhead

	checkDst := dst
	if len(checkDst) < expectedPlainLen && cap(checkDst) >= expectedPlainLen {
		checkDst = checkDst[:expectedPlainLen]
	}
	if anyOverlap(checkDst, additionalData) {
		return nil, ErrInvalidBufferOverlap
	}

	var targetDst []byte
	if cap(dst) >= expectedPlainLen {
		targetDst = dst[:expectedPlainLen]
	} else if anyOverlap(dst, sealedPacket) {
		return nil, ErrInvalidBufferOverlap
	}

	overlap := checkBufferOverlap(targetDst, sealedPacket, headerOffset, false)
	if overlap == overlapUnaligned {
		return nil, ErrInvalidBufferOverlap
	}

	rxSessionID := binary.BigEndian.Uint64(sealedPacket[:SessionIDSize])
	if rxSessionID != a.sessionID.Load() {
		return nil, ErrInvalidSessionID
	}

	nonce := sealedPacket[SessionIDSize:headerOffset]
	ciphertextAndTag := sealedPacket[headerOffset:]

	var zeroPrefix [4]byte
	if subtle.ConstantTimeCompare(nonce[:4], zeroPrefix[:]) != 1 {
		return nil, ErrInvalidAEADAuth
	}

	cnt := binary.BigEndian.Uint64(nonce[4:12])
	if err := a.recvWindow.check(cnt); err != nil {
		return nil, err
	}

	// Combine SessionID with user additional data (zero-alloc via pooled buffer for metadata <= 120 bytes)
	var fullAAD []byte
	var aadBuf *[maxStackAADSize]byte
	if len(additionalData) == 0 {
		fullAAD = sealedPacket[:SessionIDSize]
	} else if len(additionalData) <= 120 {
		aadBuf = getAADBuffer()
		defer putAADBuffer(aadBuf)
		copy(aadBuf[:SessionIDSize], sealedPacket[:SessionIDSize])
		copy(aadBuf[SessionIDSize:], additionalData)
		fullAAD = aadBuf[:SessionIDSize+len(additionalData)]
	} else {
		fullAAD = make([]byte, SessionIDSize+len(additionalData))
		copy(fullAAD[:SessionIDSize], sealedPacket[:SessionIDSize])
		copy(fullAAD[SessionIDSize:], additionalData)
	}

	switch overlap {
	case overlapExactStart:
		plaintext, err := a.aead.Open(sealedPacket[headerOffset:headerOffset], nonce, ciphertextAndTag, fullAAD)
		if err != nil {
			return nil, ErrInvalidAEADAuth
		}
		if err := a.recvWindow.mark(cnt); err != nil {
			Zeroize(plaintext)
			return nil, err
		}
		copy(targetDst, plaintext)
		Zeroize(sealedPacket[expectedPlainLen:])
		return targetDst, nil

	case overlapExactOffset:
		plaintext, err := a.aead.Open(sealedPacket[headerOffset:headerOffset], nonce, ciphertextAndTag, fullAAD)
		if err != nil {
			return nil, ErrInvalidAEADAuth
		}
		if err := a.recvWindow.mark(cnt); err != nil {
			Zeroize(plaintext)
			return nil, err
		}
		Zeroize(sealedPacket[headerOffset+expectedPlainLen:])
		return plaintext, nil

	default: // overlapDisjoint
		var out []byte
		if targetDst != nil {
			out = targetDst[:0]
		}
		plaintext, err := a.aead.Open(out, nonce, ciphertextAndTag, fullAAD)
		if err != nil {
			return nil, ErrInvalidAEADAuth
		}
		if err := a.recvWindow.mark(cnt); err != nil {
			Zeroize(plaintext)
			return nil, err
		}
		return plaintext, nil
	}
}

// CurrentCounter returns the current 64-bit nonce counter value.
func (a *ShardAEAD) CurrentCounter() uint64 {
	if a == nil {
		return 0
	}
	return a.counter.Load()
}

// Salt returns the 4-byte prefix (always 4 zero bytes for WireGuard/RFC 8439 compatibility).
func (a *ShardAEAD) Salt() [4]byte {
	return [4]byte{}
}

// SetCounterForTesting allows testing rollover protection and edge cases.
func (a *ShardAEAD) SetCounterForTesting(val uint64) {
	if a == nil {
		return
	}
	a.counter.Store(val)
}
