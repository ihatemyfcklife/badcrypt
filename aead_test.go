package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
)

func TestShardAEAD_SealAndOpenFrame(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	const sessionID uint64 = 0xabcdef0123456789
	aead, err := NewShardAEADWithSession(key, sessionID)
	if err != nil {
		t.Fatalf("NewShardAEADWithSession failed: %v", err)
	}

	plaintext := make([]byte, DefaultPlaintextFrameSize)
	copy(plaintext, []byte("Vectis Zero-Loss High-Speed Network Engine"))

	dst := make([]byte, ConstantWireFrameSize)
	sealed, err := aead.SealFrame(dst, plaintext)
	if err != nil {
		t.Fatalf("SealFrame failed: %v", err)
	}
	if len(sealed) != ConstantWireFrameSize {
		t.Fatalf("expected sealed size %d, got %d", ConstantWireFrameSize, len(sealed))
	}

	// Receiver AEAD
	recvAEAD, err := NewShardAEADWithSession(key, sessionID)
	if err != nil {
		t.Fatalf("NewShardAEADWithSession failed: %v", err)
	}

	openDst := make([]byte, DefaultPlaintextFrameSize)
	decrypted, err := recvAEAD.OpenFrame(openDst, sealed)
	if err != nil {
		t.Fatalf("OpenFrame failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted plaintext mismatch")
	}

	// Tamper test: seal a new frame (counter 2) and flip one bit in ciphertext
	sealed2, err := aead.SealFrame(nil, plaintext)
	if err != nil {
		t.Fatalf("SealFrame 2 failed: %v", err)
	}
	sealedTampered := make([]byte, len(sealed2))
	copy(sealedTampered, sealed2)
	sealedTampered[50] ^= 0x01
	_, err = recvAEAD.OpenFrame(nil, sealedTampered)
	if err != ErrInvalidAEADAuth {
		t.Fatalf("expected ErrInvalidAEADAuth on tampered frame, got %v", err)
	}
}

func TestShardAEAD_StrictPlaintextSize(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	aead, err := NewShardAEAD(key)
	if err != nil {
		t.Fatalf("NewShardAEAD failed: %v", err)
	}

	// 1. Short plaintext in SealFrame must be rejected with ErrPayloadSizeMismatch
	shortPlain := []byte("short payload requiring variable length API")
	_, err = aead.SealFrame(nil, shortPlain)
	if !errors.Is(err, ErrPayloadSizeMismatch) {
		t.Fatalf("expected ErrPayloadSizeMismatch for short payload in SealFrame, got %v", err)
	}

	// 2. Oversized plaintext in SealFrame must also be rejected with ErrPayloadSizeMismatch
	oversized := make([]byte, DefaultPlaintextFrameSize+100)
	_, err = aead.SealFrame(nil, oversized)
	if !errors.Is(err, ErrPayloadSizeMismatch) {
		t.Fatalf("expected ErrPayloadSizeMismatch for oversized payload, got %v", err)
	}

	// 3. Exact 1344 bytes must succeed
	exactPlain := make([]byte, DefaultPlaintextFrameSize)
	copy(exactPlain, []byte("exact 1344 bytes payload"))
	sealed, err := aead.SealFrame(nil, exactPlain)
	if err != nil {
		t.Fatalf("SealFrame on exact 1344 bytes failed: %v", err)
	}
	if len(sealed) != ConstantWireFrameSize {
		t.Fatalf("expected wire size %d, got %d", ConstantWireFrameSize, len(sealed))
	}

	recvAEAD, _ := NewShardAEAD(key)
	decrypted, err := recvAEAD.OpenFrame(nil, sealed)
	if err != nil {
		t.Fatalf("OpenFrame on sealed frame failed: %v", err)
	}
	if !bytes.Equal(decrypted, exactPlain) {
		t.Fatal("decrypted payload does not match original plaintext")
	}

	// 4. Short variable-length payload succeeds via Seal / Open
	sealedVar, err := aead.Seal(nil, shortPlain, nil)
	if err != nil {
		t.Fatalf("Seal failed on short variable payload: %v", err)
	}
	decryptedVar, err := recvAEAD.Open(nil, sealedVar, nil)
	if err != nil {
		t.Fatalf("Open failed on short variable payload: %v", err)
	}
	if !bytes.Equal(decryptedVar, shortPlain) {
		t.Fatalf("decrypted variable mismatch: expected %q, got %q", shortPlain, decryptedVar)
	}
}

func TestShardAEAD_SessionIDMismatch(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	sender, _ := NewShardAEADWithSession(key, 0x1111)
	receiver, _ := NewShardAEADWithSession(key, 0x2222)

	plain := make([]byte, DefaultPlaintextFrameSize)
	frame, err := sender.SealFrame(nil, plain)
	if err != nil {
		t.Fatal(err)
	}

	_, err = receiver.OpenFrame(nil, frame)
	if !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("expected ErrInvalidSessionID, got %v", err)
	}
}

func TestShardAEAD_VariablePayload(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	aead, err := NewShardAEAD(key)
	if err != nil {
		t.Fatalf("NewShardAEAD failed: %v", err)
	}
	recvAEAD, _ := NewShardAEAD(key)

	msg := []byte("arbitrary payload length test for production readiness")
	aad := []byte("metadata-context-id-42")

	sealed, err := aead.Seal(nil, msg, aad)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	expectedLen := SessionIDSize + NonceSize + len(msg) + Overhead
	if len(sealed) != expectedLen {
		t.Fatalf("unexpected sealed length: expected %d, got %d", expectedLen, len(sealed))
	}

	decrypted, err := recvAEAD.Open(nil, sealed, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(decrypted, msg) {
		t.Fatalf("decrypted mismatch: expected %q, got %q", msg, decrypted)
	}

	// AAD mismatch: seal a fresh packet (counter 2) so replay window doesn't reject it
	sealed2, err := aead.Seal(nil, msg, aad)
	if err != nil {
		t.Fatalf("Seal 2 failed: %v", err)
	}
	_, err = recvAEAD.Open(nil, sealed2, []byte("wrong-aad"))
	if err != ErrInvalidAEADAuth {
		t.Fatalf("expected ErrInvalidAEADAuth on wrong AAD, got %v", err)
	}

	// Test Seal and Open with preallocated dst and nil additionalData
	preDst := make([]byte, 1000)
	sealedNoAAD, err := aead.Seal(preDst, msg, nil)
	if err != nil {
		t.Fatalf("Seal with preallocated dst failed: %v", err)
	}
	openDst := make([]byte, len(msg))
	decryptedNoAAD, err := recvAEAD.Open(openDst, sealedNoAAD, nil)
	if err != nil {
		t.Fatalf("Open with preallocated dst failed: %v", err)
	}
	if !bytes.Equal(decryptedNoAAD, msg) {
		t.Fatal("decrypted mismatch with nil additionalData")
	}

	// Test Open replay detection
	_, err = recvAEAD.Open(nil, sealedNoAAD, nil)
	if !errors.Is(err, ErrReplayedPacket) {
		t.Fatalf("expected ErrReplayedPacket on duplicate Open call, got %v", err)
	}

	// Test Open session ID mismatch
	diffSessionAEAD, _ := NewShardAEADWithSession(key, 0x9999)
	freshSealed, _ := aead.Seal(nil, msg, nil)
	_, err = diffSessionAEAD.Open(nil, freshSealed, nil)
	if !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("expected ErrInvalidSessionID on mismatched Open session, got %v", err)
	}

	// Test Open salt mismatch
	freshSealed2, _ := aead.Seal(nil, msg, nil)
	tamperedSalt := make([]byte, len(freshSealed2))
	copy(tamperedSalt, freshSealed2)
	tamperedSalt[SessionIDSize] ^= 0xFF // Flip bit in salt
	_, err = recvAEAD.Open(nil, tamperedSalt, nil)
	if !errors.Is(err, ErrInvalidAEADAuth) {
		t.Fatalf("expected ErrInvalidAEADAuth on tampered Open salt, got %v", err)
	}

	// Test OpenFrame salt mismatch
	plain := make([]byte, DefaultPlaintextFrameSize)
	frame, _ := aead.SealFrame(nil, plain)
	tamperedFrameSalt := make([]byte, len(frame))
	copy(tamperedFrameSalt, frame)
	tamperedFrameSalt[SessionIDSize] ^= 0xFF // Flip bit in salt
	_, err = recvAEAD.OpenFrame(nil, tamperedFrameSalt)
	if !errors.Is(err, ErrInvalidAEADAuth) {
		t.Fatalf("expected ErrInvalidAEADAuth on tampered OpenFrame salt, got %v", err)
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

	const goroutines = 10
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	plain := make([]byte, DefaultPlaintextFrameSize)
	copy(plain, []byte("concurrent payload"))

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				dst := make([]byte, ConstantWireFrameSize)
				sealed, err := aead.SealFrame(dst, plain)
				if err != nil {
					t.Errorf("concurrent seal failed: %v", err)
					return
				}
				if len(sealed) != ConstantWireFrameSize {
					t.Errorf("unexpected frame size: %d", len(sealed))
					return
				}
			}
		}()
	}

	wg.Wait()
	if aead.CurrentCounter() != goroutines*iterations {
		t.Fatalf("expected counter == %d, got %d", goroutines*iterations, aead.CurrentCounter())
	}
}

func TestBufferPools_TrueZeroAlloc(t *testing.T) {
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

	// Verify buffer clearing
	reborrowed := GetPlaintextBuffer()
	defer PutPlaintextBuffer(reborrowed)
	for i, b := range reborrowed {
		if b != 0 {
			t.Fatalf("buffer was not properly zeroized at index %d", i)
		}
	}

	// Test undersized buffer returns (should be ignored safely)
	PutPlaintextBuffer([]byte("short"))
	PutWireFrameBuffer([]byte("short"))

	// Test Zeroize on nil / empty
	Zeroize(nil)
	Zeroize([]byte{})
}

func TestShardAEAD_SessionIDAndSaltGetters(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	aead, err := NewShardAEADWithSession(key, 0x11223344)
	if err != nil {
		t.Fatal(err)
	}

	if aead.SessionID() != 0x11223344 {
		t.Fatalf("expected session ID 0x11223344, got %x", aead.SessionID())
	}

	aead.SetSessionID(0x99887766)
	if aead.SessionID() != 0x99887766 {
		t.Fatalf("expected updated session ID 0x99887766, got %x", aead.SessionID())
	}

	salt := aead.Salt()
	if salt != [4]byte{} {
		t.Fatalf("expected zero salt for WireGuard/RFC 8439 privacy, got %x", salt)
	}
}

func TestShardAEAD_AntiReplayWindowInternalBranches(t *testing.T) {
	w := &antiReplayWindow{}

	// seqNum 0 must be rejected
	if err := w.check(0); !errors.Is(err, ErrReplayedPacket) {
		t.Fatalf("expected ErrReplayedPacket for seqNum=0 in check, got %v", err)
	}
	if err := w.mark(0); !errors.Is(err, ErrReplayedPacket) {
		t.Fatalf("expected ErrReplayedPacket for seqNum=0 in mark, got %v", err)
	}

	// Mark packet 1000 (advances window with diff >= replayWindowSize)
	if err := w.mark(1000); err != nil {
		t.Fatal(err)
	}

	// seqNum too old in check
	if err := w.check(1000 - replayWindowSize); !errors.Is(err, ErrReplayedPacket) {
		t.Fatalf("expected ErrReplayedPacket for expired packet in check, got %v", err)
	}

	// seqNum too old in mark
	if err := w.mark(1000 - replayWindowSize); !errors.Is(err, ErrReplayedPacket) {
		t.Fatalf("expected ErrReplayedPacket for expired packet in mark, got %v", err)
	}

	// Mark packet 990 (inside window)
	if err := w.check(990); err != nil {
		t.Fatalf("expected fresh packet 990, got %v", err)
	}
	if err := w.mark(990); err != nil {
		t.Fatalf("expected success marking 990, got %v", err)
	}

	// Re-mark 990 (duplicate detection under mark lock)
	if err := w.mark(990); !errors.Is(err, ErrReplayedPacket) {
		t.Fatalf("expected ErrReplayedPacket on duplicate mark, got %v", err)
	}
}

func TestShardAEAD_LargeAAD(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, err := NewShardAEAD(key)
	if err != nil {
		t.Fatal(err)
	}

	// Large AAD exceeding 120 bytes stack buffer (e.g. 300 bytes)
	largeAAD := make([]byte, 300)
	for i := range largeAAD {
		largeAAD[i] = byte(i % 256)
	}

	msg := []byte("payload with large AAD metadata fallback to heap")
	sealed, err := aead.Seal(nil, msg, largeAAD)
	if err != nil {
		t.Fatalf("Seal with large AAD failed: %v", err)
	}

	decrypted, err := aead.Open(nil, sealed, largeAAD)
	if err != nil {
		t.Fatalf("Open with large AAD failed: %v", err)
	}
	if !bytes.Equal(decrypted, msg) {
		t.Fatal("decrypted mismatch with large AAD")
	}
}

func TestBufferPools_StrictCapacityRejection(t *testing.T) {
	// Oversized buffers (e.g. 2048 bytes) should not be accepted by pools
	oversizedPlain := make([]byte, 2048)
	PutPlaintextBuffer(oversizedPlain)

	oversizedWire := make([]byte, 2048)
	PutWireFrameBuffer(oversizedWire)

	// Undersized buffers
	PutPlaintextBuffer(make([]byte, 10))
	PutWireFrameBuffer(make([]byte, 10))

	// Backward compatibility alias check
	if ConstantWireShardSize != ConstantWireFrameSize {
		t.Fatalf("ConstantWireShardSize (%d) != ConstantWireFrameSize (%d)", ConstantWireShardSize, ConstantWireFrameSize)
	}
	if ConstantPlaintextShardSize != DefaultPlaintextFrameSize {
		t.Fatalf("ConstantPlaintextShardSize (%d) != DefaultPlaintextFrameSize (%d)", ConstantPlaintextShardSize, DefaultPlaintextFrameSize)
	}
}

func TestShardAEAD_ConcurrentSetSessionID(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, _ := NewShardAEAD(key)

	var wg sync.WaitGroup
	const goroutines = 8
	const iterations = 100

	wg.Add(goroutines * 2)

	// Goroutines updating sessionID concurrently
	for g := 0; g < goroutines; g++ {
		sid := uint64(g * 1000)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				aead.SetSessionID(sid + uint64(i))
				_ = aead.SessionID()
			}
		}()
	}

	// Goroutines sealing frames concurrently
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			plain := make([]byte, DefaultPlaintextFrameSize)
			dst := make([]byte, ConstantWireFrameSize)
			for i := 0; i < iterations; i++ {
				_, err := aead.SealFrame(dst, plain)
				if err != nil {
					t.Errorf("SealFrame during concurrent SetSessionID failed: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()
}

func TestShardAEAD_BufferOverlapProtection(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, err := NewShardAEAD(key)
	if err != nil {
		t.Fatal(err)
	}

	// 1. SealFrame with inexact overlap
	buf := make([]byte, ConstantWireFrameSize*2)
	plainOverlap := buf[10 : 10+DefaultPlaintextFrameSize]
	_, err = aead.SealFrame(buf[:ConstantWireFrameSize], plainOverlap)
	if !errors.Is(err, ErrInvalidBufferOverlap) {
		t.Fatalf("expected ErrInvalidBufferOverlap in SealFrame, got %v", err)
	}

	// 2. OpenFrame with inexact overlap
	validPlain := make([]byte, DefaultPlaintextFrameSize)
	validFrame, err := aead.SealFrame(nil, validPlain)
	if err != nil {
		t.Fatal(err)
	}

	overlapOpenBuf := make([]byte, ConstantWireFrameSize*2)
	copy(overlapOpenBuf[10:], validFrame)
	wireOverlap := overlapOpenBuf[10 : 10+ConstantWireFrameSize]
	_, err = aead.OpenFrame(overlapOpenBuf[:DefaultPlaintextFrameSize], wireOverlap)
	if !errors.Is(err, ErrInvalidBufferOverlap) {
		t.Fatalf("expected ErrInvalidBufferOverlap in OpenFrame, got %v", err)
	}

	// 3. Seal with inexact overlap
	msg := make([]byte, 200)
	sealBuf := make([]byte, 500)
	plainMsgOverlap := sealBuf[10 : 10+len(msg)]
	_, err = aead.Seal(sealBuf[:250], plainMsgOverlap, nil)
	if !errors.Is(err, ErrInvalidBufferOverlap) {
		t.Fatalf("expected ErrInvalidBufferOverlap in Seal, got %v", err)
	}

	// 4. Open with inexact overlap
	sealedMsg, err := aead.Seal(nil, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	openOverlapBuf := make([]byte, len(sealedMsg)+300)
	copy(openOverlapBuf[15:], sealedMsg)
	sealedOverlap := openOverlapBuf[15 : 15+len(sealedMsg)]
	_, err = aead.Open(openOverlapBuf[:len(msg)], sealedOverlap, nil)
	if !errors.Is(err, ErrInvalidBufferOverlap) {
		t.Fatalf("expected ErrInvalidBufferOverlap in Open, got %v", err)
	}
}

func TestShardAEAD_NilReceiverSafety(t *testing.T) {
	var nilAEAD *ShardAEAD

	if _, err := nilAEAD.SealFrame(nil, nil); !errors.Is(err, ErrNilAEAD) {
		t.Fatalf("expected ErrNilAEAD on nil SealFrame, got %v", err)
	}
	if _, err := nilAEAD.OpenFrame(nil, nil); !errors.Is(err, ErrNilAEAD) {
		t.Fatalf("expected ErrNilAEAD on nil OpenFrame, got %v", err)
	}
	if _, err := nilAEAD.Seal(nil, nil, nil); !errors.Is(err, ErrNilAEAD) {
		t.Fatalf("expected ErrNilAEAD on nil Seal, got %v", err)
	}
	if _, err := nilAEAD.Open(nil, nil, nil); !errors.Is(err, ErrNilAEAD) {
		t.Fatalf("expected ErrNilAEAD on nil Open, got %v", err)
	}
	if cnt, err := nilAEAD.nextCounter(); !errors.Is(err, ErrNilAEAD) || cnt != 0 {
		t.Fatalf("expected ErrNilAEAD on nil nextCounter, got %v", err)
	}
	if nilAEAD.SessionID() != 0 {
		t.Fatal("expected 0 for nil SessionID")
	}
	if nilAEAD.CurrentCounter() != 0 {
		t.Fatal("expected 0 for nil CurrentCounter")
	}
	if nilAEAD.Salt() != [4]byte{} {
		t.Fatal("expected empty salt for nil Salt")
	}
	// Must not panic:
	nilAEAD.SetSessionID(42)
	nilAEAD.Close()
	nilAEAD.SetCounterForTesting(99)

	var nilWindow *antiReplayWindow
	if err := nilWindow.check(1); !errors.Is(err, ErrReplayedPacket) {
		t.Fatalf("expected ErrReplayedPacket on nilWindow.check, got %v", err)
	}
	if err := nilWindow.mark(1); !errors.Is(err, ErrReplayedPacket) {
		t.Fatalf("expected ErrReplayedPacket on nilWindow.mark, got %v", err)
	}
	nilWindow.shiftLeft(10)
}

func TestShardAEAD_CloseLifecycle(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, err := NewShardAEADWithSession(key, 0x12345678)
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, DefaultPlaintextFrameSize)
	_, err = aead.SealFrame(nil, plain)
	if err != nil {
		t.Fatal(err)
	}

	aead.Close()

	if aead.SessionID() != 0 {
		t.Fatalf("expected SessionID == 0 after Close, got %x", aead.SessionID())
	}
	if aead.Salt() != [4]byte{} {
		t.Fatalf("expected zeroized salt after Close, got %v", aead.Salt())
	}
	if aead.CurrentCounter() < MaxAllowedCounter {
		t.Fatalf("expected counter latched at MaxAllowedCounter, got %d", aead.CurrentCounter())
	}

	// Sealing after Close must immediately fail with ErrKeyExhaustion
	_, err = aead.SealFrame(nil, plain)
	if !errors.Is(err, ErrKeyExhaustion) {
		t.Fatalf("expected ErrKeyExhaustion after Close, got %v", err)
	}

	// Idempotent close
	aead.Close()
}

func TestShardAEAD_ExhaustiveSlidingWindowStep(t *testing.T) {
	w := &antiReplayWindow{}

	// Mark sequential packets 1 through 500
	for i := uint64(1); i <= 500; i++ {
		if err := w.check(i); err != nil {
			t.Fatalf("check failed for sequential packet %d: %v", i, err)
		}
		if err := w.mark(i); err != nil {
			t.Fatalf("mark failed for sequential packet %d: %v", i, err)
		}
		// Duplicate must be rejected
		if err := w.check(i); !errors.Is(err, ErrReplayedPacket) {
			t.Fatalf("expected duplicate rejection for %d", i)
		}
	}

	// Verify that packets older than 500 - 256 = 244 are rejected
	for i := uint64(1); i <= 244; i++ {
		if err := w.check(i); !errors.Is(err, ErrReplayedPacket) {
			t.Fatalf("expected expired packet rejection for %d", i)
		}
	}

	// Verify jump of diff in [1..255]
	for step := uint64(1); step < replayWindowSize; step++ {
		wStep := &antiReplayWindow{}
		if err := wStep.mark(100); err != nil {
			t.Fatal(err)
		}
		// Jump to 100 + step
		newSeq := 100 + step
		if err := wStep.mark(newSeq); err != nil {
			t.Fatalf("failed jump of step %d: %v", step, err)
		}
		// Old seq 100 must still be recorded as duplicate
		if err := wStep.check(100); !errors.Is(err, ErrReplayedPacket) {
			t.Fatalf("expected seq 100 to be recorded after jump of step %d", step)
		}
	}
}

func TestMem_OverlapClassification(t *testing.T) {
	// Empty slices
	if checkBufferOverlap(nil, nil, 20, true) != overlapDisjoint {
		t.Fatal("expected disjoint for nil slices")
	}
	if checkBufferOverlap([]byte{}, []byte("abc"), 20, true) != overlapDisjoint {
		t.Fatal("expected disjoint for empty slice")
	}

	buf := make([]byte, 100)

	// Exact start: &dst[0] == &src[0] (both seal and open)
	if checkBufferOverlap(buf, buf[:50], 20, true) != overlapExactStart {
		t.Fatal("expected overlapExactStart for seal")
	}
	if checkBufferOverlap(buf[:50], buf, 20, false) != overlapExactStart {
		t.Fatal("expected overlapExactStart for open")
	}

	// Exact offset for Seal: &dst[20] == &src[0] (dstStart + 20 == srcStart)
	if checkBufferOverlap(buf, buf[20:70], 20, true) != overlapExactOffset {
		t.Fatal("expected overlapExactOffset for seal")
	}
	// Inverted offset for Seal: must be rejected as unaligned!
	if checkBufferOverlap(buf[20:70], buf, 20, true) != overlapUnaligned {
		t.Fatal("expected overlapUnaligned for inverted offset in seal")
	}

	// Exact offset for Open: &src[20] == &dst[0] (srcStart + 20 == dstStart)
	if checkBufferOverlap(buf[20:70], buf, 20, false) != overlapExactOffset {
		t.Fatal("expected overlapExactOffset for open")
	}
	// Inverted offset for Open: must be rejected as unaligned!
	if checkBufferOverlap(buf, buf[20:70], 20, false) != overlapUnaligned {
		t.Fatal("expected overlapUnaligned for inverted offset in open")
	}

	// Disjoint
	if checkBufferOverlap(buf[:50], buf[50:], 20, true) != overlapDisjoint {
		t.Fatal("expected overlapDisjoint")
	}

	// Unaligned overlap
	if checkBufferOverlap(buf[:60], buf[10:70], 20, true) != overlapUnaligned {
		t.Fatal("expected overlapUnaligned")
	}

	// Critical slice edge cases: len(slice) == headerOffset (20 bytes)
	// Must not panic with index out of bounds!
	twentyByteBuf := make([]byte, 20)
	if checkBufferOverlap(twentyByteBuf, twentyByteBuf, 20, true) != overlapExactStart {
		t.Fatal("expected overlapExactStart on 20-byte buffer")
	}
	// Disjoint 20-byte buffers
	otherTwenty := make([]byte, 20)
	if checkBufferOverlap(twentyByteBuf, otherTwenty, 20, true) != overlapDisjoint {
		t.Fatal("expected overlapDisjoint on separate 20-byte buffers")
	}
	// Small slice < 20 bytes (e.g. 5 bytes)
	fiveByte := make([]byte, 5)
	if checkBufferOverlap(fiveByte, fiveByte, 20, true) != overlapExactStart {
		t.Fatal("expected overlapExactStart on 5-byte buffer")
	}
}

func TestShardAEAD_CorruptDecryptedLength(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, _ := NewShardAEAD(key)

	// Seal 1343 bytes directly with aead.Seal (not SealFrame)
	shortMsg := make([]byte, DefaultPlaintextFrameSize-1)
	sealedShort, err := aead.Seal(nil, shortMsg, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Pad sealedShort by 1 byte to make it exactly ConstantWireFrameSize (1380 bytes)
	fakeWireFrame := make([]byte, ConstantWireFrameSize)
	copy(fakeWireFrame, sealedShort)

	// OpenFrame must detect corrupt decrypted length != 1344 bytes
	recvAEAD, _ := NewShardAEAD(key)
	_, err = recvAEAD.OpenFrame(nil, fakeWireFrame)
	if err == nil {
		t.Fatal("expected error on invalid frame plaintext size, got nil")
	}
}

func TestShardAEAD_SealCounterExhaustion(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, _ := NewShardAEAD(key)

	aead.SetCounterForTesting(MaxAllowedCounter)

	// Calling Seal at MaxAllowedCounter must return ErrKeyExhaustion
	_, err := aead.Seal(nil, []byte("data"), nil)
	if !errors.Is(err, ErrKeyExhaustion) {
		t.Fatalf("expected ErrKeyExhaustion from Seal, got %v", err)
	}
}

func TestShardAEAD_BufferOverlapInPlaceAndProtection(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, err := NewShardAEAD(key)
	if err != nil {
		t.Fatal(err)
	}

	// 1. In-place SealFrame with &dst[0] == &plaintext[0]
	buf := make([]byte, ConstantWireFrameSize)
	origPayload := make([]byte, DefaultPlaintextFrameSize)
	for i := range origPayload {
		origPayload[i] = byte(i % 251)
	}
	copy(buf, origPayload)

	sealedInPlace, err := aead.SealFrame(buf, buf[:DefaultPlaintextFrameSize])
	if err != nil {
		t.Fatalf("in-place SealFrame failed: %v", err)
	}
	if len(sealedInPlace) != ConstantWireFrameSize {
		t.Fatalf("expected wire size %d, got %d", ConstantWireFrameSize, len(sealedInPlace))
	}
	if &sealedInPlace[0] != &buf[0] {
		t.Fatal("expected in-place seal to use original buffer address")
	}

	// Verify decryption of in-place sealed frame
	recvAEAD, _ := NewShardAEAD(key)
	decrypted, err := recvAEAD.OpenFrame(nil, sealedInPlace)
	if err != nil {
		t.Fatalf("OpenFrame on in-place sealed frame failed: %v", err)
	}
	if !bytes.Equal(decrypted, origPayload) {
		t.Fatal("decrypted payload mismatch after in-place seal")
	}

	// 2. In-place OpenFrame with &dst[0] == &wireFrame[0]
	frameBuf := make([]byte, ConstantWireFrameSize)
	copy(frameBuf, sealedInPlace)

	recvAEAD2, _ := NewShardAEAD(key)
	decryptedInPlace, err := recvAEAD2.OpenFrame(frameBuf, frameBuf)
	if err != nil {
		t.Fatalf("in-place OpenFrame failed: %v", err)
	}
	if len(decryptedInPlace) != DefaultPlaintextFrameSize {
		t.Fatalf("expected plaintext size %d, got %d", DefaultPlaintextFrameSize, len(decryptedInPlace))
	}
	if &decryptedInPlace[0] != &frameBuf[0] {
		t.Fatal("expected in-place open to use original buffer address")
	}
	if !bytes.Equal(decryptedInPlace, origPayload) {
		t.Fatal("decrypted payload mismatch after in-place open")
	}

	// 2b. In-place OpenFrame with &dst[0] == &wireFrame[20] (overlapExactOffset)
	frameBufOffset := make([]byte, ConstantWireFrameSize)
	copy(frameBufOffset, sealedInPlace)
	recvAEAD2Offset, _ := NewShardAEAD(key)
	decryptedOffset, err := recvAEAD2Offset.OpenFrame(frameBufOffset[20:1364], frameBufOffset)
	if err != nil {
		t.Fatalf("in-place OpenFrame with exact offset failed: %v", err)
	}
	if !bytes.Equal(decryptedOffset, origPayload) {
		t.Fatal("decrypted payload mismatch after in-place open with exact offset")
	}

	// 3. In-place variable Seal and Open
	varBuf := make([]byte, 200)
	varPayload := []byte("in-place variable length payload 12345")
	copy(varBuf, varPayload)

	sealedVar, err := aead.Seal(varBuf, varBuf[:len(varPayload)], nil)
	if err != nil {
		t.Fatalf("in-place Seal failed: %v", err)
	}
	if &sealedVar[0] != &varBuf[0] {
		t.Fatal("expected in-place variable seal to use original buffer address")
	}

	recvAEAD3, _ := NewShardAEAD(key)
	decryptedVar, err := recvAEAD3.Open(sealedVar, sealedVar, nil)
	if err != nil {
		t.Fatalf("in-place Open failed: %v", err)
	}
	if !bytes.Equal(decryptedVar, varPayload) {
		t.Fatalf("decrypted variable mismatch: expected %q, got %q", varPayload, decryptedVar)
	}

	// 3b. In-place variable Open with exact offset (&dst[0] == &sealedPacket[20])
	sealedVar2, err := aead.Seal(nil, varPayload, nil)
	if err != nil {
		t.Fatal(err)
	}
	varBufOffset := make([]byte, len(sealedVar2))
	copy(varBufOffset, sealedVar2)
	recvAEAD3Offset, _ := NewShardAEAD(key)
	decryptedVarOffset, err := recvAEAD3Offset.Open(varBufOffset[20:20+len(varPayload)], varBufOffset, nil)
	if err != nil {
		t.Fatalf("in-place Open with exact offset failed: %v", err)
	}
	if !bytes.Equal(decryptedVarOffset, varPayload) {
		t.Fatalf("decrypted variable mismatch after in-place open with exact offset")
	}

	// 4. Unaligned overlap in SealFrame must return ErrInvalidBufferOverlap
	badBuf := make([]byte, ConstantWireFrameSize+50)
	_, err = aead.SealFrame(badBuf[:ConstantWireFrameSize], badBuf[10:10+DefaultPlaintextFrameSize])
	if !errors.Is(err, ErrInvalidBufferOverlap) {
		t.Fatalf("expected ErrInvalidBufferOverlap on unaligned SealFrame, got %v", err)
	}

	// 5. Unaligned overlap in OpenFrame must return ErrInvalidBufferOverlap
	_, err = recvAEAD3.OpenFrame(badBuf[10:10+DefaultPlaintextFrameSize], badBuf[:ConstantWireFrameSize])
	if !errors.Is(err, ErrInvalidBufferOverlap) {
		t.Fatalf("expected ErrInvalidBufferOverlap on unaligned OpenFrame, got %v", err)
	}

	// 6. Seal with overlapping additionalData
	aadBuf := make([]byte, 300)
	_, err = aead.Seal(aadBuf[:200], []byte("hello"), aadBuf[50:100])
	if !errors.Is(err, ErrInvalidBufferOverlap) {
		t.Fatalf("expected ErrInvalidBufferOverlap for overlapping additionalData in Seal, got %v", err)
	}

	// 7. Open with overlapping additionalData
	validSealed, _ := aead.Seal(nil, []byte("payload"), nil)
	openAADBuf := make([]byte, 300)
	_, err = aead.Open(openAADBuf[:50], validSealed, openAADBuf[20:40])
	if !errors.Is(err, ErrInvalidBufferOverlap) {
		t.Fatalf("expected ErrInvalidBufferOverlap for overlapping additionalData in Open, got %v", err)
	}
}

func TestShardAEAD_ClosePermanentlySealsReceiveWindow(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	sender, _ := NewShardAEAD(key)
	receiver, _ := NewShardAEAD(key)

	plain := make([]byte, DefaultPlaintextFrameSize)
	copy(plain, []byte("Test packet before close"))

	frame, err := sender.SealFrame(nil, plain)
	if err != nil {
		t.Fatal(err)
	}

	// Close receiver
	receiver.Close()

	// OpenFrame after Close must reject frame
	_, err = receiver.OpenFrame(nil, frame)
	if err == nil {
		t.Fatal("expected error on OpenFrame after Close, got nil")
	}

	// Variable length Open after Close must reject frame
	msg := []byte("variable length test")
	sealed, err := sender.Seal(nil, msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = receiver.Open(nil, sealed, nil)
	if err == nil {
		t.Fatal("expected error on Open after Close, got nil")
	}
}

func TestShardAEAD_ZeroLengthCapacityBuffersAndAADEdgeCases(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, err := NewShardAEAD(key)
	if err != nil {
		t.Fatal(err)
	}

	// 1. SealFrame with len(dst) == 0 and cap(dst) >= ConstantWireFrameSize
	zeroLenWireBuf := make([]byte, 0, ConstantWireFrameSize)
	plain := make([]byte, DefaultPlaintextFrameSize)
	copy(plain, []byte("zero-len slice test"))

	sealed, err := aead.SealFrame(zeroLenWireBuf, plain)
	if err != nil {
		t.Fatalf("SealFrame with zero-len buffer failed: %v", err)
	}
	if len(sealed) != ConstantWireFrameSize {
		t.Fatalf("expected wire size %d, got %d", ConstantWireFrameSize, len(sealed))
	}

	// 2. OpenFrame with len(dst) == 0 and cap(dst) >= DefaultPlaintextFrameSize
	zeroLenPlainBuf := make([]byte, 0, DefaultPlaintextFrameSize)
	decrypted, err := aead.OpenFrame(zeroLenPlainBuf, sealed)
	if err != nil {
		t.Fatalf("OpenFrame with zero-len buffer failed: %v", err)
	}
	if len(decrypted) != DefaultPlaintextFrameSize {
		t.Fatalf("expected plaintext size %d, got %d", DefaultPlaintextFrameSize, len(decrypted))
	}

	// 3. Seal with len(dst) == 0 and cap(dst) >= totalLen
	zeroLenSealBuf := make([]byte, 0, 500)
	msg := []byte("short message")
	sealedVar, err := aead.Seal(zeroLenSealBuf, msg, []byte("short-aad"))
	if err != nil {
		t.Fatalf("Seal with zero-len buffer failed: %v", err)
	}

	// 4. Open with len(dst) == 0 and cap(dst) >= expectedPlainLen
	zeroLenOpenBuf := make([]byte, 0, 500)
	decryptedVar, err := aead.Open(zeroLenOpenBuf, sealedVar, []byte("short-aad"))
	if err != nil {
		t.Fatalf("Open with zero-len buffer failed: %v", err)
	}
	if !bytes.Equal(decryptedVar, msg) {
		t.Fatalf("decrypted mismatch: expected %q, got %q", msg, decryptedVar)
	}

	// 5. Seal and Open with empty plaintext payload
	emptyPlain := []byte{}
	sealedEmpty, err := aead.Seal(nil, emptyPlain, []byte("empty-aad"))
	if err != nil {
		t.Fatalf("Seal with empty plaintext failed: %v", err)
	}
	decryptedEmpty, err := aead.Open(nil, sealedEmpty, []byte("empty-aad"))
	if err != nil {
		t.Fatalf("Open with empty plaintext failed: %v", err)
	}
	if len(decryptedEmpty) != 0 {
		t.Fatalf("expected empty decrypted payload, got %d bytes", len(decryptedEmpty))
	}

	// 6. putAADBuffer with nil
	putAADBuffer(nil)
}
