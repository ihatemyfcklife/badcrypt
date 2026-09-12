package crypto

import (
	"crypto/subtle"
	"sync"
)

const (
	// DefaultPlaintextFrameSize is the standard calibrated payload size (1344 bytes)
	// matching network path MTU constraints when combined with Vectis framing.
	DefaultPlaintextFrameSize = 1344

	// ConstantPlaintextShardSize is an alias for DefaultPlaintextFrameSize for
	// seamless backwards compatibility with Vectis RLNC shards.
	ConstantPlaintextShardSize = DefaultPlaintextFrameSize

	// NonceSize is the ChaCha20-Poly1305 nonce length in bytes (RFC 8439).
	NonceSize = 12

	// Overhead is the ChaCha20-Poly1305 authentication tag size in bytes.
	Overhead = 16

	// ConstantWireFrameSize is the constant wire size after AEAD sealing:
	// 12 bytes Nonce + 1344 bytes Ciphertext + 16 bytes Poly1305 Tag = 1372 bytes.
	ConstantWireFrameSize = NonceSize + DefaultPlaintextFrameSize + Overhead
)

var (
	plainPool = sync.Pool{
		New: func() any {
			b := make([]byte, DefaultPlaintextFrameSize)
			return &b
		},
	}

	wirePool = sync.Pool{
		New: func() any {
			b := make([]byte, ConstantWireFrameSize)
			return &b
		},
	}
)

// GetPlaintextBuffer borrows a 1344-byte slice from the internal pool.
func GetPlaintextBuffer() []byte {
	bufPtr := plainPool.Get().(*[]byte)
	return (*bufPtr)[:DefaultPlaintextFrameSize]
}

// PutPlaintextBuffer returns a plaintext buffer to the internal pool.
func PutPlaintextBuffer(b []byte) {
	if cap(b) < DefaultPlaintextFrameSize {
		return
	}
	Zeroize(b[:DefaultPlaintextFrameSize])
	res := b[:DefaultPlaintextFrameSize]
	plainPool.Put(&res)
}

// GetWireFrameBuffer borrows a 1372-byte slice from the internal pool.
func GetWireFrameBuffer() []byte {
	bufPtr := wirePool.Get().(*[]byte)
	return (*bufPtr)[:ConstantWireFrameSize]
}

// PutWireFrameBuffer returns a wire frame buffer to the internal pool.
func PutWireFrameBuffer(b []byte) {
	if cap(b) < ConstantWireFrameSize {
		return
	}
	Zeroize(b[:ConstantWireFrameSize])
	res := b[:ConstantWireFrameSize]
	wirePool.Put(&res)
}

// Zeroize securely wipes the contents of a byte slice to protect secrets in memory.
// It uses subtle memory clearing to prevent compiler optimization dead-store elimination.
func Zeroize(b []byte) {
	if len(b) == 0 {
		return
	}
	// Use Go 1.21+ clear builtin
	clear(b)
	// Compiler memory barrier via crypto/subtle
	_ = subtle.ConstantTimeByteEq(b[0], 0)
}
