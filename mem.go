package crypto

import (
	"crypto/subtle"
	"runtime"
	"sync"
	"unsafe"
)

const (
	// SessionIDSize is the 64-bit session identifier length in bytes.
	SessionIDSize = 8

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
	// 8 bytes SessionID + 12 bytes Nonce + 1344 bytes Ciphertext + 16 bytes Poly1305 Tag = 1380 bytes.
	ConstantWireFrameSize = SessionIDSize + NonceSize + DefaultPlaintextFrameSize + Overhead

	// ConstantWireShardSize is an alias for ConstantWireFrameSize for
	// seamless backwards compatibility with Vectis RLNC shards.
	ConstantWireShardSize = ConstantWireFrameSize

	// IPv6MinMTU is the minimum link MTU guaranteed by IPv6 (RFC 8200).
	IPv6MinMTU = 1280

	// SafeInternetMTU is the safe, unfragmented UDP payload MTU across any IPv6/IPv4 Internet path (1280 - 40B IPv6 - 8B UDP).
	SafeInternetMTU = 1232
)

var (
	plainPool = sync.Pool{
		New: func() any {
			var b [DefaultPlaintextFrameSize]byte
			return &b
		},
	}

	wirePool = sync.Pool{
		New: func() any {
			var b [ConstantWireFrameSize]byte
			return &b
		},
	}
)

// GetPlaintextBuffer borrows a 1344-byte slice from the internal pool.
func GetPlaintextBuffer() []byte {
	bufPtr := plainPool.Get().(*[DefaultPlaintextFrameSize]byte)
	return bufPtr[:DefaultPlaintextFrameSize]
}

// PutPlaintextBuffer returns a plaintext buffer to the internal pool.
// Zero-allocation: uses array-pointer casting to avoid slice header heap escapes.
// It strictly rejects buffers whose capacity differs from DefaultPlaintextFrameSize to prevent pool pollution.
func PutPlaintextBuffer(b []byte) {
	if cap(b) != DefaultPlaintextFrameSize {
		return
	}
	Zeroize(b[:DefaultPlaintextFrameSize])
	arrPtr := (*[DefaultPlaintextFrameSize]byte)(b[:DefaultPlaintextFrameSize])
	plainPool.Put(arrPtr)
}

// GetWireFrameBuffer borrows a 1380-byte slice from the internal pool.
func GetWireFrameBuffer() []byte {
	bufPtr := wirePool.Get().(*[ConstantWireFrameSize]byte)
	return bufPtr[:ConstantWireFrameSize]
}

// PutWireFrameBuffer returns a wire frame buffer to the internal pool.
// Zero-allocation: uses array-pointer casting to avoid slice header heap escapes.
// It strictly rejects buffers whose capacity differs from ConstantWireFrameSize to prevent pool pollution.
func PutWireFrameBuffer(b []byte) {
	if cap(b) != ConstantWireFrameSize {
		return
	}
	Zeroize(b[:ConstantWireFrameSize])
	arrPtr := (*[ConstantWireFrameSize]byte)(b[:ConstantWireFrameSize])
	wirePool.Put(arrPtr)
}

// Zeroize securely wipes the contents of a byte slice to protect secrets in memory.
// It uses Go's runtime clear and memory barriers to prevent compiler dead-store elimination.
func Zeroize(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	_ = subtle.ConstantTimeByteEq(b[0], 0)
	_ = subtle.ConstantTimeByteEq(b[len(b)-1], 0)
	runtime.KeepAlive(&b[0])
	runtime.KeepAlive(&b[len(b)-1])
}

const maxStackAADSize = 128

var aadPool = sync.Pool{
	New: func() any {
		var b [maxStackAADSize]byte
		return &b
	},
}

// getAADBuffer borrows a 128-byte array pointer for zero-alloc AAD handling.
func getAADBuffer() *[maxStackAADSize]byte {
	return aadPool.Get().(*[maxStackAADSize]byte)
}

// putAADBuffer returns an AAD buffer to the pool after zeroizing.
func putAADBuffer(b *[maxStackAADSize]byte) {
	if b == nil {
		return
	}
	Zeroize(b[:])
	aadPool.Put(b)
}

// anyOverlap reports whether x and y share any bytes in memory.
func anyOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 {
		return false
	}
	return uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

// bufferOverlapKind describes how two memory slices relate to each other.
type bufferOverlapKind int

const (
	overlapDisjoint    bufferOverlapKind = iota // Slices share no memory addresses.
	overlapExactStart                           // &dst[0] == &src[0] (exact start alignment).
	overlapExactOffset                          // &dst[headerOffset] == &src[0] (pre-offset alignment).
	overlapUnaligned                            // Dangerous or unaligned overlap that would cause memory corruption.
)

// checkBufferOverlap analyzes whether dst and src share memory and whether the alignment allows safe in-place operation.
// In Seal (isSeal == true): dst is the wire frame buffer, src is plaintext.
// Valid offset in-place requires dstStart + uintptr(headerOffset) == srcStart.
// In Open (isSeal == false): src is the wire frame buffer, dst is the plaintext buffer.
// Valid offset in-place requires srcStart + uintptr(headerOffset) == dstStart.
func checkBufferOverlap(dst, src []byte, headerOffset int, isSeal bool) bufferOverlapKind {
	if len(dst) == 0 || len(src) == 0 {
		return overlapDisjoint
	}
	dstStart := uintptr(unsafe.Pointer(&dst[0]))
	dstEnd := uintptr(unsafe.Pointer(&dst[len(dst)-1]))
	srcStart := uintptr(unsafe.Pointer(&src[0]))
	srcEnd := uintptr(unsafe.Pointer(&src[len(src)-1]))

	if dstStart > srcEnd || srcStart > dstEnd {
		return overlapDisjoint
	}

	if dstStart == srcStart {
		return overlapExactStart
	}

	if headerOffset > 0 {
		if isSeal {
			// Seal / SealFrame: plaintext (src) must start at dstStart + headerOffset
			if dstStart+uintptr(headerOffset) == srcStart {
				return overlapExactOffset
			}
		} else {
			// Open / OpenFrame: decrypted plaintext (dst) must start at srcStart + headerOffset
			if srcStart+uintptr(headerOffset) == dstStart {
				return overlapExactOffset
			}
		}
	}

	return overlapUnaligned
}
