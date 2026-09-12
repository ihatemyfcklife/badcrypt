package crypto

import (
	"crypto/rand"
	"testing"
)

func BenchmarkSealFrame(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, _ := NewShardAEAD(key)

	plain := make([]byte, DefaultPlaintextFrameSize)
	dst := make([]byte, ConstantWireFrameSize)

	b.SetBytes(int64(DefaultPlaintextFrameSize))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = aead.SealFrame(dst, plain)
	}
}

func BenchmarkOpenFrame(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, _ := NewShardAEAD(key)

	plain := make([]byte, DefaultPlaintextFrameSize)
	frame := aead.SealFrame(nil, plain)
	dst := make([]byte, DefaultPlaintextFrameSize)

	b.SetBytes(int64(DefaultPlaintextFrameSize))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = aead.OpenFrame(dst, frame)
	}
}

func BenchmarkSealVariable(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, _ := NewShardAEAD(key)

	msg := make([]byte, 1024)
	dst := make([]byte, NonceSize+1024+Overhead)

	b.SetBytes(1024)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = aead.Seal(dst, msg, nil)
	}
}

func BenchmarkClientHello(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, _, _, _ = GenerateClientHello("benchmark-token-xyz")
	}
}

func BenchmarkServerHello(b *testing.B) {
	validTokens := map[string]bool{"benchmark-token-xyz": true}
	hello, _, _, _, _ := GenerateClientHello("benchmark-token-xyz")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, _, _ = ProcessClientHello(hello, validTokens, 0x1234)
	}
}

func BenchmarkAntiReplayCache(b *testing.B) {
	cache := NewAntiReplayCache()
	defer cache.Close()

	var nonce [16]byte
	_, _ = rand.Read(nonce[:])

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = cache.AddOrCheck(nonce[:])
	}
}
