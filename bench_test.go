package badcrypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
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
		_, _ = aead.SealFrame(dst, plain)
	}
}

func BenchmarkOpenFrame(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	sender, _ := NewShardAEAD(key)
	recvAEAD, _ := NewShardAEAD(key)

	plain := make([]byte, DefaultPlaintextFrameSize)
	frames := make([][]byte, 1024)
	for i := range frames {
		frames[i], _ = sender.SealFrame(nil, plain)
	}
	dst := make([]byte, DefaultPlaintextFrameSize)

	b.SetBytes(int64(DefaultPlaintextFrameSize))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		idx := i % 1024
		if idx == 0 && i > 0 {
			recvAEAD.recvWindow = antiReplayWindow{}
		}
		_, _ = recvAEAD.OpenFrame(dst, frames[idx])
	}
}

func BenchmarkSealVariable(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, _ := NewShardAEAD(key)

	msg := make([]byte, 1024)
	dst := make([]byte, SessionIDSize+NonceSize+1024+Overhead)

	b.SetBytes(1024)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = aead.Seal(dst, msg, nil)
	}
}

func BenchmarkOpenVariable(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	sender, _ := NewShardAEAD(key)
	recvAEAD, _ := NewShardAEAD(key)

	msg := make([]byte, 1024)
	frames := make([][]byte, 1024)
	for i := range frames {
		frames[i], _ = sender.Seal(nil, msg, nil)
	}
	dst := make([]byte, 1024)

	b.SetBytes(1024)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		idx := i % 1024
		if idx == 0 && i > 0 {
			recvAEAD.recvWindow = antiReplayWindow{}
		}
		_, _ = recvAEAD.Open(dst, frames[idx], nil)
	}
}

func BenchmarkOpenVariableWithAAD(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	sender, _ := NewShardAEAD(key)
	recvAEAD, _ := NewShardAEAD(key)

	msg := make([]byte, 1024)
	aad := []byte("ctx-id-42")
	frames := make([][]byte, 1024)
	for i := range frames {
		frames[i], _ = sender.Seal(nil, msg, aad)
	}
	dst := make([]byte, 1024)

	b.SetBytes(1024)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		idx := i % 1024
		if idx == 0 && i > 0 {
			recvAEAD.recvWindow = antiReplayWindow{}
		}
		_, _ = recvAEAD.Open(dst, frames[idx], aad)
	}
}

func BenchmarkClientHello(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, _, _, _ = GenerateClientHello("benchmark-token-xyz")
	}
}

func BenchmarkSealFrame_InPlace(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	aead, _ := NewShardAEAD(key)

	buf := make([]byte, ConstantWireFrameSize)

	b.SetBytes(int64(DefaultPlaintextFrameSize))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = aead.SealFrame(buf, buf[:DefaultPlaintextFrameSize])
	}
}

func BenchmarkOpenFrame_InPlace(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	sender, _ := NewShardAEAD(key)
	recvAEAD, _ := NewShardAEAD(key)

	plain := make([]byte, DefaultPlaintextFrameSize)
	frames := make([][]byte, 1024)
	for i := range frames {
		frames[i], _ = sender.SealFrame(nil, plain)
	}
	buf := make([]byte, ConstantWireFrameSize)

	b.SetBytes(int64(DefaultPlaintextFrameSize))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		idx := i % 1024
		if idx == 0 && i > 0 {
			recvAEAD.recvWindow = antiReplayWindow{}
		}
		copy(buf, frames[idx])
		_, _ = recvAEAD.OpenFrame(buf, buf)
	}
}

func BenchmarkServerHello(b *testing.B) {
	_, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("failed to generate server key: %v", err)
	}
	tokStore := NewTokenStore()
	tokStore.Add("benchmark-token-xyz")
	defer tokStore.Close()

	const batchSize = 256
	hellos := make([][]byte, batchSize)
	for i := range hellos {
		h, _, _, _, err := GenerateClientHello("benchmark-token-xyz")
		if err != nil {
			b.Fatalf("failed to generate client hello: %v", err)
		}
		hellos[i] = h
	}

	cache := NewAntiReplayCache()
	defer cache.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		idx := i % batchSize
		if idx == 0 {
			cache.Reset()
		}
		resp, _, _, err := ProcessClientHelloWithCache(hellos[idx], serverPriv, tokStore, 0x1234, cache)
		if err != nil {
			b.Fatalf("ProcessClientHello failed at i=%d: %v", i, err)
		}
		if len(resp) != ServerHelloSize {
			b.Fatalf("invalid server hello size: %d", len(resp))
		}
	}
}

func BenchmarkTokenStoreLookup(b *testing.B) {
	tokStore := NewTokenStore()
	for i := 0; i < 1000; i++ {
		tokStore.Add(fmt.Sprintf("user-token-%04d", i))
	}
	defer tokStore.Close()

	targetTID := TokenID("user-token-0500")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tok, ok := tokStore.ValidateTokenID(targetTID[:])
		if !ok || len(tok) == 0 {
			b.Fatalf("lookup failed")
		}
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

func BenchmarkBufferPools(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pBuf := GetPlaintextBuffer()
		PutPlaintextBuffer(pBuf)

		wBuf := GetWireFrameBuffer()
		PutWireFrameBuffer(wBuf)
	}
}

func BenchmarkTokenID(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = TokenID("benchmark-auth-token-6479")
	}
}

func BenchmarkSlidingWindowCheck(b *testing.B) {
	w := &antiReplayWindow{}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = w.check(uint64(i + 1))
	}
}

func BenchmarkGenerateClientHello_Blinded(b *testing.B) {
	serverPub, _, _ := ed25519.GenerateKey(rand.Reader)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _, _, _ = GenerateClientHello("benchmark-auth-token-6479", serverPub)
	}
}

func BenchmarkDatagramFragmentationAndReassembly(b *testing.B) {
	serverPub, _, _ := ed25519.GenerateKey(rand.Reader)
	hello, _, _, _, _ := GenerateClientHello("benchmark-auth-token-6479", serverPub)
	r := NewHandshakeReassembler(64, 5*time.Second)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		frags, _ := FragmentHandshakePayload(hello)
		_, _, _ = r.Feed(frags[0])
		_, _, _ = r.Feed(frags[1])
	}
}

func BenchmarkEd25519ToX25519Pub(b *testing.B) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = ed25519ToX25519Pub(pub)
	}
}

func BenchmarkServerIdentity_DerivationCached(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Prime the cache
	_, _ = getOrDeriveServerXPriv(priv)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = getOrDeriveServerXPriv(priv)
	}
}
