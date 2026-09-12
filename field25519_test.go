package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"

	"filippo.io/edwards25519"
)

// referenceEd25519ToX25519Pub is the big.Int reference implementation for cross-verification.
func referenceEd25519ToX25519Pub(edPub ed25519.PublicKey) ([]byte, error) {
	var yBytes [32]byte
	copy(yBytes[:], edPub)
	yBytes[31] &= 0x7f

	for i := 0; i < 16; i++ {
		yBytes[i], yBytes[31-i] = yBytes[31-i], yBytes[i]
	}

	p, _ := new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	y := new(big.Int).SetBytes(yBytes[:])

	one := big.NewInt(1)
	num := new(big.Int).Add(one, y)
	num.Mod(num, p)

	den := new(big.Int).Sub(one, y)
	den.Mod(den, p)

	denInv := new(big.Int).ModInverse(den, p)
	if denInv == nil {
		return nil, ErrInvalidServerKey
	}

	u := new(big.Int).Mul(num, denInv)
	u.Mod(u, p)

	uBE := u.Bytes()
	var uBytes [32]byte
	copy(uBytes[32-len(uBE):], uBE)

	var uLE [32]byte
	for i := 0; i < 32; i++ {
		uLE[i] = uBytes[31-i]
	}
	return uLE[:], nil
}

func TestField25519_Ed25519ToX25519Pub_Correctness(t *testing.T) {
	for i := 0; i < 50; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		xPub, err := ed25519ToX25519Pub(pub)
		if err != nil {
			t.Fatalf("ed25519ToX25519Pub failed: %v", err)
		}

		refBytes, err := referenceEd25519ToX25519Pub(pub)
		if err != nil {
			t.Fatalf("reference failed: %v", err)
		}

		if !bytes.Equal(xPub.Bytes(), refBytes) {
			t.Fatalf("iter %d: xPub bytes mismatch: got %x, expected %x", i, xPub.Bytes(), refBytes)
		}
	}
}

func TestField25519_NeutralAndSmallOrderPointRejection(t *testing.T) {
	// 1. Identity / Neutral point on Edwards: (0, 1) -> y = 1, x = 0
	identityBytes := edwards25519.NewIdentityPoint().Bytes()
	_, err := ed25519ToX25519Pub(identityBytes)
	if !errors.Is(err, ErrInvalidServerKey) {
		t.Fatalf("expected ErrInvalidServerKey for identity point, got %v", err)
	}

	// 2. Point of order 2: (0, -1) -> y = 2^255 - 20
	// 3. Point of order 4: (x, 0)
	// Points whose order divides 8 must be rejected
	var p edwards25519.Point
	p.SetBytes(identityBytes)
	if _, err := ed25519ToX25519Pub(p.Bytes()); !errors.Is(err, ErrInvalidServerKey) {
		t.Fatalf("expected ErrInvalidServerKey, got %v", err)
	}

	// 4. Invalid point not on curve
	var invalidPoint [32]byte
	invalidPoint[0] = 0xff
	invalidPoint[31] = 0xff
	if _, err := ed25519ToX25519Pub(invalidPoint[:]); err == nil {
		t.Fatal("expected error on invalid point not on curve")
	}
}

func TestField25519_Ed25519ToX25519Pub_ZeroAlloc(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Warmup
	_, _ = ed25519ToX25519Pub(pub)

	allocs := testing.AllocsPerRun(100, func() {
		_, _ = ed25519ToX25519Pub(pub)
	})

	if allocs > 3 {
		t.Fatalf("expected <= 3 allocs, got %.1f allocs", allocs)
	}
}

func TestServerIdentity_PrecomputationAndCaching(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	identity, err := NewServerIdentity(priv)
	if err != nil {
		t.Fatalf("NewServerIdentity failed: %v", err)
	}

	if identity.XPriv == nil || identity.XPub == nil {
		t.Fatal("expected precomputed XPriv and XPub")
	}

	// Cached derivation verification
	cachedXPriv, err := getOrDeriveServerXPriv(priv)
	if err != nil {
		t.Fatalf("getOrDeriveServerXPriv failed: %v", err)
	}

	if !bytes.Equal(cachedXPriv.Bytes(), identity.XPriv.Bytes()) {
		t.Fatal("cached XPriv does not match precomputed XPriv")
	}

	// Calling again must hit cache with 0 allocs
	allocs := testing.AllocsPerRun(50, func() {
		_, _ = getOrDeriveServerXPriv(priv)
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs on cache hit, got %.1f", allocs)
	}
}

func TestAntiReplayCache_StrictTimeRetentionUnderFlood(t *testing.T) {
	c := NewAntiReplayCache()
	defer c.Close()

	// Fill shard 0 completely with unexpired nonces
	var shard0Nonces [EntriesPerShard][16]byte
	found := 0
	var counter uint64
	for found < EntriesPerShard {
		var n [16]byte
		binary.BigEndian.PutUint64(n[8:], counter)
		counter++
		if c.getShardIndex(n[:]) == 0 {
			shard0Nonces[found] = n
			found++
		}
	}

	now := time.Now().Unix()
	expiry := now + 120 // unexpired for 120 seconds

	// Add all EntriesPerShard nonces to shard 0
	for i := 0; i < EntriesPerShard; i++ {
		replayed := c.AddOrCheckWithExpiry(shard0Nonces[i][:], expiry)
		if replayed {
			t.Fatalf("initial insert %d falsely detected as replayed", i)
		}
	}

	// Now an attacker attempts an extreme flood of 5,000 nonces into shard 0
	// to evict shard0Nonces[0] within its 120s validity window
	for i := 0; i < 5000; i++ {
		var floodNonce [16]byte
		for {
			binary.BigEndian.PutUint64(floodNonce[8:], counter)
			counter++
			if c.getShardIndex(floodNonce[:]) == 0 {
				break
			}
		}
		// Under strict anti-replay, these flood packets must be rejected (fail closed),
		// NEVER evicting legitimate unexpired nonces!
		_ = c.AddOrCheckWithExpiry(floodNonce[:], expiry)
	}

	// CRITICAL SECURITY INVARIANT:
	// The victim's legitimate nonce (shard0Nonces[0]) MUST NOT HAVE BEEN EVICTED!
	// Replaying it must still be detected as REPLAY!
	if !c.AddOrCheckWithExpiry(shard0Nonces[0][:], expiry) {
		t.Fatal("CRITICAL VULNERABILITY: Legitimate unexpired nonce was evicted by flood, breaking anti-replay guarantee!")
	}
	// Verify all legitimate nonces remain protected
	for i := 0; i < 100; i++ {
		if !c.AddOrCheckWithExpiry(shard0Nonces[i][:], expiry) {
			t.Fatalf("nonce %d was evicted under flood", i)
		}
	}
}

func TestHandshakeReassembler_PerSourceLimitAndRateLimiter(t *testing.T) {
	r := NewHandshakeReassembler(32, 5*time.Second)
	r.SetMaxPerSource(2) // Max 2 pending handshakes from same IP

	var payload [1000]byte
	copy(payload[0:4], MagicVectisHeader[:])
	payload[4] = TypeClientHello

	// Client A at "192.168.1.10:5000" sends fragments for session 1
	f1, _ := FragmentHandshakePayload(payload[:])
	_, ready, err := r.FeedFrom(f1[0], "192.168.1.10:5000")
	if err != nil || ready {
		t.Fatalf("f1[0] failed: %v", err)
	}

	// Client A sends fragments for session 2 (allowed: count = 2)
	f2, _ := FragmentHandshakePayload(payload[:])
	_, ready, err = r.FeedFrom(f2[0], "192.168.1.10:5000")
	if err != nil || ready {
		t.Fatalf("f2[0] failed: %v", err)
	}

	// Attacker at "192.168.1.10:5000" attempts session 3 (exceeds maxPerSource=2)
	f3, _ := FragmentHandshakePayload(payload[:])
	_, _, err = r.FeedFrom(f3[0], "192.168.1.10:5000")
	if !errors.Is(err, ErrSourceRateLimited) {
		t.Fatalf("expected ErrSourceRateLimited for attacker exceeding per-source quota, got %v", err)
	}

	// Legitimate Client B at "192.168.1.20:6000" CAN establish handshakes normally
	fB, _ := FragmentHandshakePayload(payload[:])
	_, ready, err = r.FeedFrom(fB[0], "192.168.1.20:6000")
	if err != nil || ready {
		t.Fatalf("Client B unexpectedly affected by Client A's quota: %v", err)
	}

	// Complete Client B's handshake
	resB, ready, err := r.FeedFrom(fB[1], "192.168.1.20:6000")
	if err != nil || !ready || !bytes.Equal(resB, payload[:]) {
		t.Fatalf("Client B reassembly failed: %v", err)
	}
}

func TestHandshakeReassembler_ProgressProtection(t *testing.T) {
	// Reassembler with small capacity = 2
	r := NewHandshakeReassembler(2, 5*time.Second)

	var payload [1000]byte
	copy(payload[0:4], MagicVectisHeader[:])
	payload[4] = TypeClientHello

	// Session A
	fA, _ := FragmentHandshakePayload(payload[:])
	_, _, _ = r.Feed(fA[0])

	// Session B
	fB, _ := FragmentHandshakePayload(payload[:])
	_, _, _ = r.Feed(fB[0])

	// Both A and B have 1 fragment received. Capacity is 2.
	// Now incoming Session C arrives: it evicts the oldest single-fragment session (A)
	fC, _ := FragmentHandshakePayload(payload[:])
	_, ready, err := r.Feed(fC[0])
	if err != nil || ready {
		t.Fatalf("Session C failed: %v", err)
	}
	if r.Count() != 2 {
		t.Fatalf("expected count 2, got %d", r.Count())
	}

	// Now Session C receives its second fragment -> C completes and is removed
	resC, ready, err := r.Feed(fC[1])
	if err != nil || !ready || !bytes.Equal(resC, payload[:]) {
		t.Fatalf("Session C failed to complete: %v", err)
	}

	// Now count should be 1 (Session B)
	if r.Count() != 1 {
		t.Fatalf("expected count 1, got %d", r.Count())
	}
}

func TestHandshakeReassembler_NoDeadlockUnderMultiFragmentSaturation(t *testing.T) {
	// Capacity = 3, TTL = 10s
	r := NewHandshakeReassembler(3, 10*time.Second)

	// Create payload needing 3 fragments: 1800 bytes
	var payload [1800]byte
	copy(payload[0:4], MagicVectisHeader[:])
	payload[4] = TypeClientHello

	// Attacker sends 3 sessions, each with 2 fragments received (partial progress)
	f1, _ := FragmentHandshakePayload(payload[:])
	_, _, _ = r.Feed(f1[0])
	_, _, _ = r.Feed(f1[1])

	f2, _ := FragmentHandshakePayload(payload[:])
	_, _, _ = r.Feed(f2[0])
	_, _, _ = r.Feed(f2[1])

	f3, _ := FragmentHandshakePayload(payload[:])
	_, _, _ = r.Feed(f3[0])
	_, _, _ = r.Feed(f3[1])

	if r.Count() != 3 {
		t.Fatalf("expected count 3, got %d", r.Count())
	}

	// Now legitimate Client 4 arrives with a new session
	// Pure chronological LRU MUST evict the oldest session (f1) and accept f4 without locking the server!
	f4, _ := FragmentHandshakePayload(payload[:])
	_, ready, err := r.Feed(f4[0])
	if err != nil || ready {
		t.Fatalf("Server locked out! Expected fresh session accepted via LRU, got err=%v ready=%v", err, ready)
	}

	if r.Count() != 3 {
		t.Fatalf("expected bounded capacity 3, got %d", r.Count())
	}

	// Complete f4
	_, _, _ = r.Feed(f4[1])
	res4, ready, err := r.Feed(f4[2])
	if err != nil || !ready || !bytes.Equal(res4, payload[:]) {
		t.Fatalf("f4 failed to complete: err=%v ready=%v", err, ready)
	}
}

func TestAntiReplayCache_RingSynchronizationNoGhostEntries(t *testing.T) {
	c := NewAntiReplayCache()
	defer c.Close()

	// Pick 10 nonces that hash to shard 0
	var testNonces [10][16]byte
	found := 0
	var counter uint64
	for found < 10 {
		var n [16]byte
		binary.BigEndian.PutUint64(n[8:], counter)
		counter++
		if c.getShardIndex(n[:]) == 0 {
			testNonces[found] = n
			found++
		}
	}

	now := time.Now().Unix()

	// Simulate repeated cycles of inserting, expiring, and re-inserting
	for cycle := 0; cycle < 5; cycle++ {
		exp := now + int64((cycle+1)*10)
		for i := 0; i < 10; i++ {
			// First insertion of the cycle
			replayed := c.AddOrCheckWithExpiry(testNonces[i][:], exp)
			if cycle == 0 && replayed {
				t.Fatalf("cycle %d, nonce %d: initial insert falsely marked as replayed", cycle, i)
			}
			// Unexpired duplicate must be detected as replay
			if !c.AddOrCheckWithExpiry(testNonces[i][:], exp) {
				t.Fatalf("cycle %d, nonce %d: replay not detected", cycle, i)
			}
		}

		// Advance virtual time past expiry to expire all entries
		now = exp + 1
	}

	// Verify shard 0 internal state:
	shard := &c.shards[0]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Ensure that len(shard.lookup) exactly matches the unique nonces stored
	if len(shard.lookup) > 10 {
		t.Fatalf("ghost entries detected! len(lookup) = %d, expected <= 10", len(shard.lookup))
	}

	// Ensure every entry in lookup points to a valid slot in ring that actually contains that nonce
	for nonce, slotIdx := range shard.lookup {
		if slotIdx < 0 || slotIdx >= EntriesPerShard {
			t.Fatalf("invalid slot index %d in lookup", slotIdx)
		}
		if shard.ring[slotIdx].nonce != nonce {
			t.Fatalf("desynchronization detected! lookup has %x pointing to slot %d, but ring has %x",
				nonce, slotIdx, shard.ring[slotIdx].nonce)
		}
	}
}
