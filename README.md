# Badcrypt (`github.com/ihatemyfcklife/badcrypt`)

[![CI](https://github.com/ihatemyfcklife/badcrypt/actions/workflows/release.yml/badge.svg)](https://github.com/ihatemyfcklife/badcrypt/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/ihatemyfcklife/badcrypt)](https://goreportcard.com/report/github.com/ihatemyfcklife/badcrypt)
[![Go Reference](https://pkg.go.dev/badge/github.com/ihatemyfcklife/badcrypt.svg)](https://pkg.go.dev/github.com/ihatemyfcklife/badcrypt)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Badcrypt** is a hardened, production-ready Go cryptographic library engineered for high-throughput, low-latency network engines and secure protocols. It delivers an authenticated hybrid post-quantum key exchange (ML-KEM-768 + X25519 + Ed25519), high-performance directional ChaCha20-Poly1305 authenticated encryption with an RFC 6479 anti-replay sliding window, direct SessionID demultiplexing via Additional Authenticated Data (AAD), and true zero-allocation memory pooling.

---

## Core Architecture and Features

- **Authenticated Hybrid Post-Quantum Handshake (PQC)**:
  - Cryptographic standard compliance: FIPS 203 (ML-KEM-768), RFC 7748 (X25519), and RFC 8032 (Ed25519).
  - **Formally Verified Curve Arithmetic (`filippo.io/edwards25519`)**: Constant-time birational Edwards-to-Montgomery coordinate conversion ($u = (1+y)/(1-y) \pmod{2^{255}-19}$) via audited `filippo.io/edwards25519` primitives (`Point.BytesMontgomery()`). Formally rejects neutral points ($y = 1$) and low-order points (order dividing 8) to eliminate small-subgroup confinement attacks.
  - **Precomputed Server Identity Cache (`ServerIdentity`)**: Concurrent thread-safe caching of Montgomery-derived private keys (`getOrDeriveServerXPriv`), bringing server identity derivation down to 25 ns/op with 0 allocations to eliminate CPU exhaustion attacks under unauthenticated UDP floods.
  - **Mutual Authentication and Anti-MITM**: The server signs the entire cryptographic transcript hash using an Ed25519 identity private key.
  - **Metadata Privacy and Untrackability (`TokenID` Blinding)**: Using ephemeral ECDH against the server's identity public key, client authentication tokens are blinded before transmission. Handshake packets from the same client present independent, pseudorandom wire representations indistinguishable from random noise, preventing traffic correlation and passive tracking during network roaming (Wi-Fi to cellular).
  - **Comprehensive Transcript Binding**: Keys are derived through HKDF-SHA256 (RFC 5869) binding SessionID, nonces, timestamps, and all public keys.

- **Directional ChaCha20-Poly1305 AEAD (RFC 8439) with Anti-Replay**:
  - **WireGuard / RFC 8439 Compliant Nonce**: Constant 32-bit zero prefix paired with a monotonic 64-bit sequence counter preventing key fingerprint leaks over the wire.
  - **Sliding Window Anti-Replay Protection (RFC 6479)**: 256-packet bitmap in `ShardAEAD` instantly rejecting replayed or out-of-order frames (`ErrReplayedPacket`) in approximately 15 ns.
  - **Direct UDP Demultiplexing**: Calibrated 1380-byte constant frame embeds an 8-byte `SessionID` authenticated inside Additional Authenticated Data (AAD).
  - **Directional Key Separation**: Derives distinct, isolated encryption keys (`c2sKey` for Client-to-Server, `s2cKey` for Server-to-Client).
  - **Nonce Overflow Latch**: Permanent latch returning `ErrKeyExhaustion` before sequence counter wrap-around to prevent key reuse.
  - **Memory Overlap Guard**: Strict detection of inexact slice overlaps (`anyOverlap`) safely returning `ErrInvalidBufferOverlap` to prevent buffer corruption.

- **AES-128 Salted Handshake Anti-Replay Cache (`AntiReplayCache`)**:
  - 64-shard partitioned structure indexed via hardware-accelerated AES-128 encryption (AES-NI). Attackers cannot predict or force hash collisions to target specific shards.
  - **Strict Time-Based Retention**: Handshake nonces remain immutable and non-evictable while their timestamp falls within the validity window ($T_{now} \le T_{expiry}$). If a shard reaches full capacity during a high-rate flood, the cache fails closed, preventing replay of captured handshakes within their time-to-live.
  - Strictly bounded memory footprint (~3 MB for 131,072 concurrent nonces).
  - Nonce freshness check in ~75 ns/op.

- **DoS-Resistant O(1) UDP Fragmentation and Reassembly (`HandshakeReassembler`)**:
  - Automatically splits oversized post-quantum handshake payloads into MTU-safe datagrams ($\le 659$ wire bytes; $\le 707$ bytes on IPv6+UDP).
  - **Per-Source Rate Limiting and Quotas (`FeedFrom`)**: Dynamic attribution by source address (`IP:port`) with configurable concurrency limits (`maxPendingPerSource = 4`) and rate limiters (`ErrSourceRateLimited`). Sessions with active progress ($\ge 2$ received fragments) are protected from eviction by incoming spoofed bursts.

- **Zero Allocation Memory Pooling (`sync.Pool`)**:
  - Fixed-array pointers (`*[1344]byte` and `*[1380]byte`) avoid heap escape of slice headers.
  - Sealing and opening throughput exceeding 1.70 GB/s per core with 0 B/op and 0 allocs/op.

- **Memory Hygiene and Secure Erasure (`Zeroize`)**:
  - Cryptographic buffers are zeroed using runtime `clear` combined with compiler optimization barriers (`runtime.KeepAlive`).

---

## Performance Benchmarks

Measured on an AMD Ryzen 5 3600 (Go 1.24+, Linux x86_64):

| Operation | Throughput / Speed | Latency | Real Memory Allocations |
| :--- | :---: | :---: | :---: |
| `SealFrame` (SessionID + RFC 8439 Nonce + ChaCha20-Poly1305) | 1,722.8 MB/s (~1.72 GB/s) | 780.1 ns/op | 0 B/op, 0 allocs/op |
| `OpenFrame` (AAD Auth + Decryption + 256-bit Anti-Replay) | 1,659.4 MB/s (~1.66 GB/s) | 809.9 ns/op | 0 B/op, 0 allocs/op |
| `SealFrame` In-Place (`&dst[0] == &src[0]`) | 1,673.4 MB/s (~1.67 GB/s) | 803.2 ns/op | 0 B/op, 0 allocs/op |
| `OpenFrame` In-Place (`&dst[0] == &src[0]`) | 1,493.9 MB/s (~1.49 GB/s) | 899.7 ns/op | 0 B/op, 0 allocs/op |
| `Seal` (Variable-length payload 1 KB) | 1,575.6 MB/s (~1.58 GB/s) | 649.9 ns/op | 0 B/op, 0 allocs/op |
| `Open` (Variable-length payload 1 KB) | 1,484.6 MB/s (~1.48 GB/s) | 689.7 ns/op | 0 B/op, 0 allocs/op |
| `Open` (Variable-length 1 KB with AAD metadata) | 1,300.7 MB/s (~1.30 GB/s) | 787.3 ns/op | 0 B/op, 0 allocs/op |
| `ClientHello` (X25519 + ML-KEM-768) | - | 124.2 us/op | 9.7 KB/op, 9 allocs/op |
| `ClientHello` Blinded (Constant-time birational ECDH) | - | 188.9 us/op | 11.0 KB/op, 28 allocs/op |
| `ServerHello` (ML-KEM + Ed25519 Signature + MAC) | - | 290.7 us/op | 13.3 KB/op, 69 allocs/op |
| `Ed25519ToX25519Pub` (Constant-time conversion) | - | 8.79 us/op | 96 B/op, 2 allocs/op |
| `ServerIdentity.Derivation` (Concurrent Montgomery cache) | - | 25.7 ns/op | 0 B/op, 0 allocs/op |
| `DatagramReassembly` (UDP fragmentation + O(1) assembly) | - | 1.60 us/op | 4.0 KB/op, 7 allocs/op |
| `TokenStore.Lookup` (O(1) lookup across 1,000 tokens) | - | 140.1 ns/op | 0 B/op, 0 allocs/op |
| `TokenID` (SHA-256 zero-allocation token hashing) | - | 99.4 ns/op | 0 B/op, 0 allocs/op |
| `AntiReplayCache` (AES-128 salting + adaptive eviction) | - | 76.9 ns/op | 16 B/op, 1 alloc/op |
| `SlidingWindowCheck` (RFC 6479 256-packet sequence check) | - | 15.6 ns/op | 0 B/op, 0 allocs/op |
| `BufferPools` (`Get` + `Put` full buffer recycling) | - | 69.4 ns/op | 0 B/op, 0 allocs/op |

---

## Installation

```bash
go get github.com/ihatemyfcklife/badcrypt
```

Requirements: **Go 1.24+** (utilizing standard library `crypto/mlkem` and `golang.org/x/crypto`).

---

## Quick Start & Usage Examples

### 1. Authenticated Post-Quantum Handshake (Stateless UDP Datagrams)

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/ihatemyfcklife/badcrypt"
)

func main() {
	// Server static Ed25519 identity key pair
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate server keys: %v", err)
	}

	// Production token store: concurrent safe, O(1) lookup in ~140 ns
	tokens := badcrypt.NewTokenStore()
	tokens.Add("client-token-prod")
	defer tokens.Close()

	// 1. Client side: generate ClientHello (ML-KEM-768 + X25519)
	// The token is blinded via ephemeral ECDH and transmitted as an unlinkable TokenID
	clientHello, clientPriv, decapsKey, nonce, err := badcrypt.GenerateClientHello("client-token-prod", serverPub)
	if err != nil {
		log.Fatalf("ClientHello failed: %v", err)
	}

	// 2. Server side: verify token in O(1), sign transcript with Ed25519, generate ServerHello
	var sessionID uint64 = 0x8899aabbccddeeff
	serverHello, serverSecret, token, err := badcrypt.ProcessClientHello(clientHello, serverPriv, tokens, sessionID)
	if err != nil {
		log.Fatalf("ProcessClientHello failed: %v", err)
	}

	// 3. Client side: verify server identity signature and Finished confirmation MAC
	rxSessionID, clientSecret, err := badcrypt.ProcessServerHello(
		clientHello, serverHello, clientPriv, decapsKey, nonce, "client-token-prod", serverPub,
	)
	if err != nil {
		log.Fatalf("ProcessServerHello failed: %v", err)
	}

	fmt.Printf("Session established: ID=%x Token=%s\n", rxSessionID, token)
	// clientSecret == serverSecret (32-byte master secret derived through HKDF-SHA256)
	_ = clientSecret
}
```

### 2. Stream-Based Handshake (`net.Conn`, TCP, QUIC Stream)

```go
// Server side: includes contextual deadlines and TokenStore integration
sessionID, secret, token, err := badcrypt.PerformServerHandshake(conn, serverPriv, tokens, sessionID)

// Client side: verifies server Ed25519 identity key
sessionID, secret, err := badcrypt.PerformClientHandshake(conn, "client-token-prod", serverPub)
```

### 3. Directional In-Place AEAD Encryption & Anti-Replay Sliding Window

```go
// Derive independent directional keys from shared master secret via HKDF
c2sKey, s2cKey := badcrypt.DeriveDirectionalAEADKeys(sharedSecret[:])

// Sender side: bound to sessionID
senderAEAD, err := badcrypt.NewShardAEADWithSession(c2sKey, sessionID)
if err != nil {
	log.Fatal(err)
}

// In-place zero-allocation frame sealing:
// buf contains plaintext at buf[:1344] with cap(buf) >= 1380
buf := badcrypt.GetWireFrameBuffer()
defer badcrypt.PutWireFrameBuffer(buf)
copy(buf[:1344], plaintextPayload)

sealedWire, err := senderAEAD.SealFrame(buf, buf[:1344])
if err != nil {
	log.Fatalf("SealFrame error: %v", err)
}

// Receiver side: decrypts in place, demultiplexes by SessionID, verifies anti-replay window
receiverAEAD, err := badcrypt.NewShardAEADWithSession(c2sKey, sessionID)
if err != nil {
	log.Fatal(err)
}

decrypted, err := receiverAEAD.OpenFrame(sealedWire, sealedWire)
if err != nil {
	log.Fatalf("Authentication or decryption failed: %v", err)
}

// Any duplicate wire packet received over the network is instantly rejected:
// _, err = receiverAEAD.OpenFrame(dst, replayedWirePacket) // returns badcrypt.ErrReplayedPacket
```

### 4. MTU Calibration & UDP Handshake Fragmentation

The calibrated Badcrypt wire frame has a constant length of `ConstantWireFrameSize = 1380` bytes (8B SessionID + 12B Nonce + 1344B Ciphertext + 16B Poly1305 Tag).

- **IPv4 overhead**: $1380 + 20 \text{ (IP)} + 8 \text{ (UDP)} = 1408\text{ bytes}$
- **IPv6 overhead**: $1380 + 40 \text{ (IP)} + 8 \text{ (UDP)} = 1428\text{ bytes}$

Both payloads fit within standard Ethernet links without fragmentation (**MTU 1500**).

For networks with constrained path MTUs (`IPv6MinMTU = 1280`, `SafeInternetMTU = 1232`, WireGuard MTU 1420/1280):
- **Application payloads**: Use variable-length `Seal` and `Open` with: $\text{PlaintextMax} = \text{MTU} - 48 - 20 - 16$.
- **PQC Handshakes**: `ClientHello` (1261 bytes) exceeds 1232 bytes under IPv6 ($1261 + 48 = 1309 > 1280$). To prevent packet drops, use native fragmentation:

```go
// Sender: split handshake into datagrams <= 659 wire bytes
frags, err := badcrypt.FragmentHandshakePayload(clientHello)
for _, frag := range frags {
    udpConn.WriteTo(frag, serverAddr)
}

// Receiver: bounded DoS-safe reassembly with source IP:port attribution
reassembler := badcrypt.NewHandshakeReassembler(512, 5*time.Second)
fullHello, ready, err := reassembler.FeedFrom(incomingDatagram, remoteAddr.String())
if ready {
    resp, secret, token, err := badcrypt.ProcessClientHello(fullHello, serverPriv, tokens, sessionID)
}
```

---

## Threat Model and Hardening Guarantees

The automated test suite (`hardening_test.go`) and continuous fuzzing (`fuzz_test.go`) validate the following defenses:

1. **Man-in-the-Middle (MITM) Prevention**: Handshake responses missing a valid Ed25519 signature over the full transcript hash are rejected (`ErrInvalidServerSignature`).
2. **Application Data Anti-Replay Protection**: `ShardAEAD` maintains an RFC 6479 256-packet bitmap. Stale or duplicate packet sequence numbers are rejected (`ErrReplayedPacket`).
3. **SessionID Integrity & Transcript Immutability**: SessionID, timestamps, and key material are authenticated inside AAD and bound via HKDF transcript hashes. Any modification in transit invalidates signatures and prevents key derivation.
4. **Metadata Privacy via TokenID Blinding**: Client identity tokens are dynamically blinded via ephemeral ECDH (Edwards-to-Montgomery birational equivalence, RFC 7748). Passive eavesdroppers observe high-entropy bytes indistinguishable from random noise, preventing correlation across IP changes.
5. **Flood-Resistant Replay Defense**: `AntiReplayCache` utilizes AES-128 salted indexing and strict time retention. Legitimate handshakes are never evicted prematurely during high-rate UDP flooding attacks.
6. **Cross-Direction and Cross-Session Isolation**: HKDF derives isolated key streams for each transmission direction (`c2s` vs `s2c`), and all frames enforce strict SessionID validation.
7. **Key Exhaustion Latch**: Nonce counters permanently latch at `ErrKeyExhaustion` before sequence overflow can occur.
8. **Memory Overlap Guard**: Detects partial buffer overlaps without crashing, gracefully returning `ErrInvalidBufferOverlap`.
9. **Zeroization on Authentication Failure**: Decrypted buffers are wiped from memory via `Zeroize` if subsequent integrity or sequence checks fail.
10. **Resource Cleanup (`Close`)**: Explicit teardown latches sequence counters, clears replay bitmaps, and zeroes sensitive memory buffers.
11. **Zero-Allocation Token Hashing**: Stack-allocated SHA-256 buffers avoid heap allocation during token lookup.
12. **Bounded AAD Buffer Pools**: Reusable AAD scratch buffers prevent allocations during authenticated frame processing.
13. **Deadliner Race Condition Immunity**: Stream handshakes prevent goroutine leaks and race conditions across deadline cancellations via synchronization barriers.
14. **Fragment Header Integrity**: `HandshakeReassembler` validates fragment bounds, prevents memory ballooning, and expires stale reassembly states.

---

## Testing, Verification and Fuzzing

```bash
# Run all unit and hardening tests
go test -v -count=1 ./...

# Run tests with race detection enabled
go test -race ./...

# Run memory allocation benchmarks
go test -bench=".*" -benchmem ./...

# Native Go continuous fuzzing
go test -fuzz=FuzzFrameDecoder -fuzztime=10s
go test -fuzz=FuzzHandshakeParser -fuzztime=10s
go test -fuzz=FuzzReplayCache -fuzztime=10s
go test -fuzz=FuzzAntiReplayWindow -fuzztime=10s
go test -fuzz=FuzzSlidingWindowSequence -fuzztime=10s
```

---

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for the full license text.
