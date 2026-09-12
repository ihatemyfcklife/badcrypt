package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

var (
	// MagicVectisHeader identifies Vectis protocol handshake datagrams.
	MagicVectisHeader = [4]byte{'V', 'E', 'C', 'T'}

	// ErrInvalidMagic is returned when a datagram does not start with MagicVectisHeader.
	ErrInvalidMagic = errors.New("crypto: invalid Vectis protocol magic")

	// ErrInvalidMsgType is returned when an unexpected handshake message type is encountered.
	ErrInvalidMsgType = errors.New("crypto: invalid handshake message type")

	// ErrUnauthorizedToken is returned when a client presents an unapproved or missing authentication token.
	ErrUnauthorizedToken = errors.New("crypto: unauthorized authentication token")

	// ErrTimestampDrift is returned when handshake timestamp is outside the allowed +/- 60s drift window.
	ErrTimestampDrift = errors.New("crypto: handshake timestamp outside allowed drift window (+/- 60s)")

	// ErrReplayedHandshake is returned when a duplicate handshake nonce is detected.
	ErrReplayedHandshake = errors.New("crypto: replayed client handshake detected")

	// ErrHandshakeMalformed is returned when a handshake payload is truncated or invalid.
	ErrHandshakeMalformed = errors.New("crypto: malformed handshake payload")

	// ErrInvalidServerSignature is returned when the server's Ed25519 signature fails verification (MITM attack).
	ErrInvalidServerSignature = errors.New("crypto: invalid server Ed25519 identity signature (MITM detected)")

	// ErrInvalidFinishedMAC is returned when the server confirmation MAC does not verify.
	ErrInvalidFinishedMAC = errors.New("crypto: invalid handshake finished confirmation MAC")

	// ErrEmptyToken is returned when an empty authentication token is provided.
	ErrEmptyToken = errors.New("crypto: authentication token cannot be empty")

	// ErrInvalidServerKey is returned when the server's Ed25519 key has an invalid length or format.
	ErrInvalidServerKey = errors.New("crypto: invalid server Ed25519 key")

	// ErrHandshakeTimeout is returned when a stream handshake exceeds its deadline.
	ErrHandshakeTimeout = errors.New("crypto: handshake timed out or deadline exceeded")

	// ErrReassemblyBufferFull is returned when the handshake datagram reassembler exceeds its pending capacity.
	ErrReassemblyBufferFull = errors.New("crypto: handshake datagram reassembly buffer full")

	// ErrSourceRateLimited is returned when a source endpoint exceeds the allowed reassembly rate or concurrent session quota.
	ErrSourceRateLimited = errors.New("crypto: handshake datagram reassembly source rate limit exceeded")
)

const (
	// TypeClientHello indicates a client handshake initiator message.
	TypeClientHello = 0x01

	// TypeServerHello indicates a server handshake response message.
	TypeServerHello = 0x02

	// TypeClientHelloFrag indicates a fragmented client handshake datagram (for MTU <= 1280 / UDP).
	TypeClientHelloFrag = 0x03

	// TypeServerHelloFrag indicates a fragmented server handshake datagram (for MTU <= 1280 / UDP).
	TypeServerHelloFrag = 0x04

	// FragHeaderSize is the wire size of the datagram fragment framing header:
	// Magic (4) + Type (1) + FragID (8) + FragIndex (1) + TotalFrags (1) + FragOffset (2) + TotalLen (2) = 19 bytes.
	FragHeaderSize = 4 + 1 + 8 + 1 + 1 + 2 + 2

	// MaxDatagramChunkSize is the max payload chunk per UDP datagram fragment.
	// Wire size: 19 + 640 = 659 bytes (IPv6+UDP = 707 bytes <= 1232 SafeInternetMTU).
	MaxDatagramChunkSize = 640

	// TokenIDSize is the size of the public token identifier in bytes (SHA-256 truncated).
	TokenIDSize = 16

	// ClientHelloSize is the exact wire size of ClientHello:
	// Magic (4) + Type (1) + TokenID (16) + Timestamp (8) + Nonce (16) + X25519 Pub (32) + ML-KEM-768 Pub (1184) = 1261 bytes.
	ClientHelloSize = 4 + 1 + TokenIDSize + 8 + 16 + 32 + 1184

	// ServerHelloPreSigSize is the ServerHello payload covered by the Ed25519 signature:
	// Magic (4) + Type (1) + SessionID (8) + Server X25519 Pub (32) + ML-KEM-768 Ciphertext (1088) = 1133 bytes.
	ServerHelloPreSigSize = 4 + 1 + 8 + 32 + 1088

	// ServerHelloSize is the exact wire size of ServerHello:
	// PreSig (1133) + Server Ed25519 Sig (64) + Finished MAC (32) = 1229 bytes.
	ServerHelloSize = ServerHelloPreSigSize + ed25519.SignatureSize + sha256.Size

	// MaxTimestampDriftSeconds defines the maximum allowed clock drift between peers.
	MaxTimestampDriftSeconds = 60

	// DefaultHandshakeTimeout is the standard network stream handshake deadline.
	DefaultHandshakeTimeout = 5 * time.Second

	// ShardCount is the number of partitioned shards in AntiReplayCache to eliminate mutex contention.
	ShardCount = 64

	// EntriesPerShard is the capacity of each shard ring buffer (total 131,072 nonces, bounded ~3MB RAM).
	EntriesPerShard = 2048
)

type cacheEntry struct {
	nonce  [16]byte
	expiry int64
}

type cacheShard struct {
	mu     sync.Mutex
	lookup map[[16]byte]int
	ring   [EntriesPerShard]cacheEntry
	head   int
}

// AntiReplayCache tracks recently observed handshake nonces to prevent replay attacks.
// It is partitioned into shards with cryptographically salted hashing and time-based retention,
// guaranteeing that nonces are never prematurely evicted within the validity window (~3 MB bounded memory).
type AntiReplayCache struct {
	shards    [ShardCount]cacheShard
	aesCipher cipher.Block
}

// NewAntiReplayCache initializes a bounded, DoS-resistant anti-replay cache with random AES salting.
func NewAntiReplayCache() *AntiReplayCache {
	var salt [16]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		binary.BigEndian.PutUint64(salt[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(salt[8:], 0x5a5a5a5a5a5a5a5a)
	}
	block, _ := aes.NewCipher(salt[:])
	c := &AntiReplayCache{aesCipher: block}
	for i := range c.shards {
		c.shards[i].lookup = make(map[[16]byte]int, EntriesPerShard)
	}
	return c
}

func (c *AntiReplayCache) getShardIndex(nonce []byte) int {
	if c == nil || len(nonce) != 16 {
		return 0
	}
	if c.aesCipher != nil {
		var enc [16]byte
		c.aesCipher.Encrypt(enc[:], nonce)
		return int(binary.BigEndian.Uint16(enc[:2])) % ShardCount
	}
	return int(binary.BigEndian.Uint16(nonce[:2])) % ShardCount
}

// Reset clears all recorded nonces in the cache.
func (c *AntiReplayCache) Reset() {
	if c == nil {
		return
	}
	for i := range c.shards {
		shard := &c.shards[i]
		shard.mu.Lock()
		clear(shard.lookup)
		clear(shard.ring[:])
		shard.head = 0
		shard.mu.Unlock()
	}
}

// Close gracefully releases any cache resources by resetting all shards.
func (c *AntiReplayCache) Close() {
	c.Reset()
}

// AddOrCheck returns true if the nonce was already seen (replay detected).
// Returns false and registers the nonce if it is fresh.
// Expiry is set to now + 2*MaxTimestampDriftSeconds + 1.
func (c *AntiReplayCache) AddOrCheck(nonce []byte) bool {
	now := time.Now().Unix()
	return c.AddOrCheckWithExpiry(nonce, now+2*MaxTimestampDriftSeconds+1)
}

// AddOrCheckWithTime registers or checks a nonce with a reference timestamp.
// The entry remains valid and protected from eviction until msgTime + MaxTimestampDriftSeconds + 1.
func (c *AntiReplayCache) AddOrCheckWithTime(nonce []byte, msgTime int64) bool {
	return c.AddOrCheckWithExpiry(nonce, msgTime+MaxTimestampDriftSeconds+1)
}

// AddOrCheckWithExpiry registers or checks a nonce with an explicit expiration unix timestamp.
// Entries are retained and protected from eviction while now <= expiry.
func (c *AntiReplayCache) AddOrCheckWithExpiry(nonce []byte, expiry int64) bool {
	if c == nil || len(nonce) != 16 {
		return true
	}

	shardIdx := c.getShardIndex(nonce)
	shard := &c.shards[shardIdx]

	var k [16]byte
	copy(k[:], nonce)

	now := time.Now().Unix()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if shard.lookup == nil {
		shard.lookup = make(map[[16]byte]int, EntriesPerShard)
	}

	// 1. Check if already present
	if idx, exists := shard.lookup[k]; exists {
		ent := &shard.ring[idx]
		if now <= ent.expiry {
			// Unexpired duplicate -> REPLAY!
			return true
		}
		// Expired entry found: refresh in-place in its existing slot!
		// Perfectly synchronized: no duplicate in ring, no ghost entries.
		ent.expiry = expiry
		return false
	}

	// 2. If at capacity, purge expired entries
	if len(shard.lookup) >= EntriesPerShard {
		for i := 0; i < EntriesPerShard; i++ {
			ent := &shard.ring[i]
			if ent.expiry != 0 && now > ent.expiry {
				delete(shard.lookup, ent.nonce)
				ent.expiry = 0
			}
		}
		// If still at capacity after purging expired entries:
		// All entries in this shard are unexpired! Strict anti-replay guarantee:
		// NEVER evict an unexpired nonce before its expiry timestamp.
		// Failing closed guarantees that an attacker flooding UDP packets
		// can NEVER force the eviction of a legitimate captured handshake
		// to replay it before its validity window expires.
		if len(shard.lookup) >= EntriesPerShard {
			return true
		}
	}

	// 3. Store new nonce in an available (empty or expired) ring slot
	for i := 0; i < EntriesPerShard; i++ {
		slotIdx := shard.head
		shard.head = (shard.head + 1) % EntriesPerShard
		slot := &shard.ring[slotIdx]
		if slot.expiry == 0 || now > slot.expiry {
			if slot.expiry != 0 {
				delete(shard.lookup, slot.nonce)
			}
			slot.nonce = k
			slot.expiry = expiry
			shard.lookup[k] = slotIdx
			return false
		}
	}

	// Saturated with unexpired nonces: strictly fail closed
	return true
}

var globalReplayCache = NewAntiReplayCache()

// ResetGlobalReplayCache resets the package-level default AntiReplayCache.
func ResetGlobalReplayCache() {
	globalReplayCache.Reset()
}

const tokenPrefix = "vectis-token-id-v1:"

// TokenID computes the 16-byte public token identifier for database lookup without revealing the token.
// All temporary secret buffers are wiped from memory before returning.
func TokenID(token string) [16]byte {
	var id [16]byte
	totalLen := len(tokenPrefix) + len(token)

	var stackBuf [128]byte
	var b []byte
	if totalLen <= len(stackBuf) {
		b = stackBuf[:totalLen]
	} else {
		b = make([]byte, totalLen)
	}

	copy(b[:len(tokenPrefix)], tokenPrefix)
	copy(b[len(tokenPrefix):], token)

	digest := sha256.Sum256(b)
	copy(id[:], digest[:16])

	Zeroize(b)
	Zeroize(digest[:])
	return id
}

// TokenValidator defines an interface for authenticating client TokenIDs.
type TokenValidator interface {
	ValidateTokenID(tokenID []byte) (token string, ok bool)
}

// TokenStore provides concurrent-safe, O(1) token lookup indexed by 16-byte TokenID.
// It prevents CPU DoS under UDP floods, eliminates map concurrency data races,
// and securely wipes tokens on removal or close.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[[16]byte]string
}

// NewTokenStore creates an empty, thread-safe TokenStore.
func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens: make(map[[16]byte]string),
	}
}

// NewTokenStoreWithTokens initializes a TokenStore populated with the provided tokens.
func NewTokenStoreWithTokens(tokens ...string) *TokenStore {
	s := NewTokenStore()
	for _, tok := range tokens {
		s.Add(tok)
	}
	return s
}

// Add securely registers an authorized token into the store, indexed by its public 16-byte TokenID.
func (s *TokenStore) Add(token string) {
	if s == nil || len(token) == 0 {
		return
	}
	tid := TokenID(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tid] = token
}

// Remove deletes a token from the store.
func (s *TokenStore) Remove(token string) {
	if s == nil || len(token) == 0 {
		return
	}
	tid := TokenID(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, tid)
}

// ValidateTokenID performs an O(1) concurrent-safe lookup for tokenID (16 bytes).
// It confirms authentication using constant-time comparison against the stored token.
func (s *TokenStore) ValidateTokenID(tokenID []byte) (string, bool) {
	if s == nil || len(tokenID) != TokenIDSize {
		return "", false
	}
	var key [16]byte
	copy(key[:], tokenID)

	s.mu.RLock()
	tok, exists := s.tokens[key]
	s.mu.RUnlock()

	if !exists {
		return "", false
	}

	expectedID := TokenID(tok)
	if subtle.ConstantTimeCompare(expectedID[:], key[:]) != 1 {
		return "", false
	}
	return tok, true
}

// Count returns the number of active authorized tokens in the store.
func (s *TokenStore) Count() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens)
}

// Close securely clears all tokens from the store.
func (s *TokenStore) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.tokens)
}

// ed25519ToX25519Priv converts an Ed25519 private key/seed to an X25519 private key.
func ed25519ToX25519Priv(edPriv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	if len(edPriv) == ed25519.SeedSize {
		edPriv = ed25519.NewKeyFromSeed(edPriv)
	}
	if len(edPriv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidServerKey
	}
	seed := edPriv.Seed()
	h := sha512.Sum512(seed)
	var scalar [32]byte
	copy(scalar[:], h[:32])
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	priv, err := ecdh.X25519().NewPrivateKey(scalar[:])
	Zeroize(scalar[:])
	Zeroize(h[:])
	return priv, err
}

// ServerIdentity holds a server's long-term identity keys, caching the Montgomery
// X25519 key derivation to avoid recomputation under high throughput.
type ServerIdentity struct {
	EdPriv ed25519.PrivateKey
	EdPub  ed25519.PublicKey
	XPriv  *ecdh.PrivateKey
	XPub   *ecdh.PublicKey
}

// NewServerIdentity precomputes and caches the Montgomery X25519 keys
// corresponding to the given Ed25519 private key.
func NewServerIdentity(edPriv ed25519.PrivateKey) (*ServerIdentity, error) {
	if len(edPriv) == ed25519.SeedSize {
		edPriv = ed25519.NewKeyFromSeed(edPriv)
	}
	if len(edPriv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidServerKey
	}
	xPriv, err := ed25519ToX25519Priv(edPriv)
	if err != nil {
		return nil, err
	}
	edPub := edPriv.Public().(ed25519.PublicKey)
	xPub, err := ed25519ToX25519Pub(edPub)
	if err != nil {
		return nil, err
	}
	return &ServerIdentity{
		EdPriv: edPriv,
		EdPub:  edPub,
		XPriv:  xPriv,
		XPub:   xPub,
	}, nil
}

var serverXPrivCache sync.Map // map[[32]byte]*ecdh.PrivateKey

// getOrDeriveServerXPriv retrieves the cached Montgomery private key or computes and caches it.
func getOrDeriveServerXPriv(edPriv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	if len(edPriv) == ed25519.SeedSize {
		edPriv = ed25519.NewKeyFromSeed(edPriv)
	}
	if len(edPriv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidServerKey
	}
	var cacheKey [32]byte
	copy(cacheKey[:], edPriv.Seed())
	if val, ok := serverXPrivCache.Load(cacheKey); ok {
		return val.(*ecdh.PrivateKey), nil
	}
	xPriv, err := ed25519ToX25519Priv(edPriv)
	if err != nil {
		return nil, err
	}
	serverXPrivCache.Store(cacheKey, xPriv)
	return xPriv, nil
}

const tokenMaskContext = "vectis-token-mask-v1:"

func deriveTokenMask(sharedDH []byte, nonce []byte) ([16]byte, error) {
	var mask [16]byte
	prk := hkdf.Extract(sha256.New, sharedDH, nonce)
	defer Zeroize(prk)
	r := hkdf.Expand(sha256.New, prk, []byte(tokenMaskContext))
	if _, err := io.ReadFull(r, mask[:]); err != nil {
		return mask, err
	}
	return mask, nil
}

// GenerateClientHello creates a ClientHello datagram payload for PQC handshake.
// When serverEdPub is supplied, TokenID is blinded using ephemeral ECDH against the server's identity key,
// rendering the wire TokenID statistically indistinguishable from uniform random noise and preventing
// passive network correlation across roaming IP addresses.
func GenerateClientHello(token string, serverEdPub ...ed25519.PublicKey) (payload []byte, clientPriv *ecdh.PrivateKey, decapsKey *mlkem.DecapsulationKey768, nonce []byte, err error) {
	if len(token) == 0 {
		return nil, nil, nil, nil, ErrEmptyToken
	}

	x25519Curve := ecdh.X25519()
	clientPriv, err = x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}
	clientPubKey := clientPriv.PublicKey().Bytes()

	decapsKey, err = mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate ML-KEM key: %w", err)
	}
	mlkemPubKey := decapsKey.EncapsulationKey().Bytes()

	nonce = make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate handshake nonce: %w", err)
	}

	payload = make([]byte, ClientHelloSize)
	copy(payload[0:4], MagicVectisHeader[:])
	payload[4] = TypeClientHello

	// 16-byte public TokenID (with optional ephemeral blinding for zero-linkability privacy)
	tid := TokenID(token)
	if len(serverEdPub) > 0 && len(serverEdPub[0]) == ed25519.PublicKeySize {
		serverXPub, err := ed25519ToX25519Pub(serverEdPub[0])
		if err == nil {
			sharedDH, err := clientPriv.ECDH(serverXPub)
			if err == nil {
				mask, err := deriveTokenMask(sharedDH, nonce)
				Zeroize(sharedDH)
				if err == nil {
					for i := 0; i < 16; i++ {
						tid[i] ^= mask[i]
					}
					Zeroize(mask[:])
				}
			}
		}
	}
	copy(payload[5:21], tid[:])

	// Timestamp
	binary.BigEndian.PutUint64(payload[21:29], uint64(time.Now().Unix()))

	// Nonce
	copy(payload[29:45], nonce)

	// Keys
	copy(payload[45:77], clientPubKey)
	copy(payload[77:ClientHelloSize], mlkemPubKey)

	return payload, clientPriv, decapsKey, nonce, nil
}

// ProcessClientHello verifies the ClientHello and generates a signed, authenticated ServerHello.
// The tokens argument accepts a *TokenStore, any TokenValidator implementation, or legacy map[string]bool.
func ProcessClientHello(
	payload []byte,
	serverEdPriv ed25519.PrivateKey,
	tokens any,
	assignSessionID uint64,
) (respPayload []byte, sessionSecret [32]byte, token string, err error) {
	return ProcessClientHelloWithCache(payload, serverEdPriv, tokens, assignSessionID, globalReplayCache)
}

// ProcessClientHelloWithCache verifies the ClientHello against a specific AntiReplayCache instance.
// The tokens argument accepts a *TokenStore, any TokenValidator implementation, or legacy map[string]bool.
func ProcessClientHelloWithCache(
	payload []byte,
	serverEdPriv ed25519.PrivateKey,
	tokens any,
	assignSessionID uint64,
	cache *AntiReplayCache,
) (respPayload []byte, sessionSecret [32]byte, token string, err error) {
	var emptySecret [32]byte
	if len(serverEdPriv) == ed25519.SeedSize {
		serverEdPriv = ed25519.NewKeyFromSeed(serverEdPriv)
	}
	if len(serverEdPriv) != ed25519.PrivateKeySize {
		return nil, emptySecret, "", ErrInvalidServerKey
	}
	if len(payload) != ClientHelloSize {
		return nil, emptySecret, "", ErrHandshakeMalformed
	}

	if !bytes.Equal(payload[0:4], MagicVectisHeader[:]) {
		return nil, emptySecret, "", ErrInvalidMagic
	}
	if payload[4] != TypeClientHello {
		return nil, emptySecret, "", ErrInvalidMsgType
	}

	// Token lookup by TokenID (constant-time evaluation)
	if tokens == nil {
		return nil, emptySecret, "", ErrUnauthorizedToken
	}

	// Unmask candidate TokenIDs (privacy unmasking with backward-compatible fallback)
	rxTokenID := payload[5:21]
	clientPubKeyBytes := payload[45:77]
	nonce := payload[29:45]

	var candidateIDs [][16]byte
	serverXPriv, err := getOrDeriveServerXPriv(serverEdPriv)
	if err == nil {
		x25519Curve := ecdh.X25519()
		clientPub, err := x25519Curve.NewPublicKey(clientPubKeyBytes)
		if err == nil {
			sharedDH, err := serverXPriv.ECDH(clientPub)
			if err == nil {
				mask, err := deriveTokenMask(sharedDH, nonce)
				Zeroize(sharedDH)
				if err == nil {
					var unmasked [16]byte
					for i := 0; i < 16; i++ {
						unmasked[i] = rxTokenID[i] ^ mask[i]
					}
					Zeroize(mask[:])
					candidateIDs = append(candidateIDs, unmasked)
				}
			}
		}
	}
	// Fallback for unmasked legacy clients
	var rawID [16]byte
	copy(rawID[:], rxTokenID)
	candidateIDs = append(candidateIDs, rawID)

	var matchedToken string
	var found bool

	for _, candID := range candidateIDs {
		switch tv := tokens.(type) {
		case TokenValidator:
			matchedToken, found = tv.ValidateTokenID(candID[:])
		case map[string]bool:
			if len(tv) == 0 {
				return nil, emptySecret, "", ErrUnauthorizedToken
			}
			for validTok, authorized := range tv {
				if !authorized || len(validTok) == 0 {
					continue
				}
				tid := TokenID(validTok)
				if subtle.ConstantTimeCompare(candID[:], tid[:]) == 1 {
					matchedToken = validTok
					found = true
					break
				}
			}
		default:
			return nil, emptySecret, "", ErrUnauthorizedToken
		}
		if found && len(matchedToken) > 0 {
			break
		}
	}

	if !found || len(matchedToken) == 0 {
		return nil, emptySecret, "", ErrUnauthorizedToken
	}

	// Clock drift validation (strictly overflow-proof)
	now := time.Now().Unix()
	tsUint := binary.BigEndian.Uint64(payload[21:29])
	if tsUint > math.MaxInt64 {
		return nil, emptySecret, "", ErrTimestampDrift
	}
	tsInt := int64(tsUint)
	if tsInt < now-MaxTimestampDriftSeconds || tsInt > now+MaxTimestampDriftSeconds {
		return nil, emptySecret, "", ErrTimestampDrift
	}

	// Anti-replay validation with time-based retention
	if cache != nil && cache.AddOrCheckWithTime(nonce, tsInt) {
		return nil, emptySecret, "", ErrReplayedHandshake
	}

	clientMlkemPubKeyBytes := payload[77:ClientHelloSize]

	// Ephemeral Server X25519
	x25519Curve := ecdh.X25519()
	serverX25519Priv, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, emptySecret, "", fmt.Errorf("failed to generate server X25519 key: %w", err)
	}

	clientPubKey, err := x25519Curve.NewPublicKey(clientPubKeyBytes)
	if err != nil {
		return nil, emptySecret, "", fmt.Errorf("invalid client X25519 key: %w", err)
	}

	x25519Shared, err := serverX25519Priv.ECDH(clientPubKey)
	if err != nil {
		return nil, emptySecret, "", fmt.Errorf("X25519 ECDH computation failed: %w", err)
	}

	// Server ML-KEM-768 encapsulation
	clientMlkemEncapsKey, err := mlkem.NewEncapsulationKey768(clientMlkemPubKeyBytes)
	if err != nil {
		Zeroize(x25519Shared)
		return nil, emptySecret, "", fmt.Errorf("invalid client ML-KEM key: %w", err)
	}

	mlkemShared, mlkemCiphertext := clientMlkemEncapsKey.Encapsulate()

	// Assemble ServerHello pre-signature portion:
	// Magic(4) + Type(1) + SessionID(8) + ServerX25519Pub(32) + MLKEMCiphertext(1088) = 1133 bytes
	respPayload = make([]byte, ServerHelloSize)
	copy(respPayload[0:4], MagicVectisHeader[:])
	respPayload[4] = TypeServerHello
	binary.BigEndian.PutUint64(respPayload[5:13], assignSessionID)
	copy(respPayload[13:45], serverX25519Priv.PublicKey().Bytes())
	copy(respPayload[45:ServerHelloPreSigSize], mlkemCiphertext)

	// Compute TranscriptHash = SHA256(ClientHello || ServerHelloPreSig)
	transcript := sha256.New()
	transcript.Write(payload[:ClientHelloSize])
	transcript.Write(respPayload[:ServerHelloPreSigSize])
	transcriptHash := transcript.Sum(nil)

	// Sign TranscriptHash with server Ed25519 identity key (anti-MITM)
	serverSig := ed25519.Sign(serverEdPriv, transcriptHash)
	copy(respPayload[ServerHelloPreSigSize:ServerHelloPreSigSize+ed25519.SignatureSize], serverSig)

	// Derive Master Secret and Keys using HKDF-SHA256 (RFC 5869)
	var ikm [64 + 32]byte
	copy(ikm[0:32], x25519Shared)
	copy(ikm[32:64], mlkemShared)
	bToken := []byte(matchedToken)
	tokenHash := sha256.Sum256(bToken)
	Zeroize(bToken)
	copy(ikm[64:96], tokenHash[:])

	prk := hkdf.Extract(sha256.New, ikm[:], nonce)
	Zeroize(ikm[:])
	Zeroize(x25519Shared)
	Zeroize(mlkemShared)
	Zeroize(tokenHash[:])
	defer Zeroize(prk)

	// Session Secret (for data encryption)
	var sessionInfo [24 + sha256.Size]byte
	copy(sessionInfo[:24], "vectis-session-secret-v1:")
	copy(sessionInfo[24:], transcriptHash)

	kdfSession := hkdf.Expand(sha256.New, prk, sessionInfo[:])
	if _, err := io.ReadFull(kdfSession, sessionSecret[:]); err != nil {
		Zeroize(sessionSecret[:])
		return nil, emptySecret, "", err
	}

	// Finished Confirmation MAC Key
	var macKey [32]byte
	var macInfo [22 + sha256.Size]byte
	copy(macInfo[:22], "vectis-finished-mac-v1:")
	copy(macInfo[22:], transcriptHash)

	kdfMAC := hkdf.Expand(sha256.New, prk, macInfo[:])
	if _, err := io.ReadFull(kdfMAC, macKey[:]); err != nil {
		Zeroize(macKey[:])
		Zeroize(sessionSecret[:])
		return nil, emptySecret, "", err
	}

	// Compute Finished MAC over TranscriptHash
	hm := hmac.New(sha256.New, macKey[:])
	hm.Write(transcriptHash)
	finishedMAC := hm.Sum(nil)
	Zeroize(macKey[:])
	copy(respPayload[ServerHelloPreSigSize+ed25519.SignatureSize:ServerHelloSize], finishedMAC)

	return respPayload, sessionSecret, matchedToken, nil
}

// ProcessServerHello decapsulates ServerHello, verifies server Ed25519 signature and Finished MAC.
func ProcessServerHello(
	clientHelloPayload []byte,
	respPayload []byte,
	clientPriv *ecdh.PrivateKey,
	decapsKey *mlkem.DecapsulationKey768,
	nonce []byte,
	token string,
	serverEdPub ed25519.PublicKey,
) (sessionID uint64, sessionSecret [32]byte, err error) {
	var emptySecret [32]byte
	if clientPriv == nil || decapsKey == nil {
		return 0, emptySecret, ErrHandshakeMalformed
	}
	if len(respPayload) != ServerHelloSize {
		return 0, emptySecret, ErrHandshakeMalformed
	}
	if len(clientHelloPayload) != ClientHelloSize {
		return 0, emptySecret, ErrHandshakeMalformed
	}
	if len(nonce) != 16 || !bytes.Equal(nonce, clientHelloPayload[29:45]) {
		return 0, emptySecret, ErrHandshakeMalformed
	}

	if !bytes.Equal(respPayload[0:4], MagicVectisHeader[:]) {
		return 0, emptySecret, ErrInvalidMagic
	}
	if respPayload[4] != TypeServerHello {
		return 0, emptySecret, ErrInvalidMsgType
	}

	// 1. Verify Server Ed25519 Identity Signature over TranscriptHash (anti-MITM)
	if len(serverEdPub) != ed25519.PublicKeySize {
		return 0, emptySecret, fmt.Errorf("%w: %w", ErrInvalidServerSignature, ErrInvalidServerKey)
	}

	transcript := sha256.New()
	transcript.Write(clientHelloPayload[:ClientHelloSize])
	transcript.Write(respPayload[:ServerHelloPreSigSize])
	transcriptHash := transcript.Sum(nil)

	serverSig := respPayload[ServerHelloPreSigSize : ServerHelloPreSigSize+ed25519.SignatureSize]
	if !ed25519.Verify(serverEdPub, transcriptHash, serverSig) {
		return 0, emptySecret, ErrInvalidServerSignature
	}

	sessionID = binary.BigEndian.Uint64(respPayload[5:13])
	serverX25519PubKeyBytes := respPayload[13:45]
	mlkemCiphertext := respPayload[45:ServerHelloPreSigSize]

	// 2. Compute X25519 shared secret
	x25519Curve := ecdh.X25519()
	serverX25519PubKey, err := x25519Curve.NewPublicKey(serverX25519PubKeyBytes)
	if err != nil {
		return 0, emptySecret, fmt.Errorf("invalid server X25519 key: %w", err)
	}
	x25519Shared, err := clientPriv.ECDH(serverX25519PubKey)
	if err != nil {
		return 0, emptySecret, fmt.Errorf("client X25519 ECDH computation failed: %w", err)
	}

	// 3. Decapsulate ML-KEM-768
	mlkemShared, err := decapsKey.Decapsulate(mlkemCiphertext)
	if err != nil {
		Zeroize(x25519Shared)
		return 0, emptySecret, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
	}

	// 4. Derive Master Secret and Keys using HKDF-SHA256
	var ikm [64 + 32]byte
	copy(ikm[0:32], x25519Shared)
	copy(ikm[32:64], mlkemShared)
	bToken := []byte(token)
	tokenHash := sha256.Sum256(bToken)
	Zeroize(bToken)
	copy(ikm[64:96], tokenHash[:])

	prk := hkdf.Extract(sha256.New, ikm[:], nonce)
	Zeroize(ikm[:])
	Zeroize(x25519Shared)
	Zeroize(mlkemShared)
	Zeroize(tokenHash[:])
	defer Zeroize(prk)

	// 5. Verify Finished Confirmation MAC BEFORE deriving session secret (Verify-Before-Derive)
	var macKey [32]byte
	var macInfo [22 + sha256.Size]byte
	copy(macInfo[:22], "vectis-finished-mac-v1:")
	copy(macInfo[22:], transcriptHash)

	kdfMAC := hkdf.Expand(sha256.New, prk, macInfo[:])
	if _, err := io.ReadFull(kdfMAC, macKey[:]); err != nil {
		Zeroize(macKey[:])
		return 0, emptySecret, err
	}

	hm := hmac.New(sha256.New, macKey[:])
	hm.Write(transcriptHash)
	expectedMAC := hm.Sum(nil)
	Zeroize(macKey[:])
	rxMAC := respPayload[ServerHelloPreSigSize+ed25519.SignatureSize : ServerHelloSize]

	if subtle.ConstantTimeCompare(expectedMAC, rxMAC) != 1 {
		return 0, emptySecret, ErrInvalidFinishedMAC
	}

	// 6. Finished MAC verified: now derive the Session Secret
	var sessionInfo [24 + sha256.Size]byte
	copy(sessionInfo[:24], "vectis-session-secret-v1:")
	copy(sessionInfo[24:], transcriptHash)

	kdfSession := hkdf.Expand(sha256.New, prk, sessionInfo[:])
	if _, err := io.ReadFull(kdfSession, sessionSecret[:]); err != nil {
		Zeroize(sessionSecret[:])
		return 0, emptySecret, err
	}

	return sessionID, sessionSecret, nil
}

// PerformClientHandshake executes the full PQC handshake over any io.ReadWriter stream with a default 5s timeout.
func PerformClientHandshake(conn io.ReadWriter, token string, serverEdPub ed25519.PublicKey) (sessionID uint64, sessionSecret [32]byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultHandshakeTimeout)
	defer cancel()
	return PerformClientHandshakeContext(ctx, conn, token, serverEdPub)
}

func wrapStreamError(ctx context.Context, op string, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %w (%s)", ErrHandshakeTimeout, ctx.Err(), op)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("%w: %w (%s)", ErrHandshakeTimeout, err, op)
	}
	return fmt.Errorf("%s: %w", op, err)
}

type deadliner interface {
	SetDeadline(t time.Time) error
}

// PerformClientHandshakeContext executes the full PQC handshake over any io.ReadWriter stream with a context deadline.
func PerformClientHandshakeContext(
	ctx context.Context,
	conn io.ReadWriter,
	token string,
	serverEdPub ed25519.PublicKey,
) (sessionID uint64, sessionSecret [32]byte, err error) {
	if conn == nil {
		return 0, [32]byte{}, errors.New("crypto: nil connection provided")
	}
	if err := ctx.Err(); err != nil {
		return 0, [32]byte{}, fmt.Errorf("%w: %w (handshake context cancelled before start)", ErrHandshakeTimeout, err)
	}

	if d, ok := conn.(deadliner); ok {
		if deadline, ok := ctx.Deadline(); ok {
			_ = d.SetDeadline(deadline)
		}
		done := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				_ = d.SetDeadline(time.Now())
			case <-done:
			}
		}()
		defer func() {
			close(done)
			wg.Wait()
			_ = d.SetDeadline(time.Time{})
		}()
	}

	hello, priv, decaps, nonce, err := GenerateClientHello(token, serverEdPub)
	if err != nil {
		return 0, [32]byte{}, err
	}

	if _, err := conn.Write(hello); err != nil {
		return 0, [32]byte{}, wrapStreamError(ctx, "failed to send client hello", err)
	}

	resp := make([]byte, ServerHelloSize)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, [32]byte{}, wrapStreamError(ctx, "failed to read server hello", err)
	}

	return ProcessServerHello(hello, resp, priv, decaps, nonce, token, serverEdPub)
}

// PerformServerHandshake executes the server side of the PQC handshake with a default 5s timeout.
func PerformServerHandshake(
	conn io.ReadWriter,
	serverEdPriv ed25519.PrivateKey,
	tokens any,
	assignSessionID uint64,
) (sessionID uint64, sessionSecret [32]byte, token string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultHandshakeTimeout)
	defer cancel()
	return PerformServerHandshakeContext(ctx, conn, serverEdPriv, tokens, assignSessionID)
}

// PerformServerHandshakeContext executes the server side of the PQC handshake with a context deadline.
// The tokens argument accepts a *TokenStore, any TokenValidator implementation, or legacy map[string]bool.
func PerformServerHandshakeContext(
	ctx context.Context,
	conn io.ReadWriter,
	serverEdPriv ed25519.PrivateKey,
	tokens any,
	assignSessionID uint64,
) (sessionID uint64, sessionSecret [32]byte, token string, err error) {
	if conn == nil {
		return 0, [32]byte{}, "", errors.New("crypto: nil connection provided")
	}
	if err := ctx.Err(); err != nil {
		return 0, [32]byte{}, "", fmt.Errorf("%w: %w (handshake context cancelled before start)", ErrHandshakeTimeout, err)
	}

	if d, ok := conn.(deadliner); ok {
		if deadline, ok := ctx.Deadline(); ok {
			_ = d.SetDeadline(deadline)
		}
		done := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				_ = d.SetDeadline(time.Now())
			case <-done:
			}
		}()
		defer func() {
			close(done)
			wg.Wait()
			_ = d.SetDeadline(time.Time{})
		}()
	}

	clientPayload := make([]byte, ClientHelloSize)
	if _, err := io.ReadFull(conn, clientPayload); err != nil {
		return 0, [32]byte{}, "", wrapStreamError(ctx, "failed to read client hello", err)
	}

	resp, secret, token, err := ProcessClientHello(clientPayload, serverEdPriv, tokens, assignSessionID)
	if err != nil {
		return 0, [32]byte{}, "", err
	}

	if _, err := conn.Write(resp); err != nil {
		Zeroize(secret[:])
		return 0, [32]byte{}, "", wrapStreamError(ctx, "failed to send server hello", err)
	}

	return assignSessionID, secret, token, nil
}

// FragmentHandshakePayload splits a ClientHello (1261B) or ServerHello (1229B) payload
// into MTU-safe datagram fragments (<= 659 bytes on wire, well under SafeInternetMTU=1232).
func FragmentHandshakePayload(payload []byte) ([][]byte, error) {
	if len(payload) == 0 {
		return nil, ErrHandshakeMalformed
	}
	if !bytes.Equal(payload[0:4], MagicVectisHeader[:]) {
		return nil, ErrInvalidMagic
	}

	var fragType byte
	switch payload[4] {
	case TypeClientHello:
		fragType = TypeClientHelloFrag
	case TypeServerHello:
		fragType = TypeServerHelloFrag
	default:
		return nil, ErrInvalidMsgType
	}

	totalLen := len(payload)
	chunkSize := MaxDatagramChunkSize
	numFrags := (totalLen + chunkSize - 1) / chunkSize
	if numFrags > 255 {
		return nil, errors.New("crypto: payload too large for datagram fragmentation")
	}

	var fragID [8]byte
	if _, err := io.ReadFull(rand.Reader, fragID[:]); err != nil {
		binary.BigEndian.PutUint64(fragID[:], uint64(time.Now().UnixNano()))
	}

	frags := make([][]byte, numFrags)
	for i := 0; i < numFrags; i++ {
		offset := i * chunkSize
		end := offset + chunkSize
		if end > totalLen {
			end = totalLen
		}
		chunk := payload[offset:end]

		frag := make([]byte, FragHeaderSize+len(chunk))
		copy(frag[0:4], MagicVectisHeader[:])
		frag[4] = fragType
		copy(frag[5:13], fragID[:])
		frag[13] = byte(i)
		frag[14] = byte(numFrags)
		binary.BigEndian.PutUint16(frag[15:17], uint16(offset))
		binary.BigEndian.PutUint16(frag[17:19], uint16(totalLen))
		copy(frag[19:], chunk)

		frags[i] = frag
	}

	return frags, nil
}

type pendingFragHandshake struct {
	id         uint64
	srcAddr    string
	totalLen   int
	totalFrags int
	received   int
	data       []byte
	bitmap     uint32
	createdAt  time.Time
	prev       *pendingFragHandshake
	next       *pendingFragHandshake
}

type srcRateLimit struct {
	windowStart int64
	count       int
}

// HandshakeReassembler provides concurrent-safe, bounded, DoS-resistant datagram reassembly.
// It reconstructs fragmented client/server handshakes, enforces per-source rate limits and quotas,
// and purges stale pending buffers in O(1).
type HandshakeReassembler struct {
	mu           sync.Mutex
	pending      map[uint64]*pendingFragHandshake
	head         *pendingFragHandshake // oldest session
	tail         *pendingFragHandshake // newest session
	maxPending   int
	ttl          time.Duration
	maxPerSource int
	srcSessions  map[string]int
	srcRates     map[string]*srcRateLimit
	maxRate      int
}

// NewHandshakeReassembler creates a HandshakeReassembler with maximum pending concurrent handshakes and TTL.
func NewHandshakeReassembler(maxPending int, ttl time.Duration) *HandshakeReassembler {
	if maxPending <= 0 {
		maxPending = 512
	}
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &HandshakeReassembler{
		pending:      make(map[uint64]*pendingFragHandshake, maxPending),
		maxPending:   maxPending,
		ttl:          ttl,
		maxPerSource: 4,
		srcSessions:  make(map[string]int),
		srcRates:     make(map[string]*srcRateLimit),
		maxRate:      50,
	}
}

// SetMaxPerSource configures the maximum concurrent incomplete handshakes allowed per source.
func (r *HandshakeReassembler) SetMaxPerSource(maxPerSource int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxPerSource = maxPerSource
}

// SetRateLimit configures the maximum fragments accepted per second from a single source.
func (r *HandshakeReassembler) SetRateLimit(maxRate int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxRate = maxRate
}

func (r *HandshakeReassembler) pushTail(p *pendingFragHandshake) {
	p.next = nil
	p.prev = r.tail
	if r.tail != nil {
		r.tail.next = p
	} else {
		r.head = p
	}
	r.tail = p
}

func (r *HandshakeReassembler) removeEntry(p *pendingFragHandshake) {
	if p.prev != nil {
		p.prev.next = p.next
	} else {
		r.head = p.next
	}
	if p.next != nil {
		p.next.prev = p.prev
	} else {
		r.tail = p.prev
	}
	p.prev = nil
	p.next = nil
	delete(r.pending, p.id)
	if p.srcAddr != "" {
		if count := r.srcSessions[p.srcAddr]; count > 1 {
			r.srcSessions[p.srcAddr] = count - 1
		} else {
			delete(r.srcSessions, p.srcAddr)
		}
	}
	Zeroize(p.data)
}

// Feed ingests an incoming UDP datagram without source attribution (backward-compatible).
func (r *HandshakeReassembler) Feed(datagram []byte) ([]byte, bool, error) {
	return r.FeedFrom(datagram, "")
}

// FeedFrom ingests an incoming UDP datagram with source tracking (IP:port),
// enforcing per-source rate limits and concurrency quotas to prevent asymmetric DoS attacks.
// - If the datagram is an unfragmented handshake (TypeClientHello or TypeServerHello), it returns (datagram, true, nil).
// - If the datagram is a fragment, it stores and checks for full reassembly.
// - When complete, it returns (completePayload, true, nil).
// - If waiting for remaining fragments, it returns (nil, false, nil).
func (r *HandshakeReassembler) FeedFrom(datagram []byte, srcAddr string) ([]byte, bool, error) {
	if len(datagram) < 5 {
		return nil, false, ErrHandshakeMalformed
	}
	if !bytes.Equal(datagram[0:4], MagicVectisHeader[:]) {
		return nil, false, ErrInvalidMagic
	}

	msgType := datagram[4]
	if msgType == TypeClientHello || msgType == TypeServerHello {
		return datagram, true, nil
	}

	if msgType != TypeClientHelloFrag && msgType != TypeServerHelloFrag {
		return nil, false, ErrInvalidMsgType
	}

	if len(datagram) < FragHeaderSize {
		return nil, false, ErrHandshakeMalformed
	}

	fragID := binary.BigEndian.Uint64(datagram[5:13])
	fragIdx := int(datagram[13])
	totalFrags := int(datagram[14])
	offset := int(binary.BigEndian.Uint16(datagram[15:17]))
	totalLen := int(binary.BigEndian.Uint16(datagram[17:19]))
	chunk := datagram[FragHeaderSize:]

	if totalFrags <= 0 || totalFrags > 32 || fragIdx >= totalFrags {
		return nil, false, ErrHandshakeMalformed
	}
	if offset+len(chunk) > totalLen || totalLen > 4096 || totalLen < 5 {
		return nil, false, ErrHandshakeMalformed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	nowUnix := now.Unix()

	// Rate limiting check for attributed sources
	if srcAddr != "" && r.maxRate > 0 {
		rateInfo := r.srcRates[srcAddr]
		if rateInfo == nil {
			r.srcRates[srcAddr] = &srcRateLimit{windowStart: nowUnix, count: 1}
		} else if rateInfo.windowStart != nowUnix {
			rateInfo.windowStart = nowUnix
			rateInfo.count = 1
		} else {
			rateInfo.count++
			if rateInfo.count > r.maxRate {
				return nil, false, ErrSourceRateLimited
			}
		}
	}

	// 1. O(1) Head-of-line TTL pruning: since entries are appended chronologically,
	// checking from head to tail stops as soon as an unexpired entry is encountered.
	for r.head != nil && now.Sub(r.head.createdAt) > r.ttl {
		r.removeEntry(r.head)
	}

	// Lazy cleanup of stale rate-limiting entries when table grows
	if len(r.srcRates) > 256 {
		for src, info := range r.srcRates {
			if nowUnix-info.windowStart > 2 {
				delete(r.srcRates, src)
			}
		}
	}

	p, exists := r.pending[fragID]
	if !exists {
		// Enforce per-source session quota
		if srcAddr != "" && r.maxPerSource > 0 {
			if r.srcSessions[srcAddr] >= r.maxPerSource {
				return nil, false, ErrSourceRateLimited
			}
		}

		// Capacity management: pure chronological LRU eviction of the oldest pending session.
		// Never blocks the server regardless of fragment patterns.
		if len(r.pending) >= r.maxPending {
			if r.head != nil {
				r.removeEntry(r.head)
			}
		}

		p = &pendingFragHandshake{
			id:         fragID,
			srcAddr:    srcAddr,
			totalLen:   totalLen,
			totalFrags: totalFrags,
			data:       make([]byte, totalLen),
			createdAt:  now,
		}
		r.pending[fragID] = p
		if srcAddr != "" {
			r.srcSessions[srcAddr]++
		}
		r.pushTail(p)
	}

	if p.totalLen != totalLen || p.totalFrags != totalFrags {
		return nil, false, ErrHandshakeMalformed
	}

	mask := uint32(1) << fragIdx
	if (p.bitmap & mask) == 0 {
		copy(p.data[offset:offset+len(chunk)], chunk)
		p.bitmap |= mask
		p.received++
	}

	if p.received == p.totalFrags {
		result := make([]byte, p.totalLen)
		copy(result, p.data)
		r.removeEntry(p)
		return result, true, nil
	}

	return nil, false, nil
}

// Count returns the number of currently pending reassembly sessions.
func (r *HandshakeReassembler) Count() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

// Reset clears all pending reassembly buffers and securely wipes data.
func (r *HandshakeReassembler) Reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.pending {
		Zeroize(p.data)
		p.prev = nil
		p.next = nil
	}
	clear(r.pending)
	clear(r.srcSessions)
	clear(r.srcRates)
	r.head = nil
	r.tail = nil
}
