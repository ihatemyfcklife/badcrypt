package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var (
	// MagicVectisHeader identifies Vectis protocol handshake datagrams.
	MagicVectisHeader = [4]byte{'V', 'E', 'C', 'T'}

	// ErrInvalidMagic is returned when a datagram does not start with MagicVectisHeader.
	ErrInvalidMagic = errors.New("crypto: invalid Vectis protocol magic")

	// ErrInvalidMsgType is returned when an unexpected handshake message type is encountered.
	ErrInvalidMsgType = errors.New("crypto: invalid handshake message type")

	// ErrUnauthorizedToken is returned when a client presents an unapproved authentication token.
	ErrUnauthorizedToken = errors.New("crypto: unauthorized authentication token")

	// ErrTimestampDrift is returned when handshake timestamp is outside the allowed +/- 60s drift window.
	ErrTimestampDrift = errors.New("crypto: handshake timestamp outside allowed drift window (+/- 60s)")

	// ErrReplayedHandshake is returned when a duplicate handshake nonce is detected.
	ErrReplayedHandshake = errors.New("crypto: replayed client handshake detected")

	// ErrHandshakeMalformed is returned when a handshake payload is truncated or invalid.
	ErrHandshakeMalformed = errors.New("crypto: malformed handshake payload")
)

const (
	// TypeClientHello indicates a client handshake initiator message.
	TypeClientHello = 0x01

	// TypeServerHello indicates a server handshake response message.
	TypeServerHello = 0x02

	// ClientHelloSize is the exact wire size of ClientHello:
	// Magic (4) + Type (1) + Token (32) + Timestamp (8) + Nonce (16) + X25519 Pub (32) + ML-KEM-768 Pub (1184) = 1277 bytes.
	ClientHelloSize = 4 + 1 + 32 + 8 + 16 + 32 + 1184

	// ServerHelloSize is the exact wire size of ServerHello:
	// Magic (4) + Type (1) + SessionID (8) + Server X25519 Pub (32) + ML-KEM-768 Ciphertext (1088) = 1133 bytes.
	ServerHelloSize = 4 + 1 + 8 + 32 + 1088

	// MaxTimestampDriftSeconds defines the maximum allowed clock drift between peers.
	MaxTimestampDriftSeconds = 60
)

// AntiReplayCache tracks recently observed handshake nonces to prevent replay attacks.
type AntiReplayCache struct {
	mu     sync.Mutex
	nonces map[[16]byte]time.Time
	stopCh chan struct{}
}

// NewAntiReplayCache initializes an active anti-replay cache with background expiration.
func NewAntiReplayCache() *AntiReplayCache {
	c := &AntiReplayCache{
		nonces: make(map[[16]byte]time.Time),
		stopCh: make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// Close gracefully terminates the background cleanup goroutine.
func (c *AntiReplayCache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
}

// Cleanup removes nonces recorded before the cutoff time.
func (c *AntiReplayCache) Cleanup(cutoff time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, t := range c.nonces {
		if t.Before(cutoff) {
			delete(c.nonces, k)
		}
	}
}

// Size returns the count of currently cached nonces.
func (c *AntiReplayCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.nonces)
}

func (c *AntiReplayCache) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.Cleanup(time.Now().Add(-120 * time.Second))
		}
	}
}

// AddOrCheck returns true if the nonce was already seen (replay detected).
// Returns false and registers the nonce if it is fresh.
func (c *AntiReplayCache) AddOrCheck(nonce []byte) bool {
	if len(nonce) != 16 {
		return true
	}
	var k [16]byte
	copy(k[:], nonce)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.nonces[k]; exists {
		return true
	}
	c.nonces[k] = time.Now()
	return false
}

var globalReplayCache = NewAntiReplayCache()

// GenerateClientHello creates a ClientHello datagram payload for PQC handshake.
func GenerateClientHello(token string) (payload []byte, clientPriv *ecdh.PrivateKey, decapsKey *mlkem.DecapsulationKey768, nonce []byte, err error) {
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

	// 32-byte token
	tokenBytes := make([]byte, 32)
	copy(tokenBytes, []byte(token))
	copy(payload[5:37], tokenBytes)

	// Timestamp
	binary.BigEndian.PutUint64(payload[37:45], uint64(time.Now().Unix()))

	// Nonce
	copy(payload[45:61], nonce)

	// Keys
	copy(payload[61:93], clientPubKey)
	copy(payload[93:ClientHelloSize], mlkemPubKey)

	return payload, clientPriv, decapsKey, nonce, nil
}

// ProcessClientHello verifies the ClientHello using the default global replay cache.
func ProcessClientHello(payload []byte, validTokens map[string]bool, assignSessionID uint64) (respPayload []byte, sessionSecret [32]byte, token string, err error) {
	return ProcessClientHelloWithCache(payload, validTokens, assignSessionID, globalReplayCache)
}

// ProcessClientHelloWithCache verifies the ClientHello against a specific AntiReplayCache instance.
func ProcessClientHelloWithCache(payload []byte, validTokens map[string]bool, assignSessionID uint64, cache *AntiReplayCache) (respPayload []byte, sessionSecret [32]byte, token string, err error) {
	var emptySecret [32]byte
	if len(payload) < ClientHelloSize {
		return nil, emptySecret, "", ErrHandshakeMalformed
	}

	if !bytes.Equal(payload[0:4], MagicVectisHeader[:]) {
		return nil, emptySecret, "", ErrInvalidMagic
	}
	if payload[4] != TypeClientHello {
		return nil, emptySecret, "", ErrInvalidMsgType
	}

	token = string(bytes.TrimRight(payload[5:37], "\x00"))
	if len(validTokens) > 0 && !validTokens[token] {
		return nil, emptySecret, token, ErrUnauthorizedToken
	}

	ts := binary.BigEndian.Uint64(payload[37:45])
	now := uint64(time.Now().Unix())
	if ts > now+MaxTimestampDriftSeconds || now > ts+MaxTimestampDriftSeconds {
		return nil, emptySecret, token, ErrTimestampDrift
	}

	nonce := payload[45:61]
	if cache != nil && cache.AddOrCheck(nonce) {
		return nil, emptySecret, token, ErrReplayedHandshake
	}

	clientPubKeyBytes := payload[61:93]
	clientMlkemPubKeyBytes := payload[93:ClientHelloSize]

	// Server X25519
	x25519Curve := ecdh.X25519()
	serverPrivKey, err := x25519Curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, emptySecret, token, fmt.Errorf("failed to generate server X25519 key: %w", err)
	}

	clientPubKey, err := x25519Curve.NewPublicKey(clientPubKeyBytes)
	if err != nil {
		return nil, emptySecret, token, fmt.Errorf("invalid client X25519 key: %w", err)
	}

	x25519Shared, err := serverPrivKey.ECDH(clientPubKey)
	if err != nil {
		return nil, emptySecret, token, fmt.Errorf("X25519 ECDH computation failed: %w", err)
	}

	// Server ML-KEM-768 encapsulation
	clientMlkemEncapsKey, err := mlkem.NewEncapsulationKey768(clientMlkemPubKeyBytes)
	if err != nil {
		return nil, emptySecret, token, fmt.Errorf("invalid client ML-KEM key: %w", err)
	}

	mlkemShared, mlkemCiphertext := clientMlkemEncapsKey.Encapsulate()

	// Assemble ServerHello: Magic(4) + Type(1) + SessionID(8) + ServerX25519(32) + MLKEMCiphertext(1088) = 1133 bytes
	respPayload = make([]byte, ServerHelloSize)
	copy(respPayload[0:4], MagicVectisHeader[:])
	respPayload[4] = TypeServerHello
	binary.BigEndian.PutUint64(respPayload[5:13], assignSessionID)
	copy(respPayload[13:45], serverPrivKey.PublicKey().Bytes())
	copy(respPayload[45:ServerHelloSize], mlkemCiphertext)

	// Combine shared secrets with nonce into SHA-256 session secret
	var combined [80]byte
	copy(combined[0:32], x25519Shared)
	copy(combined[32:64], mlkemShared)
	copy(combined[64:80], nonce)
	sessionSecret = sha256.Sum256(combined[:])
	Zeroize(combined[:])

	return respPayload, sessionSecret, token, nil
}

// ProcessServerHello decapsulates the ServerHello on the client and derives the exact same session secret.
func ProcessServerHello(respPayload []byte, clientPriv *ecdh.PrivateKey, decapsKey *mlkem.DecapsulationKey768, nonce []byte) (sessionID uint64, sessionSecret [32]byte, err error) {
	var emptySecret [32]byte
	if len(respPayload) < ServerHelloSize {
		return 0, emptySecret, ErrHandshakeMalformed
	}

	if !bytes.Equal(respPayload[0:4], MagicVectisHeader[:]) {
		return 0, emptySecret, ErrInvalidMagic
	}
	if respPayload[4] != TypeServerHello {
		return 0, emptySecret, ErrInvalidMsgType
	}

	sessionID = binary.BigEndian.Uint64(respPayload[5:13])
	serverX25519PubKeyBytes := respPayload[13:45]
	mlkemCiphertext := respPayload[45:ServerHelloSize]

	// Compute X25519 shared secret
	x25519Curve := ecdh.X25519()
	serverX25519PubKey, err := x25519Curve.NewPublicKey(serverX25519PubKeyBytes)
	if err != nil {
		return 0, emptySecret, fmt.Errorf("invalid server X25519 key: %w", err)
	}
	x25519Shared, err := clientPriv.ECDH(serverX25519PubKey)
	if err != nil {
		return 0, emptySecret, fmt.Errorf("client X25519 ECDH computation failed: %w", err)
	}

	// Decapsulate ML-KEM-768
	mlkemShared, err := decapsKey.Decapsulate(mlkemCiphertext)
	if err != nil {
		return 0, emptySecret, fmt.Errorf("ML-KEM decapsulation failed: %w", err)
	}

	// Derive combined SHA-256 session secret
	var combined [80]byte
	copy(combined[0:32], x25519Shared)
	copy(combined[32:64], mlkemShared)
	copy(combined[64:80], nonce)
	sessionSecret = sha256.Sum256(combined[:])
	Zeroize(combined[:])

	return sessionID, sessionSecret, nil
}

// PerformClientHandshake executes the full PQC handshake over any io.ReadWriter stream (e.g. TCP or virtual stream).
func PerformClientHandshake(conn io.ReadWriter, token string) (sessionID uint64, sessionSecret [32]byte, err error) {
	hello, priv, decaps, nonce, err := GenerateClientHello(token)
	if err != nil {
		return 0, [32]byte{}, err
	}

	if _, err := conn.Write(hello); err != nil {
		return 0, [32]byte{}, fmt.Errorf("failed to send client hello: %w", err)
	}

	resp := make([]byte, ServerHelloSize)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, [32]byte{}, fmt.Errorf("failed to read server hello: %w", err)
	}

	return ProcessServerHello(resp, priv, decaps, nonce)
}

// PerformServerHandshake executes the server side of the PQC handshake over any io.ReadWriter stream.
func PerformServerHandshake(conn io.ReadWriter, validTokens map[string]bool, assignSessionID uint64) (sessionID uint64, sessionSecret [32]byte, token string, err error) {
	clientPayload := make([]byte, ClientHelloSize)
	if _, err := io.ReadFull(conn, clientPayload); err != nil {
		return 0, [32]byte{}, "", fmt.Errorf("failed to read client hello: %w", err)
	}

	resp, secret, token, err := ProcessClientHello(clientPayload, validTokens, assignSessionID)
	if err != nil {
		return 0, [32]byte{}, token, err
	}

	if _, err := conn.Write(resp); err != nil {
		return 0, [32]byte{}, token, fmt.Errorf("failed to send server hello: %w", err)
	}

	return assignSessionID, secret, token, nil
}
