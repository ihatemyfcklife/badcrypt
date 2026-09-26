package badcrypt

import (
	"crypto/ecdh"
	"crypto/ed25519"

	"filippo.io/edwards25519"
)

// ed25519ToX25519Pub converts an Ed25519 public key to an X25519 public key using
// filippo.io/edwards25519, which is formally verified, constant-time, and audited.
// It maps the Edwards curve point (x, y) to the Montgomery curve u-coordinate:
// u = (1 + y) / (1 - y) mod (2^255 - 19) as defined in RFC 7748 §4.1.
//
// Security & Validation Guarantees:
//  1. Constant-time execution: fully immune to cache and branch timing attacks.
//  2. Point validation: ensures the point lies on the edwards25519 curve.
//  3. Small-subgroup confinement rejection: strictly rejects the neutral/identity
//     point (y = 1) and any low-order points (order dividing 8).
func ed25519ToX25519Pub(edPub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	if len(edPub) != ed25519.PublicKeySize {
		return nil, ErrInvalidServerKey
	}

	point, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return nil, ErrInvalidServerKey
	}

	// Reject neutral/identity point and small-order points (order dividing 8)
	var p8 edwards25519.Point
	p8.MultByCofactor(point)
	if p8.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, ErrInvalidServerKey
	}

	montBytes := point.BytesMontgomery()
	xPub, err := ecdh.X25519().NewPublicKey(montBytes)
	if err != nil {
		return nil, ErrInvalidServerKey
	}
	return xPub, nil
}
