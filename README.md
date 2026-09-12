# Vectis Crypto (`github.com/vectis-net/vectis-crypto`)

[![CI](https://github.com/vectis-net/vectis-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/vectis-net/vectis-crypto/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/vectis-net/vectis-crypto)](https://goreportcard.com/report/github.com/vectis-net/vectis-crypto)
[![Go Reference](https://pkg.go.dev/badge/github.com/vectis-net/vectis-crypto.svg)](https://pkg.go.dev/github.com/vectis-net/vectis-crypto)
[![License: GPL v3 / Commercial](https://img.shields.io/badge/License-GPLv3%20%2F%20Commercial-blue.svg)](LICENSE)

**`vectis-crypto`** est une bibliothèque cryptographique Go de pointe, autonome, durcie et calibrée pour les moteurs réseau à haut débit et faible latence. Elle combine un **handshake post-quantique hybride (ML-KEM-768 + X25519)** avec un chiffrement authentifié **ChaCha20-Poly1305 à nonces directionnels déterministes** et des pools de mémoire à zéro allocation.

---

## 🚀 Caractéristiques Principales

- 🛡️ **Handshake Post-Quantique Hybride (PQC)** :
  - Combinaison conforme aux standards **FIPS 203 (ML-KEM-768)** et **RFC 7748 (X25519)**.
  - Dérivation de secret de session via SHA-256 avec nonces anti-rejeu et fenêtre temporelle de dérive horloge (±60s).
  - Rejet implicite instantané en cas d'altération du transcript ou des clés de chiffrement.
- ⚡ **AEAD Directionnel ChaCha20-Poly1305 (RFC 8439)** :
  - Dérivation de clés directionnelles distinctes (`c2sKey` pour Client $\rightarrow$ Serveur, `s2cKey` pour Serveur $\rightarrow$ Client) empêchant formellement les collisions de nonces et les attaques par réflexion/rejeu croisé.
  - Compteur atomique 64-bit déterministe (`sync/atomic`) éliminant les appels système de génération d'entropie dans la boucle critique.
  - **Protection contre l'épuisement de clé** : arrêt strict avant tout dépassement (rollover) de compteur pour prévenir toute réutilisation de masque (Two-Time Pad).
- 🔄 **Cache Anti-Rejeu Hautes Performances (`AntiReplayCache`)** :
  - Structure de contrôle concurrente thread-safe avec suppression glissante en arrière-plan (expiration automatique des nonces).
  - Vérification de nonce en **~19 ns/op** avec **0 allocation**.
- 🏎️ **Zéro Allocation Mémoire (`sync.Pool`)** :
  - Trames de taille constante calibrées pour les MTU réseau (trames filaires de 1372 octets, données utiles de 1344 octets).
  - Débit de scellement et déchiffrement supérieur à **~1.95 GB/s par cœur** avec **0 alloc/op**.
- 🧹 **Hygiène Mémoire & Sécurité (`Zeroize`)** :
  - Effacement automatique des secrets éphémères et buffers recyclés avec barrière mémoire anti-optimisation compilateur.

---

## 📊 Performances & Benchmarks

Mesuré sur AMD Ryzen 5 3600 (Go 1.26.1, Windows/Linux x86_64) :

| Opération | Débit / Vitesse | Latence | Allocations |
| :--- | :---: | :---: | :---: |
| **`SealFrame` (ChaCha20-Poly1305)** | **1 949.6 MB/s** (~1.95 GB/s) | **689 ns/op** | **0 B/op, 0 allocs/op** |
| **`OpenFrame` (Authentification + Déchiffrement)** | **1 941.7 MB/s** (~1.94 GB/s) | **692 ns/op** | **0 B/op, 0 allocs/op** |
| **`Seal` (Charge utile variable 1 KB)** | **1 840.7 MB/s** (~1.84 GB/s) | **556 ns/op** | **0 B/op, 0 allocs/op** |
| **`ServerHello` (Encapsulation PQC + Dérivation)** | — | **88.5 ns/op** | **24 B/op, 1 allocs/op** |
| **`AntiReplayCache` (Vérification atomique nonce)** | — | **19.3 ns/op** | **0 B/op, 0 allocs/op** |

---

## 📦 Installation

```bash
go get github.com/vectis-net/vectis-crypto
```

Nécessite **Go 1.24+** (utilisant le package standard `crypto/mlkem` et `golang.org/x/crypto`).

---

## 💡 Guide d'Utilisation

### 1. Handshake Post-Quantique (Datagrammes UDP ou Réseau sans état)

```go
package main

import (
	"fmt"
	"log"

	"github.com/vectis-net/vectis-crypto"
)

func main() {
	validTokens := map[string]bool{"client-token-prod": true}

	// 1. Côté Client : génération du ClientHello PQC (ML-KEM-768 + X25519)
	clientHello, clientPriv, decapsKey, nonce, err := crypto.GenerateClientHello("client-token-prod")
	if err != nil {
		log.Fatalf("ClientHello failed: %v", err)
	}

	// 2. Côté Serveur : traitement et génération du ServerHello
	var sessionID uint64 = 0x8899aabbccddeeff
	serverHello, serverSecret, token, err := crypto.ProcessClientHello(clientHello, validTokens, sessionID)
	if err != nil {
		log.Fatalf("ProcessClientHello failed: %v", err)
	}

	// 3. Côté Client : traitement du ServerHello et dérivation du secret identique
	rxSessionID, clientSecret, err := crypto.ProcessServerHello(serverHello, clientPriv, decapsKey, nonce)
	if err != nil {
		log.Fatalf("ProcessServerHello failed: %v", err)
	}

	fmt.Printf("Session %x établie avec succès ! Token: %s\n", rxSessionID, token)
	// clientSecret == serverSecret (32 octets de clé maîtresse)
}
```

### 2. Handshake sur Flux Continu (`net.Conn`, TCP, Stream QUIC)

```go
// Côté Serveur
sessionID, secret, token, err := crypto.PerformServerHandshake(conn, validTokens, sessionID)

// Côté Client
sessionID, secret, err := crypto.PerformClientHandshake(conn, "client-token-prod")
```

### 3. Chiffrement Directionnel Haute Performance (Zéro Allocation)

```go
// Dérivation des clés c2s (client->serveur) et s2c (serveur->client)
c2sKey, s2cKey := crypto.DeriveDirectionalAEADKeys(sharedSecret[:])

// Côté expéditeur
senderAEAD, err := crypto.NewShardAEAD(c2sKey)
if err != nil {
	log.Fatal(err)
}

// Scellement d'une trame constante (1344 octets de plaintext -> 1372 octets filaire)
dstFrame := crypto.GetWireFrameBuffer()
defer crypto.PutWireFrameBuffer(dstFrame)

sealedWire := senderAEAD.SealFrame(dstFrame, plaintextPayload)

// Côté récepteur
receiverAEAD, err := crypto.NewShardAEAD(c2sKey)
decrypted, err := receiverAEAD.OpenFrame(nil, sealedWire)
if err != nil {
	log.Fatalf("Authentification échouée / altération : %v", err)
}
```

### 4. Chiffrement de Données à Taille Variable (`Seal` / `Open`)

```go
aead, _ := crypto.NewShardAEAD(c2sKey)

// Chiffrement avec métadonnées d'authentification associées (AAD)
aad := []byte("header-metadata-id-42")
sealed := aead.Seal(nil, []byte("Message confidentiel"), aad)

// Déchiffrement
plain, err := aead.Open(nil, sealed, aad)
if err != nil {
	log.Fatalf("Altération détectée : %v", err)
}
```

---

## 🔒 Modèle de Menace & Durcissement Cryptographique

La suite de durcissement [`hardening_test.go`](hardening_test.go) et le fuzzing natif [`fuzz_test.go`](fuzz_test.go) couvrent activement :

1. **Attaques par rejeu croisé (`c2s` $\leftrightarrow$ `s2c`)** : Les flux montants et descendants utilisent des dérivations disjointes (`vectis-aead-c2s-v1:` vs `vectis-aead-s2c-v1:`). Toute trame cliente renvoyée au client est rejetée avec `ErrInvalidAEADAuth`.
2. **Rejeu inter-sessions** : Les clés dérivées intègrent l'aléa post-quantique et les nonces de session, garantissant l'isolation totale entre sessions.
3. **Épuisement de clé (Nonce Rollover)** : Le compteur interne refuse formellement de boucler sur $2^{64}-1$, déclenchant une panique sécurisée avant tout réemploi de clé/nonce.
4. **Altération de transcript** : Conformément à FIPS 203, toute altération des clés ou trames d'encapsulation ML-KEM conduit au rejet implicite par divergence des secrets dérivés.
5. **Dérive temporelle** : Tout `ClientHello` dont le timestamp s'écarte de plus de 60 secondes de l'horloge serveur est invalidé (`ErrTimestampDrift`).

---

## 🧪 Tests, Fuzzing & Validation

```bash
# Exécution de l'intégralité des tests unitaires et de durcissement
go test -v -count=1 ./...

# Détection de data-race
go test -race ./...

# Benchmarks avec allocation mémoire
go test -bench=".*" -benchmem ./...

# Fuzzing natif Go
go test -fuzz=FuzzFrameDecoder -fuzztime=30s
go test -fuzz=FuzzHandshakeParser -fuzztime=30s
go test -fuzz=FuzzReplayCache -fuzztime=30s
```

---

## 📄 Licence

Ce composant est publié sous double licence :
- **GNU General Public License v3.0 (GPLv3)** pour les projets Open-Source.
- **Licence Commerciale & OEM** pour les intégrations industrielles, télécoms, avioniques et systèmes fermés nécessitant des garanties de support d'entreprise. Contact : `licensing@vectis.net`.
