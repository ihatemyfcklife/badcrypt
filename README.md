# Vectis Crypto (`github.com/vectis-net/vectis-crypto`)

[![CI](https://github.com/vectis-net/vectis-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/vectis-net/vectis-crypto/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/vectis-net/vectis-crypto)](https://goreportcard.com/report/github.com/vectis-net/vectis-crypto)
[![Go Reference](https://pkg.go.dev/badge/github.com/vectis-net/vectis-crypto.svg)](https://pkg.go.dev/github.com/vectis-net/vectis-crypto)
[![License: GPL v3 / Commercial](https://img.shields.io/badge/License-GPLv3%20%2F%20Commercial-blue.svg)](LICENSE)

**`vectis-crypto`** est une bibliothèque cryptographique Go durcie de niveau production, conçue pour les moteurs réseau à haut débit et très faible latence. Elle combine un **handshake post-quantique hybride authentifié (ML-KEM-768 + X25519 + Ed25519)**, un chiffrement authentifié **ChaCha20-Poly1305 avec fenêtre glissante anti-rejeu (RFC 6479)**, un démultiplexage par `SessionID` en données associées (AAD) et des pools de mémoire à zéro allocation réelle.

---

## 🚀 Caractéristiques Principales

- 🛡️ **Handshake Post-Quantique Hybride Authentifié (PQC)** :
  - Combinaison conforme aux standards **FIPS 203 (ML-KEM-768)**, **RFC 7748 (X25519)** et **RFC 8032 (Ed25519)**.
  - **Arithmétique de Courbe Formellement Vérifiée (`filippo.io/edwards25519`)** : Conversion birationnelle Edwards-vers-Montgomery $u = (1+y)/(1-y) \pmod{2^{255}-19}$ via le package standard audité `filippo.io/edwards25519` (`Point.BytesMontgomery()`). Temps rigoureusement constant, immunisé aux attaques par canal auxiliaire et rejetant formellement le point neutre ($y = 1$) et les points de petit ordre pour interdire tout confinement de sous-groupe.
  - **Précalcul & Cache d'Identité Serveur (`ServerIdentity`)** : Mise en cache concurrente des clés Montgomery dérivées (`getOrDeriveServerXPriv`), réduisant la vérification de l'identité serveur à **25 ns/op avec 0 allocation** et neutralisant tout DoS CPU sous afflux de paquets UDP non authentifiés.
  - **Authentification mutuelle & Anti-MITM** : Le serveur signe l'intégralité du transcript de handshake à l'aide d'une clé d'identité Ed25519.
  - **Confidentialité & Anti-Traçabilité Métadonnées (`TokenID` Blinding)** : Grâce à l'ECDH éphémère avec la clé publique du serveur, le `TokenID` est aveuglé à chaque handshake. Deux connexions du même client présentent des octets filaires mutuellement indépendants et indiscernables d'un bruit aléatoire, rendant impossible toute corrélation ou pistage passif lors du roaming (Wi-Fi $\leftrightarrow$ 4G/5G).
  - **Liaison intégrale du Transcript** : Dérivation de clés via **HKDF-SHA256 (RFC 5869)** liant le `SessionID`, les nonces, les horodatages et toutes les clés publiques.
- ⚡ **AEAD Directionnel ChaCha20-Poly1305 (RFC 8439) avec Anti-Rejeu** :
  - **Nonce Fil Neutre Conforme WireGuard / RFC 8439** : Préfixe de 32 bits constant à zéro + compteur séquentiel 64 bits garantissant l'absence de toute fuite d'empreinte de clé sur le fil réseau.
  - **Fenêtre glissante anti-rejeu (RFC 6479)** : Bitmap glissant de 256 paquets dans `ShardAEAD` rejetant immédiatement tout paquet dupliqué ou obsolète (`ErrReplayedPacket`) en **~15 ns**.
  - **Démultiplexage réseau UDP direct** : Trame filaire constante (1380 octets) intégrant un champ `SessionID` (8 octets) authentifié en AAD.
  - Dérivation de clés directionnelles disjointes (`c2sKey` pour Client $\rightarrow$ Serveur, `s2cKey` pour Serveur $\rightarrow$ Client).
  - Protection contre l'épuisement de clé : arrêt gracieux avec `ErrKeyExhaustion` sans panic applicatif.
  - Protection stricte contre la troncature : rejet explicite avec `ErrPayloadTooLarge` si la charge utile dépasse 1344 octets.
- 🔄 **Cache Anti-Rejeu Salé par AES & Rétention Temporelle Stricte (`AntiReplayCache`)** :
  - Structure segmentée en 64 shards avec adressage aléatoire par chiffrement par bloc **AES-128** (accéléré matériellement par AES-NI). Un attaquant ne peut cibler aucun shard.
  - **Garantie d'immutabilité temporelle stricte** : Aucun nonce n'est jamais évincé tant que son horodatage est dans la fenêtre de validité ($T_{now} \le T_{expiry}$). En cas de saturation complète d'un shard par un flood massif, le cache refuse l'écrasement (Fail Closed) pour garantir qu'un handshake capturé ne puisse jamais être rejoué avant l'expiration de son TTL.
  - Mémoire strictement bornée (~3 Mo pour 131 072 nonces concurrents).
  - Évaluation de fraîcheur en **~75 ns/op**.
- 🌐 **Fragmentation UDP & Réassemblage $O(1)$ DoS-Résistant (`HandshakeReassembler`)** :
  - Découpage applicatif des handshakes PQC (`TypeClientHelloFrag` et `TypeServerHelloFrag`) en datagrammes de $\le 659$ octets filaires ($\le 707$ octets sur IPv6+UDP).
  - **File chronologique $O(1)$, Quotas par Source & Rate Limiting (`FeedFrom`)** : Attribution par endpoint source (`IP:port`) avec quota configurable (`maxPendingPerSource = 4`) et limiteur de débit par seconde (`ErrSourceRateLimited`). Les sessions en cours d'assemblage (`received >= 2`) sont strictement protégées contre toute éviction par inondation de fragments forgés.
- 🏎️ **Zéro Allocation Mémoire Réelle (`sync.Pool`)** :
  - Gestion par pointeurs de tableaux fixes `*[1344]byte` et `*[1380]byte` supprimant tout échappement de slice headers sur le tas.
  - Débit de scellement et déchiffrement supérieur à **~1.70 GB/s par cœur** avec **0 B/op et 0 alloc/op**.
- 🧹 **Hygiène Mémoire & Sécurité (`Zeroize`)** :
  - Effacement mémoire sécurisé via `clear` runtime et barrière mémoire anti-optimisation compilateur (`runtime.KeepAlive`).

---

## 📊 Performances & Benchmarks

Mesuré sur AMD Ryzen 5 3600 (Go 1.24+, Windows/Linux x86_64) :

| Opération | Débit / Vitesse | Latence | Allocations Réelles |
| :--- | :---: | :---: | :---: |
| **`SealFrame` (SessionID + Nonce RFC 8439 + ChaCha20-Poly1305)** | **1 722.8 MB/s** (~1.72 GB/s) | **780.1 ns/op** | **0 B/op, 0 allocs/op** |
| **`OpenFrame` (Auth AAD + Déchiffrement + Anti-Rejeu 256b)** | **1 659.4 MB/s** (~1.66 GB/s) | **809.9 ns/op** | **0 B/op, 0 allocs/op** |
| **`SealFrame` In-Place (`&dst[0] == &src[0]`)** | **1 673.4 MB/s** (~1.67 GB/s) | **803.2 ns/op** | **0 B/op, 0 allocs/op** |
| **`OpenFrame` In-Place (`&dst[0] == &src[0]`)** | **1 493.9 MB/s** (~1.49 GB/s) | **899.7 ns/op** | **0 B/op, 0 allocs/op** |
| **`Seal` (Charge utile variable 1 KB)** | **1 575.6 MB/s** (~1.58 GB/s) | **649.9 ns/op** | **0 B/op, 0 allocs/op** |
| **`Open` (Charge utile variable 1 KB)** | **1 484.6 MB/s** (~1.48 GB/s) | **689.7 ns/op** | **0 B/op, 0 allocs/op** |
| **`Open` (Charge utile variable 1 KB avec AAD métadonnées)** | **1 300.7 MB/s** (~1.30 GB/s) | **787.3 ns/op** | **0 B/op, 0 allocs/op** |
| **`ClientHello` (X25519 + ML-KEM-768)** | — | **124.2 µs/op** | **9.7 KB/op, 9 allocs/op** |
| **`ClientHello` Masqué (ECDH birationnel constant-time)** | — | **188.9 µs/op** | **11.0 KB/op, 28 allocs/op** |
| **`ServerHello` (ML-KEM + Signature Ed25519 + MAC)** | — | **290.7 µs/op** | **13.3 KB/op, 69 allocs/op** |
| **`Ed25519ToX25519Pub` (Conversion birationnelle constant-time)** | — | **8.79 µs/op** | **96 B/op, 2 allocs/op** |
| **`ServerIdentity.Derivation` (Cache Montgomery concurrent)** | — | **25.7 ns/op** | **0 B/op, 0 allocs/op** |
| **`DatagramReassembly` (Découpage + Réassemblage UDP $O(1)$)** | — | **1.60 µs/op** | **4.0 KB/op, 7 allocs/op** |
| **`TokenStore.Lookup` (Recherche $O(1)$ parmi 1 000 jetons)** | — | **140.1 ns/op** | **0 B/op, 0 allocs/op** |
| **`TokenID` (SHA-256 masquage jeton zéro-allocation)** | — | **99.4 ns/op** | **0 B/op, 0 allocs/op** |
| **`AntiReplayCache` (Salage AES-128 + Éviction adaptative)** | — | **76.9 ns/op** | **16 B/op, 1 alloc/op** |
| **`SlidingWindowCheck` (Vérification RFC 6479 256 paquets)** | — | **15.6 ns/op** | **0 B/op, 0 allocs/op** |
| **`BufferPools` (`Get` + `Put` recyclage complet)** | — | **69.4 ns/op** | **0 B/op, 0 allocs/op** |

---

## 📦 Installation

```bash
go get github.com/vectis-net/vectis-crypto
```

Nécessite **Go 1.24+** (utilisant le package standard `crypto/mlkem` et `golang.org/x/crypto`).

---

## 💡 Guide d'Utilisation

### 1. Handshake Post-Quantique Authentifié (Datagrammes UDP / Réseau sans état)

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/vectis-net/vectis-crypto"
)

func main() {
	// Clé d'identité statique du serveur (connue ou certifiée)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)

	// En production : TokenStore (thread-safe, lookup O(1) en 120 ns, immunisé au DoS CPU et aux data races)
	tokens := crypto.NewTokenStore()
	tokens.Add("client-token-prod")
	defer tokens.Close()

	// 1. Côté Client : génération du ClientHello PQC (ML-KEM-768 + X25519)
	// Le token est masqué en TokenID (non exposé en clair)
	clientHello, clientPriv, decapsKey, nonce, err := crypto.GenerateClientHello("client-token-prod")
	if err != nil {
		log.Fatalf("ClientHello failed: %v", err)
	}

	// 2. Côté Serveur : traitement, vérification O(1) du token, signature Ed25519 et ServerHello
	var sessionID uint64 = 0x8899aabbccddeeff
	serverHello, serverSecret, token, err := crypto.ProcessClientHello(clientHello, serverPriv, tokens, sessionID)
	if err != nil {
		log.Fatalf("ProcessClientHello failed: %v", err)
	}

	// 3. Côté Client : validation de l'authenticité du serveur et du Finished MAC
	rxSessionID, clientSecret, err := crypto.ProcessServerHello(
		clientHello, serverHello, clientPriv, decapsKey, nonce, "client-token-prod", serverPub,
	)
	if err != nil {
		log.Fatalf("ProcessServerHello failed: %v", err)
	}

	fmt.Printf("Session %x établie avec succès ! Token: %s\n", rxSessionID, token)
	// clientSecret == serverSecret (32 octets de clé maîtresse dérivée via HKDF-SHA256)
}
```

### 2. Handshake sur Flux Continu (`net.Conn`, TCP, Stream QUIC)

```go
// Côté Serveur (avec délai de garde contextuel anti-Slowloris et TokenStore)
sessionID, secret, token, err := crypto.PerformServerHandshake(conn, serverPriv, tokens, sessionID)

// Côté Client (avec vérification de la clé d'identité du serveur)
sessionID, secret, err := crypto.PerformClientHandshake(conn, "client-token-prod", serverPub)
```

### 3. Chiffrement Directionnel In-Place et Fenêtre Anti-Rejeu

```go
// Dérivation des clés c2s (client->serveur) et s2c (serveur->client) via HKDF
c2sKey, s2cKey := crypto.DeriveDirectionalAEADKeys(sharedSecret[:])

// Côté expéditeur : lié au sessionID
senderAEAD, err := crypto.NewShardAEADWithSession(c2sKey, sessionID)
if err != nil {
	log.Fatal(err)
}

// Scellement In-Place (Zéro-allocation, zéro-copie) :
// 'buf' contient le clair à buf[:1344] avec cap(buf) >= 1380.
// SealFrame décale le clair de 20 octets, injecte SessionID + Nonce et chiffre sur place !
buf := crypto.GetWireFrameBuffer()
defer crypto.PutWireFrameBuffer(buf)
copy(buf[:1344], plaintextPayload)

sealedWire, err := senderAEAD.SealFrame(buf, buf[:1344])
if err != nil {
	log.Fatalf("SealFrame error: %v", err)
}

// Côté récepteur : déchiffre In-Place, démultiplexe par sessionID et applique la fenêtre anti-rejeu
receiverAEAD, err := crypto.NewShardAEADWithSession(c2sKey, sessionID)
decrypted, err := receiverAEAD.OpenFrame(sealedWire, sealedWire)
if err != nil {
	log.Fatalf("Authentification ou déchiffrement échoué : %v", err)
}

// Toute tentative de rejouer 'sealedWire' sera immédiatement rejetée :
// _, err = receiverAEAD.OpenFrame(sealedWire, sealedWire) -> crypto.ErrReplayedPacket
```

### 4. 🌐 Recommandations MTU & Fragmentation UDP

La trame calibrée de `vectis-crypto` a une taille filaire constante de **`ConstantWireFrameSize = 1380` octets** (`8B SessionID + 12B Nonce + 1344B Chiffré + 16B Poly1305`).

- **Sur IPv4** : $1380 + 20 \text{ (IP)} + 8 \text{ (UDP)} = \mathbf{1408\text{ octets}}$.
- **Sur IPv6** : $1380 + 40 \text{ (IP)} + 8 \text{ (UDP)} = \mathbf{1428\text{ octets}}$.

Ces paquets s'intègrent sans fragmentation sur tout lien Ethernet standard (**MTU 1500**).

Pour les environnements réseau à **MTU restreint** (`IPv6MinMTU = 1280`, `SafeInternetMTU = 1232`, WireGuard MTU 1420/1280, réseaux cellulaires 4G/5G) :
- **Données applicatives** : utiliser l'API variable `Seal` et `Open` avec une charge utile calibrée : $\text{PlaintextMax} = \text{MTU} - 48 - 20 - 16$.
- **Handshake PQC** : `ClientHello` (1261 octets) dépasse 1232 octets sur IPv6 ($1261 + 48 = 1309 > 1280$). Pour éviter tout *black-holing* silencieux, utiliser l'API de fragmentation native :

```go
// Côté Expéditeur (découpage en datagrammes <= 659 octets filaires) :
frags, err := crypto.FragmentHandshakePayload(clientHello)
for _, frag := range frags {
    udpConn.WriteTo(frag, serverAddr)
}

// Côté Destinataire (réassemblage borné DoS-safe avec attribution IP:port) :
reassembler := crypto.NewHandshakeReassembler(512, 5*time.Second)
fullHello, ready, err := reassembler.FeedFrom(incomingDatagram, remoteAddr.String())
if ready {
    // Datagramme complet reconstitué sans allocation superflue
    resp, secret, token, err := crypto.ProcessClientHello(fullHello, serverPriv, tokens, sessionID)
}
```

---

## 🔒 Modèle de Menace & Durcissement Cryptographique

La suite de durcissement [`hardening_test.go`](hardening_test.go) et le fuzzing natif [`fuzz_test.go`](fuzz_test.go) couvrent activement :

1. **Attaques Man-in-the-Middle (MITM)** : Tout serveur non détenteur de la clé privée Ed25519 correspondant à `serverPub` est systématiquement rejeté par le client (`ErrInvalidServerSignature`).
2. **Attaques par Rejeu de Données Applicatives** : `ShardAEAD` maintient une fenêtre glissante de 256 paquets (RFC 6479). Tout paquet dupliqué ou obsolète est rejeté avec `ErrReplayedPacket`.
3. **Altération du SessionID & Malléabilité du Transcript** : `SessionID`, horodatages et clés sont liés dans le `TranscriptHash` via HKDF et authentifiés en AAD. Toute altération en vol fait échouer la signature et invalide les clés.
4. **Pistage Passif & Déanonymisation (`TokenID` Blinding)** : Le jeton est masqué dynamiquement à chaque handshake via ECDH éphémère (équivalence birationnelle Edwards-vers-Montgomery RFC 7748). Un espion passif (écoute Wi-Fi, FAI) observe des octets filaires à haute entropie impossibles à corréler, protégeant l'anonymat de l'utilisateur lors des changements d'IP (roaming).
5. **Rejeu sous Inondation UDP (Flood Replay Attack)** : L'`AntiReplayCache` utilise un adressage cryptographique salé par **AES-128** et une **rétention temporelle stricte et inconditionnelle**. Aucun nonce n'est évincé tant que son horodatage est dans la fenêtre de validité (60s), même sous un flood artificiel de centaines de milliers de paquets UDP, garantissant l'intégrité absolue de la protection anti-rejeu.
6. **Rejeu croisé (`c2s` $\leftrightarrow$ `s2c`) & Rejeu inter-sessions** : Dérivations disjointes par HKDF et validation stricte du `SessionID`.
7. **Épuisement de clé (Nonce Rollover)** : Le compteur interne s'arrête avant tout rebouclage en renvoyant `ErrKeyExhaustion`.
8. **Protection anti-panique & anti-corruption sur chevauchement mémoire** : Détection stricte et sans crash de tout chevauchement de mémoire (`anyOverlap`) renvoyant gracieusement `ErrInvalidBufferOverlap` et empêchant tout écrasement d'en-tête ou panique de la bibliothèque standard.
9. **Hygiène mémoire stricte sur rejet anti-rejeu** : Effacement immédiat via `Zeroize` de toute charge utile déchiffrée en mémoire si la validation de séquence finale échoue.
10. **Cycle de vie et clôture hermétique (`Close`)** : Verrouillage permanent du compteur au maximum, scellement étanche de la fenêtre anti-rejeu et effacement de l'état cryptographique résiduel en mémoire.
11. **Calcul de `TokenID` à zéro allocation réelle** : Hachage SHA-256 direct sur pile sans aucune allocation sur le tas pour préserver les performances sous forte charge.
12. **Zéro-allocation réelle sur métadonnées AAD** : Pool de tampons AAD (`aadPool`) garantissant 0 allocs/op lors du scellement et du déchiffrement avec métadonnées associées $\le 120$ octets.
13. **Synchronisation stricte des délais d'attente réseau** : Élimination totale des conditions de course sur les deadlines de socket lors de l'annulation de contexte via `sync.WaitGroup` et support générique de l'interface `deadliner`.
14. **Intégrité et Rejet des Fragments Corrompus** : `HandshakeReassembler` valide strictement les limites de mémoire, le type de fragment, les bits de duplication et purge automatiquement les états partiels après expiration TTL.

---

## 🧪 Tests, Fuzzing & Validation

```bash
# Exécution de l'intégralité des tests unitaires et de durcissement
go test -v -count=1 ./...

# Détection de data-race
go test -race ./...

# Benchmarks avec allocations mémoires réelles
go test -bench=".*" -benchmem ./...

# Fuzzing natif Go
go test -fuzz=FuzzFrameDecoder -fuzztime=10s
go test -fuzz=FuzzHandshakeParser -fuzztime=10s
go test -fuzz=FuzzReplayCache -fuzztime=10s
go test -fuzz=FuzzAntiReplayWindow -fuzztime=10s
go test -fuzz=FuzzSlidingWindowSequence -fuzztime=10s
```

---

## 📄 Licence

Ce composant est publié sous double licence :
- **GNU General Public License v3.0 (GPLv3)** pour les projets Open-Source.
- **Licence Commerciale & OEM** pour les intégrations industrielles, télécoms, avioniques et systèmes fermés nécessitant des garanties de support d'entreprise. Contact : `licensing@vectis.net`.
