# Retro

**Anonymous, ephemeral, end-to-end encrypted chat.**

## Welcome to Retro

Welcome to Retro! Before you dive in, let’s talk about what this thing actually is, why it exists, and why it behaves like it does, because it's a little unusual.

Retro is new.
But Retro doesn’t know it’s new.

Actually, Retro doesn’t know much at all.

It doesn’t know who you are.
It doesn’t know where you’re connecting from.
It doesn’t know what you’re saying.

And if everything is working correctly, it **never will**.

Retro is basically a middleman with zero curiosity and terrible memory. It takes messages from you, hands them to someone else, and immediately forgets the whole interaction ever happened.

---

## So what *does* Retro do?

Retro has one job:

**Take your message → deliver it → ask no questions → leave.**

That’s it.

No accounts. No signups. No “verify your email.” No “add your phone number.” Retro doesn’t even want your name. When you connect, you get something like `anon_8f3k`.

That’s you. That’s your entire “identity.”
Not a profile. Not a history. Just a temporary label so messages don’t get lost.

When you leave, the identity you were assigned is taken out of existence, just like us when we go to visit the big man in the sky.

---

## Messages? Never heard of them.

When you send a message, Retro does something very important:

**it refuses to understand it.**

Your message gets unnecessarily encrypted twice (because paranoia is healthy I guess), sent through the server, and delivered to other people. The server seesnothing useful except your "address". Just encrypted noise.

Retro doesn’t know if you sent:

* a “hello”
* a file
* or the secret to perfect chocolate chip cookies

It all looks the same.

And Retro likes it that way.

---

## Chat rooms (with commitment issues)

Everything in Retro happens inside chat rooms.

But these aren’t cozy, permanent little spaces.

These rooms are **extremely temporary**.

* You join → you see messages from that moment forward
* You leave → you lose access immediately
* Everyone leaves → the room is **destroyed**

Not archived. Not saved. Not “we’ll keep it just in case.”

Destroyed.

Like it tripped, fell, and landed directly into a shredder.

Whatever happened in that room now only exists in the heads of the people who were there. Retro has already moved on emotionally.

---

## Keys: the only thing that matters

When you join a room, your application generates a specific set of keys.

These keys are what let you read messages. No key = no access.

Now here’s where it gets fun:

Every time someone joins or leaves, the keys change.

* New people can’t read old messages
* People who leave can’t read new ones
* Old keys? **Gone. Obliterated. Zeroized.**

If a key disappears, the messages it unlocked might as well have never existed.

Retro doesn’t “lock” old messages away.

It deletes the only thing that could ever unlock them.

---

## Why is it like this?

Because storing information is risky.

Keeping identities is risky.
Keeping messages is risky.
Knowing things in general? Surprisingly risky.

So Retro takes a different approach:

**it tries very hard to know nothing and remember nothing.**

No identity → nothing to tie back to you
No stored messages → nothing to leak later
No server knowledge → nothing useful to steal

Retro isn’t asking you to trust it.

It’s designed so that even if you *didn’t* trust it… it still wouldn’t matter.

---

## One tiny (important) problem

Retro protects your messages.

It does **not** protect you from… you.

If you go into a chat room and say:

> “Hi, I’m Andrea, I live in Seattle, and here’s my social security number”

Retro will faithfully deliver that message.

It will not stop you.
It will not judge you.
It will quietly watch you make that decision and then forget it watched you make that decision.

So yeah—talk, make friends, share ideas. Just remember:

**privacy only works if you participate in it.**

---

## The whole idea

Retro lives by a very simple philosophy:

**“If it doesn’t know it, it can’t leak it.”**

So it doesn’t know anything.

And when everything is working right…
it never will.

---

## Table of Contents

- [What Is Retro](#what-is-retro)
- [Architecture](#architecture)
- [How It Works](#how-it-works)
- [Cryptography](#cryptography)
  - [Session Key Generation](#1-session-key-generation)
  - [Double-Wrapped Encryption](#2-double-wrapped-encryption)
  - [Key Exchange Protocol](#3-key-exchange-protocol)
  - [Group Key Ratchet](#4-group-key-ratchet)
  - [Zeroization](#5-zeroization)
  - [End-to-End Data Flow](#6-end-to-end-data-flow)
- [Project Structure](#project-structure)
- [Building & Running](#building--running)

---

## Features of Retro (for the more serious readers)

- **No accounts.** Every time you connect, you get a randomly generated anonymous handle (e.g., `anon_8f3k`). There is no registration, no email, no phone number, no identity.

- **No history.** Messages exist only in the RAM of participants. The server relays opaque ciphertext blobs and never holds a decryption key. When a room is closed, all stored ciphertexts are zero-overwritten before deallocation.

- **No metadata.** The server knows that *someone* connected and sent *something*, but it cannot read the content, cannot identify the user beyond the ephemeral handle, and retains nothing after disconnect.

- **Ephemeral rooms.** A room exists only while participants are in it. The creator can close it at any time, triggering immediate cryptographic death — all key material and ciphertexts are destroyed on every client and on the server.

- **Forward secrecy.** The group encryption key ratchets forward on every membership change. If a key is ever compromised, it reveals nothing about past messages. If a member leaves, they cannot decrypt future messages.

- **Double-wrapped encryption.** Every message passes through two independent ciphers from different algorithm families (XChaCha20-Poly1305 and AES-256-GCM). An attacker must break *both* to read anything.

- **Defense-in-depth key exchange.** The group key is transferred using both X25519 ECDH and RSA-4096 OAEP wrapping, signed with Ed25519. An attacker must break both key agreement schemes *and* forge a digital signature to intercept the key.

- **Key Elimination** When the application, server, chat room or user disconnect occurs, the keys which unlocked the chat are obliterated. When the key is destroyed, absolutely nothing about the session is recoverable. 

The UI is a monochrome CRT-aesthetic desktop app with scanline effects, phosphor glow, and screen curvature to emulate a type of retro-styled computer.

---

## Architecture

Retro is a Cargo workspace with four crates:

```
┌─────────────────────────────────────────────────────────────┐
│                     retro-client (Tauri 2)                  │
│  Desktop app — HTML/CSS/JS frontend + Rust backend          │
│  All encryption/decryption happens here. Server never       │
│  sees plaintext.                                            │
└────────────────────────────┬────────────────────────────────┘
                             │ WebSocket (opaque ciphertext)
┌────────────────────────────▼────────────────────────────────┐
│                     retro-server (Axum)                     │
│  Dumb relay. Routes ciphertext between clients.             │
│  Manages room membership. Holds no keys.                    │
└────────────────────────────┬────────────────────────────────┘
                             │ Heartbeat (optional)
┌────────────────────────────▼────────────────────────────────┐
│                   retro-registry (Axum)                     │
│  Optional server discovery. Servers announce themselves     │
│  via periodic heartbeat. Clients can browse the list.       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     retro-crypto (library)                  │
│  Shared types + all cryptographic primitives.               │
│  Used by both client and server for message serialization.  │
│  Encryption/decryption only ever called by the client.      │
└─────────────────────────────────────────────────────────────┘
```

- **retro-crypto** — Pure Rust cryptographic library. Key generation, double-wrapped encryption, key exchange, group key ratchet, protocol message types. 21 unit tests.

- **retro-server** — Axum 0.8 WebSocket server. Routes messages between clients, manages ephemeral rooms, runs background cleanup (zero-overwrite expired ciphertexts). Holds no encryption keys.

- **retro-registry** — Optional Axum service for server discovery. Servers send periodic heartbeats; clients can fetch the server list.

- **retro-client** — Tauri 2 desktop application. Plain HTML/CSS/JS frontend with a Rust backend that handles all cryptographic operations. The Rust side connects via WebSocket, generates keys, encrypts/decrypts messages, and manages the key ratchet. The JS side handles UI only.

---

## How It Works

### Connecting

1. You open the app and click **Direct Connect** (or pick a server from the list).
2. The client generates three fresh keypairs: **X25519** (key exchange), **Ed25519** (signatures), and **RSA-4096** (additional key wrapping).
3. A WebSocket connection is established to the server.
4. The server assigns you a random anonymous handle (e.g., `anon_8f3k`) and sends it back.
5. You land in the **Lobby** — ready to create or join a room.

### Creating a Room

1. You enter a room name and click **Create**.
2. The server creates the room and returns a room ID.
3. Your client initializes a fresh **Group Key Ratchet** with a cryptographically random 256-bit key.
4. Your client publishes its public key bundle (X25519 + Ed25519 + RSA public keys) to the room so future joiners can perform key exchange.

### Joining a Room

1. You enter a room ID and click **Join**.
2. The server adds you to the room and sends you the current member list (with their public keys).
3. Your client derives **DM keys** for each existing member via X25519 ECDH + HKDF.
4. Each existing member's client sees you join, **ratchets the group key forward** (forward secrecy), then initiates **key exchange** — sending you the current group key encrypted so only you can read it (using X25519 ECDH + RSA-4096 OAEP + Ed25519 signature + double-wrap encryption).
5. Your client receives the key exchange payload, verifies the signature, decrypts it, and installs the group key. You now see: *"End-to-end encryption established."*

### Sending Messages

1. You type a message and press Send.
2. Your client takes the plaintext, derives two subkeys from the group key via HKDF, encrypts through XChaCha20-Poly1305 (inner layer) then AES-256-GCM (outer layer), zeroizes the subkeys, and sends the double-wrapped ciphertext over the WebSocket.
3. The server receives an opaque blob and broadcasts it to all other room members. It cannot read it.
4. Each recipient's client decrypts in reverse order: AES-256-GCM → XChaCha20-Poly1305 → plaintext.

### Membership Changes

- **Member joins:** Every existing client ratchets the group key forward. The new member receives the post-ratchet key, so they cannot decrypt messages from before they arrived.
- **Member leaves:** Every remaining client ratchets the group key forward. The departed member still has the old key in memory, but all future messages use a key they don't have.

### Closing a Room

1. The room creator clicks **Close Room** and confirms.
2. The server broadcasts `RoomClosed` to all members, then zero-overwrites all stored ciphertexts and destroys the room.
3. Every client receives the event, drops the group key ratchet (triggering `ZeroizeOnDrop`), clears all member keys and DM keys, and returns to the lobby.
4. Nothing remains. No keys, no ciphertexts, no room.

### Disconnecting

When you disconnect (or close the app), all session keys, group keys, DM keys, and member data are dropped, triggering zeroization. Your anonymous handle is discarded. The server removes you from any rooms and, if you were the last member, destroys the room.

---

## Cryptography

Everything below describes what the `retro-crypto` crate does, how it's implemented, and why.

### 1. Session Key Generation

**Source:** `crypto/src/keys.rs`

The moment you connect, your client generates three completely independent keypairs from scratch using OS-provided cryptographic randomness (`OsRng`):

#### X25519 — Elliptic-Curve Diffie-Hellman

- **What it is:** A key-agreement protocol based on Curve25519. Produces a 32-byte secret key and a 32-byte public key.
- **What it does:** Allows two parties who have never communicated to derive an identical shared secret by exchanging only public keys. The math is `shared = our_secret × their_public`, and because elliptic-curve scalar multiplication is commutative, both sides arrive at the same value.
- **Where it's used:** Group key exchange (securely transferring the room key to new joiners) and DM key derivation (private pairwise keys between any two members).
- **Implementation:** `X25519Secret::random_from_rng(OsRng)` generates a random scalar on Curve25519. The public key is the generator point `G` multiplied by that scalar. Handled by the `x25519-dalek` crate. The secret key implements `ZeroizeOnDrop` — when the struct is freed, the memory is overwritten with zeros before deallocation.

#### Ed25519 — Digital Signatures

- **What it is:** An Edwards-curve Digital Signature Algorithm. Produces a 32-byte signing key and a 32-byte verifying (public) key.
- **What it does:** Lets you **sign** data so anyone with your public key can verify you authored it, but nobody can forge your signature. This is not encryption — it's **authentication**.
- **Where it's used:** During key exchange, the existing member signs the entire payload so the new joiner can verify it actually came from that member and wasn't tampered with in transit. This is the anti-MITM (man-in-the-middle) defense.
- **Implementation:** `SigningKey::generate(&mut OsRng)` from `ed25519-dalek`. Signing produces a 64-byte signature. Verification is a point decompression + scalar multiplication check on the twisted Edwards curve. The signing key implements `ZeroizeOnDrop`.

#### RSA-4096 — Asymmetric Encryption

- **What it is:** A 4096-bit RSA keypair. The public key is ~550 bytes (DER-encoded).
- **What it does:** Encrypts data that only the private key holder can decrypt. Used with OAEP padding (Optimal Asymmetric Encryption Padding) and SHA-256.
- **Where it's used:** During key exchange, the ECDH shared secret is **also** encrypted with the recipient's RSA-4096 public key. This is the defense-in-depth — an attacker needs to break **both** X25519 **and** RSA-4096 to intercept the group key.
- **Implementation:** `RsaPrivateKey::new(&mut OsRng, 4096)` generates two random 2048-bit primes, multiplies them, and computes the modular inverse for the private exponent. RSA key generation requires finding large primes via probabilistic primality testing (Miller-Rabin), which involves modular exponentiation of huge numbers — this takes ~1-3 seconds unoptimized (under 1 second with `opt-level = 3` applied to crypto crates in the dev profile).

#### Public Key Bundle

After generation, `public_bundle()` exports the three public keys as base64 strings:

```json
{
  "x25519": "<32 bytes, base64>",
  "ed25519": "<32 bytes, base64>",
  "rsa": "<~550 bytes DER, base64>"
}
```

This bundle is the **only information that ever leaves the client** during key exchange. Secret keys **never** leave memory.

---

### 2. Double-Wrapped Encryption

**Source:** `crypto/src/encryption.rs`

Every message, file, and group-key-in-transit is encrypted **twice** using two completely different cipher families. If a catastrophic vulnerability is discovered in one (a side-channel attack on AES, a mathematical break of ChaCha), the other still protects you.

#### Step 1: Subkey Derivation via HKDF-SHA256

The raw group key is never used directly. Two independent 256-bit subkeys are derived:

```
K_inner = HKDF-SHA256(IKM=group_key, salt=epoch, info="retro-inner-xchacha20poly1305")
K_outer = HKDF-SHA256(IKM=group_key, salt=epoch, info="retro-outer-aes256gcm")
```

**HKDF** (HMAC-based Key Derivation Function) is a two-step process:
1. **Extract** — compress the input key material into a pseudorandom key using HMAC-SHA256 with the epoch as salt.
2. **Expand** — use the pseudorandom key and the info string to produce output key material.

The different `info` strings guarantee the inner and outer keys are **cryptographically independent** even though they derive from the same source. The epoch salt ensures keys at epoch 0 are completely different from epoch 1.

#### Step 2: Inner Layer — XChaCha20-Poly1305

- **Cipher:** XChaCha20 — a stream cipher from the ChaCha family (designed by Daniel J. Bernstein). Generates a keystream from the key + nonce and XORs it with plaintext.
- **Authentication:** Poly1305 — a one-time authenticator that produces a 16-byte MAC (message authentication code). Guarantees integrity: if even one bit of ciphertext is flipped, decryption fails.
- **Nonce:** 24 bytes, randomly generated via `OsRng`. The "X" in XChaCha means "eXtended nonce" — 24 bytes gives 2^192 possible nonces, making random collisions astronomically unlikely even across billions of messages.
- **Output:** The ciphertext (same length as plaintext) plus a 16-byte Poly1305 authentication tag.

#### Step 3: Outer Layer — AES-256-GCM

- **Cipher:** AES-256 in Galois/Counter Mode. AES is a substitution-permutation network block cipher; GCM turns it into an authenticated stream cipher using counter mode + GHASH.
- **Nonce:** 12 bytes, independently randomly generated.
- **Input:** The inner ciphertext (from Step 2) is treated as the plaintext for this layer.
- **Output:** Double-wrapped ciphertext with a 16-byte GCM authentication tag.

#### Step 4: Zeroize and Package

Both `inner_key` and `outer_key` are explicitly zeroized after use. The result is packaged as:

```json
{
  "outer_nonce": "<12 bytes, base64>",
  "inner_nonce": "<24 bytes, base64>",
  "ciphertext": "<double-encrypted data, base64>",
  "epoch": 42
}
```

#### Decryption

Reverse order: base64 decode → AES-256-GCM decrypt (verifies GCM tag, strips outer layer) → XChaCha20-Poly1305 decrypt (verifies Poly1305 tag, strips inner layer) → plaintext. If **either** authentication tag fails, the entire decryption is rejected — no partial output.

---

### 3. Key Exchange Protocol

**Source:** `crypto/src/exchange.rs`

When a new member joins a room, they need the current group key — but the server must never see it.

#### Scenario: Alice is in a room. Bob joins.

The server tells Alice: "Bob joined — here are his public keys." Alice's client runs `initiate_key_exchange()`:

**Step 1 — X25519 ECDH:**

```
shared_ecdh = Alice_x25519_secret × Bob_x25519_public
```

This produces a 32-byte shared secret. Bob can independently compute the same value as `Bob_x25519_secret × Alice_x25519_public`. The math works because scalar multiplication on elliptic curves is commutative: `a·(b·G) = b·(a·G)`.

**Step 2 — RSA-OAEP Wrapping:**

Alice takes the 32-byte `shared_ecdh` and encrypts it with Bob's RSA-4096 public key using OAEP padding (SHA-256). This produces a 512-byte RSA ciphertext that only Bob's private key can decrypt.

This is the defense-in-depth layer: even if X25519 is somehow compromised, an attacker still needs to break RSA-4096. And vice versa.

**Step 3 — Double-Wrap the Group Key:**

Alice encrypts the current group key using `shared_ecdh` as the symmetric key, through the full double-wrap pipeline (XChaCha20-Poly1305 inner + AES-256-GCM outer).

**Step 4 — Ed25519 Signature:**

Alice signs `rsa_wrapped_b64 || json(encrypted_group_key)` with her Ed25519 signing key. This 64-byte signature proves:
1. The payload was authored by Alice (not a man-in-the-middle).
2. Nothing was modified in transit.

**Step 5 — Zeroize and Send:**

`shared_ecdh` is zeroized from memory. The payload is sent:

```json
{
  "rsa_wrapped_secret": "<512 bytes RSA-OAEP ciphertext, base64>",
  "encrypted_group_key": { "outer_nonce": "...", "inner_nonce": "...", "ciphertext": "...", "epoch": 5 },
  "signature": "<64 bytes Ed25519 signature, base64>"
}
```

#### Bob receives it — `complete_key_exchange()`:

1. **Verify Ed25519 signature** — Decode Alice's verifying key, reconstruct the signed data, verify the signature. Fails → reject (possible tampering).
2. **RSA-OAEP decrypt** — Use Bob's RSA private key to decrypt `rsa_wrapped_secret` → recovers the `shared_ecdh` that Alice computed.
3. **X25519 ECDH independently** — Bob computes `Bob_secret × Alice_public` himself.
4. **Compare** — If the RSA-decrypted value doesn't match the independently computed ECDH value → **possible MITM attack** → abort. The RSA-wrapped value and the ECDH value must be byte-identical.
5. **Decrypt the group key** — Using the verified `shared_ecdh`, double-wrap decrypt the `encrypted_group_key` → raw 32-byte group key.
6. **Install** — Bob creates a `GroupKeyRatchet::from_key(group_key, epoch)` and can now encrypt/decrypt room messages.

#### DM Keys — `derive_dm_key()`

For private direct messages between two members, a separate per-pair key is derived:

```
dm_key = HKDF-SHA256(IKM = ECDH(our_secret, their_public), info = "retro-dm-key")
```

Because ECDH is commutative, both parties derive the **same** DM key without any explicit exchange. The HKDF with a `"retro-dm-key"` info string provides domain separation — this key is cryptographically independent from the group key even though it uses the same ECDH shared secret.

---

### 4. Group Key Ratchet

**Source:** `crypto/src/ratchet.rs`

The ratchet provides **forward secrecy**: compromising the current key reveals nothing about messages encrypted under previous keys.

#### How It Works

```
K(0) ──HKDF──→ K(1) ──HKDF──→ K(2) ──HKDF──→ ...
  │               │               │
  └─ zeroized     └─ zeroized     └─ current
```

Each ratchet step:

```
K(n+1) = HKDF-SHA256(IKM = K(n), salt = epoch(n+1), info = "retro-ratchet")
```

After computing `K(n+1)`, the old key `K(n)` is **immediately zeroized** — overwritten with zeros in memory.

#### When It Ratchets

- **Member joins:** All existing clients ratchet forward. The new member receives the post-ratchet key, so they cannot decrypt any messages from before their arrival (not that they'd have the ciphertexts, but defense in depth).
- **Member leaves:** All remaining clients ratchet forward. The departed member still has the old key in memory, but all future messages are encrypted under a key they don't have.

#### Properties

- **One-way:** HKDF is a one-way function. Given `K(n+1)`, you cannot compute `K(n)`. This is what makes forward secrecy work.
- **Deterministic:** If two clients start with the same `K(0)` and ratchet the same number of times, they arrive at the same key. This is how everyone in the room stays in sync without further communication.
- **Epoch tracking:** The epoch counter increments with each ratchet step. It's used as the HKDF salt and is included in every `EncryptedPayload` so the decryptor knows which generation of subkeys to derive.

---

### 5. Zeroization

This is the "cryptographic death" principle — when something is no longer needed, it is actively destroyed, not just forgotten.

| What | When | How |
|------|------|-----|
| `SessionKeys` (X25519 + Ed25519 + RSA) | Disconnect / app close | `Drop` impl triggers `ZeroizeOnDrop` on X25519 secret and Ed25519 signing key |
| `GroupKeyRatchet` current key | Every ratchet step | Old key explicitly `zeroize()`d before installing the new one |
| `GroupKeyRatchet` (entire struct) | Leave room / room closed / disconnect | `Drop` impl calls `current_key.zeroize()` and zeros the epoch |
| Encryption subkeys (`K_inner`, `K_outer`) | After every encrypt/decrypt call | Explicitly `zeroize()`d after use |
| ECDH shared secrets | After key exchange | Explicitly `zeroize()`d in both `initiate` and `complete` key exchange |
| All client state (keys, members, DM keys) | Disconnect | All `RwLock` fields set to `None` / cleared, dropping values and triggering zeroization |
| Server-side ciphertexts | Room closed / message expiry | Zero-overwritten (`0x00` fill) before deallocation |

The result: after a session ends, a forensic analysis of the process memory would find only zeros where keys and ciphertexts used to be.

---

### 6. End-to-End Data Flow

Here's the complete path when you type `hello` and press Send:

```
 You type "hello"
  │
  ▼
 UTF-8 encode: [104, 101, 108, 108, 111]
  │
  ▼
 Read group ratchet → current key K_g at epoch e
  │
  ▼
 HKDF(K_g, salt=e, info="retro-inner-...") → K_inner
 HKDF(K_g, salt=e, info="retro-outer-...") → K_outer
  │
  ▼
 XChaCha20-Poly1305(K_inner, random 24-byte nonce, "hello") → C₁
  │
  ▼
 AES-256-GCM(K_outer, random 12-byte nonce, C₁) → C₂
  │
  ▼
 Zeroize K_inner and K_outer
  │
  ▼
 WebSocket send: { ciphertext: base64(C₂), nonces, epoch }
  │
  ▼
 ┌─────────────────────────────────────┐
 │           retro-server              │
 │  Receives opaque blob. No keys.    │
 │  Cannot read it. Broadcasts to     │
 │  all other room members.           │
 └─────────────────────────────────────┘
  │
  ▼
 Recipient reads their K_g at epoch e
  │
  ▼
 Derive K_inner, K_outer from K_g
  │
  ▼
 AES-256-GCM decrypt(K_outer, C₂) → C₁  (verifies GCM tag)
  │
  ▼
 XChaCha20-Poly1305 decrypt(K_inner, C₁) → "hello"  (verifies Poly1305 tag)
  │
  ▼
 Display: "anon_8f3k: hello"
```

The server is a dumb relay. It never touches a key, never sees plaintext. If someone seized the server's RAM, they'd find only ciphertext blobs and zero key material.

---

## Project Structure

```
Retr0/
├── Cargo.toml                  # Workspace: 4 crates
├── Cargo.lock
├── .gitignore
│
├── crypto/                     # retro-crypto — shared crypto library
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs              # Module exports
│       ├── types.rs            # Protocol types, error types, message enums
│       ├── keys.rs             # Session key generation (X25519 + Ed25519 + RSA-4096)
│       ├── encryption.rs       # Double-wrapped encrypt/decrypt
│       ├── exchange.rs         # Key exchange protocol + DM key derivation
│       ├── ratchet.rs          # Group key ratchet (forward secrecy)
│       └── registry.rs         # Registry-related types
│
├── server/                     # retro-server — WebSocket relay
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs             # CLI args, routes (/ws, /info)
│       ├── ws.rs               # WebSocket handler, message routing
│       ├── room.rs             # Room management, member tracking
│       ├── state.rs            # Shared server state (DashMap)
│       ├── cleanup.rs          # Background expiry + zero-overwrite
│       └── heartbeat.rs        # Optional registry heartbeat
│
├── registry/                   # retro-registry — server discovery
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs             # Heartbeat endpoint, server list API
│       └── state.rs            # Registry state
│
└── client/                     # retro-client — Tauri 2 desktop app
    ├── package.json
    ├── src/
    │   ├── index.html          # UI layout (sidebar, views, modal)
    │   ├── style.css           # Monochrome CRT aesthetic
    │   └── main.js             # All frontend logic
    └── src-tauri/
        ├── Cargo.toml
        ├── tauri.conf.json     # Tauri config (window, permissions)
        ├── capabilities/       # Tauri 2 permission capabilities
        └── src/
            ├── main.rs         # Tauri entry point
            ├── lib.rs          # Tauri builder, command registration
            ├── commands.rs     # 16 Tauri IPC commands
            └── ws.rs           # WebSocket client, all crypto operations
```

---

## Building & Running

### Prerequisites

- [Rust](https://rustup.rs/) (1.75+)
- [Tauri CLI](https://tauri.app/): `cargo install tauri-cli`
- macOS, Linux, or Windows

### Run the Server

```bash
cargo run -p retro-server
```

The server listens on `0.0.0.0:9300` by default. Options:

```bash
cargo run -p retro-server -- --port 9300 --registry http://localhost:9301
```

### Run the Client

```bash
cargo tauri dev
```

### Run the Registry (Optional)

```bash
cargo run -p retro-registry
```

### Run Crypto Tests

```bash
cargo test -p retro-crypto
```

All 21 tests cover: key generation, encryption roundtrips (empty, normal, 64KB), wrong-key rejection, ciphertext tampering detection, subkey independence, epoch separation, key exchange roundtrip, signature tampering rejection, wrong-receiver rejection, ratchet determinism, ratchet irreversibility.

---

*Retro — because privacy shouldn't require trust.*
