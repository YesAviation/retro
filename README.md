Retro Crypto — How Every Piece Works
1. Session Key Generation (keys.rs)
The moment you hit "Connect" on a server, before the WebSocket even opens, your client generates three completely independent keypairs from scratch:

X25519 (Elliptic-Curve Diffie-Hellman)
What it is: A key-agreement protocol based on Curve25519. It produces a 32-byte secret key and a 32-byte public key.
What it does: Allows two parties who have never communicated to derive an identical shared secret by exchanging only their public keys. The math is shared = our_secret × their_public, and because elliptic-curve scalar multiplication is commutative, both sides get the same result.
Where it's used: Group key exchange (transferring the room key to new joiners) and DM key derivation (private pairwise keys between two members).
Implementation: X25519Secret::random_from_rng(OsRng) generates a random scalar on Curve25519. The public key is just the generator point multiplied by that scalar. The x25519-dalek crate handles this. The secret key implements ZeroizeOnDrop, meaning when the struct is freed, the memory is overwritten with zeros.
Ed25519 (Digital Signatures)
What it is: An Edwards-curve Digital Signature Algorithm. Produces a 32-byte signing key and a 32-byte verifying (public) key.
What it does: Lets you sign data so anyone with your public key can verify you authored it, but nobody can forge your signature. This is not encryption — it's authentication.
Where it's used: During key exchange, the existing member signs the payload so the new joiner can verify it actually came from that member and wasn't tampered with in transit (anti-MITM).
Implementation: SigningKey::generate(&mut OsRng) from ed25519-dalek. Signing produces a 64-byte signature. Verification is a point decompression + scalar multiplication check on the Edwards curve. The signing key implements ZeroizeOnDrop.
RSA-4096 (Asymmetric Encryption)
What it is: A 4096-bit RSA keypair. The public key is ~550 bytes (DER-encoded), the private key is much larger.
What it does: Allows encrypting data that only the private key holder can decrypt. Used here with OAEP padding (Optimal Asymmetric Encryption Padding) using SHA-256.
Where it's used: During key exchange, the ECDH shared secret is also encrypted with the recipient's RSA public key. This is the "belt and suspenders" — an attacker would need to break both X25519 and RSA-4096 to intercept the group key.
Implementation: RsaPrivateKey::new(&mut OsRng, 4096) generates two random 2048-bit primes, multiplies them, and computes the modular inverse for the private exponent. This is the slow step (~1-3 seconds unoptimized, <1s with the opt-level = 3 profile you have). The rsa crate handles the heavy number theory.
Why it's slow: RSA key generation requires finding large primes via probabilistic primality testing (Miller-Rabin), which involves modular exponentiation of huge numbers.
Public Key Bundle
After generation, public_bundle() exports the three public keys as base64 strings in a PublicKeyBundle:

This is the only thing that ever leaves your machine. Secret keys stay in local memory.

2. Double-Wrapped Encryption (encryption.rs)
Every message, file, and group-key-in-transit is encrypted twice using two completely different cipher families. The thinking: if a catastrophic vulnerability is found in one (like a side-channel attack on AES, or a mathematical break of ChaCha), the other still protects you.

Step 1: Subkey Derivation via HKDF-SHA256
You never use the raw group key directly. Instead, you derive two independent subkeys from it:

K
i
n
n
e
r
,
K
o
u
t
e
r
=
HKDF-SHA256
(
group_key
,
salt
=
epoch
,
info
)
K 
inner
​
 ,K 
outer
​
 =HKDF-SHA256(group_key,salt=epoch,info)

Specifically:

K
i
n
n
e
r
=
HKDF
(
IKM
=
group_key
,
salt
=
epoch bytes
,
info
=
"retro-inner-xchacha20poly1305"
)
K 
inner
​
 =HKDF(IKM=group_key,salt=epoch bytes,info="retro-inner-xchacha20poly1305")
K
o
u
t
e
r
=
HKDF
(
IKM
=
group_key
,
salt
=
epoch bytes
,
info
=
"retro-outer-aes256gcm"
)
K 
outer
​
 =HKDF(IKM=group_key,salt=epoch bytes,info="retro-outer-aes256gcm")
HKDF (HMAC-based Key Derivation Function) is a two-step process: extract (compress the input key material into a pseudorandom key using HMAC-SHA256 with the salt) and expand (use the pseudorandom key and the info string to produce output key material of any length). The different info strings guarantee the inner and outer keys are cryptographically independent even though they come from the same source. The epoch salt means keys derived at epoch 0 are completely different from epoch 1, etc.

Step 2: Inner Layer — XChaCha20-Poly1305
Cipher: XChaCha20 — a stream cipher from the ChaCha family (designed by Daniel J. Bernstein). It generates a keystream from the key + nonce and XORs it with plaintext.
Auth tag: Poly1305 — a one-time authenticator that produces a 16-byte MAC (message authentication code). This guarantees integrity: if even one bit of ciphertext is flipped, decryption fails.
Nonce: 24 bytes, randomly generated via OsRng.fill_bytes(). The "X" in XChaCha means "eXtended nonce" — 24 bytes vs the normal 12. With 24 bytes you get 
2
192
2 
192
  possible nonces, making random nonce collisions astronomically unlikely even across billions of messages (the birthday bound is around 
2
96
2 
96
  messages).
Output: ciphertext = plaintext XOR keystream || poly1305_tag (the ciphertext is the same length as plaintext plus 16 bytes for the authentication tag).
Step 3: Outer Layer — AES-256-GCM
Cipher: AES-256 in Galois/Counter Mode. AES is a substitution-permutation network block cipher; GCM turns it into an authenticated stream cipher using counter mode + GHASH authentication.
Nonce: 12 bytes, independently randomly generated.
Input: The output from Step 2 (the inner ciphertext + Poly1305 tag) is treated as the plaintext for this layer.
Output: Another ciphertext with a 16-byte GCM authentication tag appended.
Step 4: Zeroize and Package
After encryption, both inner_key and outer_key are explicitly zeroized (key.zeroize()). The result is packaged as:

Decryption
Reverse order: decode base64 → AES-256-GCM decrypt (strips outer layer + verifies GCM tag) → XChaCha20-Poly1305 decrypt (strips inner layer + verifies Poly1305 tag) → plaintext. If either authentication tag fails, the entire decryption is rejected.

3. Key Exchange Protocol (exchange.rs)
This is the most complex piece. When a new member joins a room, they need to receive the current group key — but the server must never see it.

Scenario: Alice is in a room. Bob joins.
On the server side: When Bob joins, the server tells Alice "Bob joined, here are his public keys." Alice then runs initiate_key_exchange():

Step 1 — X25519 ECDH:
shared_ecdh
=
Alice_x25519_secret
×
Bob_x25519_public
shared_ecdh=Alice_x25519_secret×Bob_x25519_public

This produces a 32-byte shared secret that Bob can independently compute as 
Bob_x25519_secret
×
Alice_x25519_public
Bob_x25519_secret×Alice_x25519_public. The math works because scalar multiplication on elliptic curves is commutative: 
a
⋅
(
b
⋅
G
)
=
b
⋅
(
a
⋅
G
)
a⋅(b⋅G)=b⋅(a⋅G).

Step 2 — RSA-OAEP Wrapping:
Alice takes that 32-byte shared_ecdh and encrypts it with Bob's RSA-4096 public key using OAEP padding (SHA-256). This produces a 512-byte RSA ciphertext. Only Bob's RSA private key can decrypt this.

This is the defense-in-depth: even if X25519 is somehow compromised, an attacker still needs to break RSA-4096 to recover the shared secret. And vice versa.

Step 3 — Encrypt the Group Key:
Alice takes the current group key and encrypts it using the shared_ecdh as the symmetric key — through the full double-wrap (XChaCha20 inner + AES-256-GCM outer). So the group key is protected by a key that's itself derived from ECDH.

Step 4 — Ed25519 Signature:
Alice signs rsa_wrapped_b64 || json(encrypted_group_key) with her Ed25519 signing key. This produces a 64-byte signature that proves:

This payload was authored by Alice (not a MITM).
Nothing was modified in transit.
Step 5 — Zeroize and Send:
The shared_ecdh is zeroized from memory. The payload is sent:

Bob receives it (complete_key_exchange()):
Verify Ed25519 signature: Decode Alice's Ed25519 verifying key from her public bundle, reconstruct the signed data, verify the signature. If this fails → reject (possible tampering).
RSA-OAEP decrypt: Use Bob's RSA private key to decrypt the rsa_wrapped_secret → recovers shared_ecdh (from Alice's perspective).
X25519 ECDH independently: Bob computes 
Bob_secret
×
Alice_public
Bob_secret×Alice_public himself.
Compare: If the ECDH result from step 3 doesn't match what was RSA-decrypted in step 2 → possible MITM attack → abort. This is a critical integrity check: the RSA-wrapped value and the independently-computed ECDH value must be byte-identical.
Decrypt the group key: Using the verified shared_ecdh, double-wrap-decrypt the encrypted_group_key → produces the raw 32-byte group key.
Install: Bob creates a GroupKeyRatchet::from_key(group_key, epoch) and can now encrypt/decrypt room messages.
DM Keys (derive_dm_key())
For private messages between two members, a separate per-pair key is derived:

dm_key
=
HKDF-SHA256
(
IKM
=
ECDH(us, them)
,
info
=
"retro-dm-key"
)
dm_key=HKDF-SHA256(IKM=ECDH(us, them),info="retro-dm-key")

Because ECDH is commutative, both parties derive the same DM key without exchanging anything extra. The HKDF with a "retro-dm-key" info string ensures domain separation — this key is cryptographically independent from the group key even though it comes from the same ECDH operation.

4. Group Key Ratchet (ratchet.rs)
The ratchet provides forward secrecy: if someone compromises the current key, they can't go backwards to read old messages.

How it works:
K
n
+
1
=
HKDF-SHA256
(
IKM
=
K
n
,
salt
=
epoch
n
+
1
,
info
=
"retro-ratchet"
)
K 
n+1
​
 =HKDF-SHA256(IKM=K 
n
​
 ,salt=epoch 
n+1
​
 ,info="retro-ratchet")

After computing 
K
n
+
1
K 
n+1
​
 , the old key 
K
n
K 
n
​
  is immediately zeroized — overwritten with zeros in memory.

When it ratchets:
Looking at ws.rs, the ratchet advances on:

Member joins (line ~342): Even though the new member won't have old ciphertexts, ratcheting means their key can't theoretically decrypt any old messages.
Member leaves (line ~353): The departed member still has the old key in their memory. By ratcheting, all future messages are encrypted under a key they don't have.
Properties:
One-way: HKDF is a one-way function. Given 
K
n
+
1
K 
n+1
​
 , you cannot compute 
K
n
K 
n
​
 . This is what makes forward secrecy work.
Deterministic: If two clients start with the same 
K
0
K 
0
​
  and both ratchet the same number of times, they arrive at the same key. This is how everyone in the room stays in sync.
Epoch tracking: The epoch counter increments with each ratchet. It's used as the HKDF salt and is included in EncryptedPayload so the decryptor knows which epoch-generation of subkeys to derive.
5. Zeroization (Everywhere)
This is the "cryptographic death" principle:

SessionKeys: The Drop impl ensures secrets are wiped. X25519Secret and SigningKey from dalek both implement ZeroizeOnDrop natively.
GroupKeyRatchet: Custom Drop impl calls self.current_key.zeroize() and zeros the epoch.
encrypt()/decrypt(): After use, inner_key.zeroize() and outer_key.zeroize() are called explicitly.
initiate_key_exchange() / complete_key_exchange(): shared_ecdh.zeroize() is called after use.
Disconnect: ws.rs sets session_keys and group_ratchet to None, which drops the old values, triggering ZeroizeOnDrop.
Room closed: All of group_ratchet, members, and dm_keys are cleared — the group key, DM keys, and all public key material vanish.
The server also does its own cleanup: ciphertexts stored in memory are zero-overwritten before deallocation (in server/src/cleanup.rs and server/src/room.rs).

6. Complete Data Flow — End to End
Here's what happens when you type "hello" and press Send:

Client gets plaintext: "hello" → UTF-8 bytes
Read group ratchet: Get current 
K
g
K 
g
​
  and epoch 
e
e
Derive subkeys: 
K
i
n
n
e
r
,
K
o
u
t
e
r
=
HKDF
(
K
g
,
e
)
K 
inner
​
 ,K 
outer
​
 =HKDF(K 
g
​
 ,e)
Inner encrypt: 
C
1
=
XChaCha20-Poly1305
(
K
i
n
n
e
r
,
nonce
24
,
"hello"
)
C 
1
​
 =XChaCha20-Poly1305(K 
inner
​
 ,nonce 
24
​
 ,"hello")
Outer encrypt: 
C
2
=
AES-256-GCM
(
K
o
u
t
e
r
,
nonce
12
,
C
1
)
C 
2
​
 =AES-256-GCM(K 
outer
​
 ,nonce 
12
​
 ,C 
1
​
 )
Zeroize 
K
i
n
n
e
r
K 
inner
​
  and 
K
o
u
t
e
r
K 
outer
​
 
Send over WebSocket: { type: "SendMessage", data: { room_id, payload: { outer_nonce, inner_nonce, ciphertext: base64(C_2), epoch: e } } }
Server receives: Stores opaque ciphertext, broadcasts to all other room members. Server never has any key. It sees only random bytes.
Recipient receives: Reads their own 
K
g
K 
g
​
  at epoch 
e
e, derives subkeys, AES-256-GCM decrypts 
C
2
C 
2
​
  → 
C
1
C 
1
​
 , XChaCha20-Poly1305 decrypts 
C
1
C 
1
​
  → "hello".
The server is a dumb relay. It never touches a key, never sees plaintext. If someone seized the server's RAM, they'd find only ciphertext blobs and no key material whatsoever.
