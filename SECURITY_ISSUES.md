# Security Issues

This document tracks known security vulnerabilities identified in the codebase. Items are organized by severity. Each issue includes its location, a description of the problem, and its impact.

---

## 🔴 Critical

### 1. Transport Layer Defaults to Unencrypted

| | |
|---|---|
| **Location** | `client/src-tauri/src/ws.rs:80–84`, `client/src-tauri/src/commands.rs` |
| **Status** | Open |

**Description:**
The client defaults to `ws://` (plaintext WebSocket) and `http://` (plaintext HTTP) when no scheme is specified. `fetch_server_info()` in `commands.rs` defaults to HTTP.

**Impact:**
The application has an E2EE implementation, but if the WebSocket transport is unencrypted, a network-level attacker can tamper with key-exchange messages before encryption is even established. The double-wrap encryption protects message content, but key-exchange protocol messages — public key bundles, RSA-wrapped secrets, and signatures — travel over this connection. A man-in-the-middle attacker could substitute their own public keys before the encrypted session begins.

**Fix:** Default to `wss://` and `https://`. Reject connections that attempt to use plaintext schemes, or at minimum warn the user prominently.

---

### 2. `hash_password()` Uses Unsalted SHA-256

| | |
|---|---|
| **Location** | `crypto/src/lib.rs` |
| **Status** | Open |

**Description:**
Room passwords are hashed using a single-pass SHA-256 with no salt. SHA-256 is a general-purpose hash function, not a password hashing function. It has no work factor and is trivially reversible for common passwords via rainbow tables.

**Impact:**
Room passwords are trivially brute-forceable if an attacker captures the hash. Rainbow tables can reverse common passwords in microseconds.

**Fix:** Replace with a proper password hashing function such as `argon2`, `bcrypt`, or `scrypt` with a random per-password salt.

---

### 3. Server Has No Authorization Checks on Room Operations

| | |
|---|---|
| **Location** | `server/src/ws.rs` |
| **Status** | Open |

**Description:**
Two message handlers lack membership verification:
- **`SendMessage`** — No check that the sender is a member of the target room. Any connected client can send ciphertext to any room ID.
- **`DownloadFile`** — Any connected client can download any file if they know the `room_id` and `file_id`. No membership verification is performed.

**Impact:**
Unauthorized clients can inject messages into rooms they do not belong to, and can exfiltrate files from any room.

**Fix:** Before processing `SendMessage` or `DownloadFile`, verify that the requesting connection is an authenticated member of the specified room.

---

### 4. Frontend XSS via `innerHTML`

| | |
|---|---|
| **Location** | `client/src/main.js:641–657` (`showModal()`) |
| **Status** | Open |

**Description:**
The `showModal()` function assigns dynamic content — including raw error messages from the server — directly to `element.innerHTML` without sanitization:

```js
generic.innerHTML = bodyHtml;  // bodyHtml may contain unsanitized server error strings
```

**Impact:**
A malicious or compromised server can inject arbitrary HTML and JavaScript through error responses, leading to cross-site scripting (XSS) and potential full client compromise.

**Fix:** Use `textContent` instead of `innerHTML` for user/server-supplied strings. If HTML rendering is required, sanitize with a library such as [DOMPurify](https://github.com/cure53/DOMPurify) before assignment.

---

### 5. File Path Traversal

| | |
|---|---|
| **Location** | `client/src-tauri/src/commands.rs` (`download_file()`, `upload_file()`) |
| **Status** | Open |

**Description:**
`download_file()` accepts an arbitrary `save_path` from the frontend without validation and passes it directly to `tokio::fs::write()`. Similarly, `upload_file()` reads from an arbitrary path supplied by the frontend.

**Impact:**
A crafted path (e.g., `../../.ssh/authorized_keys`) could allow reading or overwriting sensitive files anywhere on the user's filesystem.

**Fix:** Validate and canonicalize all file paths. Restrict operations to a user-approved directory (e.g., a downloads folder). Use Tauri's file-system scope APIs to enforce path restrictions at the framework level.

---

### 6. RSA Key Zeroization Is a No-Op

| | |
|---|---|
| **Location** | `crypto/src/keys.rs:103–109` |
| **Status** | Open |

**Description:**
The `Drop` implementation for `SessionKeys` contains only comments — RSA private key material is never explicitly zeroized. The `rsa` crate does not guarantee `ZeroizeOnDrop` behaviour.

**Impact:**
After a session ends, private key material may remain in heap memory, increasing the window for memory-scraping attacks or cold-boot attacks.

**Fix:** Implement zeroization using the `zeroize` crate. Ensure the `ZeroizeOnDrop` derive or manual `zeroize()` calls are applied to all fields holding private key material.

---

## 🟠 High

### 7. No Rate Limiting or Resource Limits (Server DoS)

| | |
|---|---|
| **Location** | `server/` (general) |
| **Status** | Open |

**Description:**
The server imposes no protective limits:
- No maximum message size (100 MB+ JSON will hang the parser)
- No per-connection rate limiting (unlimited messages/second)
- No room creation limit (unbounded memory growth)
- No file upload size limit
- The `--max-players` CLI flag is never enforced; it is metadata-only

**Impact:**
Any connected client can exhaust server memory or CPU, causing a denial-of-service for all users.

**Fix:** Enforce a maximum frame/message size in the WebSocket layer, add per-connection rate limiting (e.g., using a token-bucket algorithm), cap room count and player count, enforce a file upload size limit, and wire `max_players` to actual room admission logic.

---

### 8. AES-GCM 96-bit Random Nonce Birthday Bound

| | |
|---|---|
| **Location** | `crypto/src/encryption.rs` |
| **Status** | Open |

**Description:**
The outer AES-256-GCM encryption layer generates random 96-bit nonces. The birthday collision probability reaches dangerous levels around 2^48 (~16 million) messages under the same key. While the ratchet rotates keys on membership changes, a stable room with no joins or leaves could theoretically reach this threshold in a high-traffic deployment.

**Impact:**
Nonce reuse under AES-GCM is catastrophic — it completely breaks both confidentiality and integrity for the affected messages.

**Fix:** Use a counter-based nonce instead of a random nonce, or adopt a nonce-misuse-resistant scheme (e.g., AES-GCM-SIV / XChaCha20-Poly1305).

---

### 9. Empty Rooms Never Cleaned Up

| | |
|---|---|
| **Location** | `server/src/` (room management) |
| **Status** | Open |

**Description:**
If a room creator disconnects without explicitly closing the room, and all remaining members also leave, the room persists in memory indefinitely. There is no automatic garbage collection for abandoned rooms.

**Impact:**
A long-running server will accumulate orphaned rooms, leading to unbounded memory growth and eventual OOM.

**Fix:** Implement a cleanup task that removes rooms with zero members after a configurable grace period.

---

### 10. Heartbeat Leaks Activity Data

| | |
|---|---|
| **Location** | `server/src/heartbeat.rs` |
| **Status** | Open |

**Description:**
Real-time `player_count` data is sent to the registry server over potentially plaintext HTTP. The registry operator can track activity patterns and correlate user presence over time.

**Impact:**
Even without access to message content, traffic-analysis metadata (who is online when) can be sensitive in a privacy-focused application.

**Fix:** Enforce HTTPS for registry heartbeats. Consider whether `player_count` needs to be reported at all, or whether it can be omitted or bucketed to reduce precision.

---

## 🟡 Medium

| # | Issue | Location | Detail |
|---|-------|----------|--------|
| 11 | CSP allows `'unsafe-inline'` styles | `tauri.conf.json` | Weakens XSS protections by permitting inline style injection |
| 12 | No heartbeat authentication | `registry/src/main.rs` | Anyone can register fake servers with arbitrary metadata |
| 13 | Permissive CORS on registry | `registry/src/main.rs` | `CorsLayer::permissive()` allows any origin to query the registry |
| 14 | Signature uses string concatenation | `crypto/src/exchange.rs` | `format!("{}{}", rsa_b64, json)` — fragile canonical form susceptible to length-extension ambiguity |
| 15 | Sensitive metadata in server logs | `server/src/ws.rs` | Handle-level data persists in log files |
| 16 | Room password stored in memory indefinitely | `server/src/room.rs` | Password hash is only cleared on explicit room destroy |
| 17 | DM key HKDF uses no salt | `crypto/src/exchange.rs` | Non-standard (functional, but inconsistent with the rest of the key derivation) |
| 18 | `.gitignore` missing secret file patterns | `.gitignore` | `.env*`, `*.pem`, `*.key` are not ignored — risk of accidental secret commits |
