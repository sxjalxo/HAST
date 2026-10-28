# HAST

**Hash-based Authentication and Signature Toolkit**: post-quantum, end-to-end encrypted and signed chat plus a small secure-messaging suite, written in Rust.

Naming: **HAST** is the project. **HBSS** (Hash-Based Stateless Signatures) is the signature scheme it implements, so it keeps that name in code and docs (`hast_core::hbss`, HBSS*/HBSS**, the `/hbss-explained` and `/hbss-lab` pages).

| Crate | What it is |
|---|---|
| `hast-core` | Hash-based stateless signatures (HBSS, HBSS*, HBSS**), account key chains, SLH-DSA (FIPS 205) co-signing, ML-KEM-768 (FIPS 203) + XChaCha20-Poly1305 message sealing, extended Hamming (SECDED) error correction, a BB84-style QKD simulation, the Cipher Lab pipeline, hash-lab helpers, and the BlackBerry Dynamics mock. |
| `hast-server` | axum server on **one port**: the built UI, the account API (`/api/*`), LiveChat (`/ws`) and messaging (`/api/messaging/*`, `/ws/messaging`). Accounts and sessions in SQLite. |
| `hast-web` | Leptos (client-side) UI styled with Tailwind. |

## Run

```bash
cargo test --workspace --exclude hast-web      # unit + real-server integration tests
# one-time: rustup target add wasm32-unknown-unknown && cargo install trunk && (cd crates/hast-web && npm install)
cd crates/hast-web && trunk build
cd ../.. && HAST_STATIC_DIR=crates/hast-web/dist cargo run -p hast-server
# open http://localhost:8000 and create an account
```

For hot reload run `trunk serve` in `crates/hast-web` (port 5173, proxies `/api` and `/ws` to :8000) and start the server with `HAST_ALLOWED_ORIGINS=http://localhost:5173`.

Configuration (environment variables):

| variable | default | meaning |
|---|---|---|
| `PORT` | `8000` | listen port |
| `HAST_DB` | `hast.db` | SQLite file (accounts, key chains, sessions, LiveChat history) |
| `HAST_STATIC_DIR` | none | built UI to serve |
| `HAST_SIGNUP` | `open` | `open`, `invite` (needs `HAST_INVITE_CODE`) or `closed` |
| `HAST_COOKIE_SECURE` | off | `1` adds `Secure` to the session cookie: set it behind HTTPS |
| `HAST_SESSION_DAYS` | `7` | sliding session lifetime |
| `HAST_ALLOWED_ORIGINS` | none | extra `Origin`s allowed for POSTs and WebSockets (comma separated) |
| `HAST_TRUSTED_PROXIES` | none | reverse-proxy IPs whose `X-Forwarded-For` is used for login throttling (comma separated) |
| `HAST_RP_ID` | the request's host | passkey relying-party id: the site's domain, e.g. `chat.example.org` |
| `HAST_HISTORY_FILE` | `_chat_history.jsonl` | LiveChat history file from older versions: imported into the database once, then renamed `*.imported` |
| `HAST_MESSAGING_STORE` | `_gd_fallback_storage.json` | JSON messaging store from older versions: imported into the database once, then renamed `*.imported` |

Operator commands: `hast-server user list` and `hast-server user reset <name>` (new password on stdin; ends that account's sessions). There is no email, so this is how a forgotten password is handled.

Docker: `docker compose up --build` (port 8000, data in a volume; put a TLS proxy in front and set `HAST_COOKIE_SECURE=1`).
CI (`.github/workflows/ci.yml`): fmt, clippy (`-D warnings`, native and wasm), tests, release web build, and browser tests (Playwright, `e2e/`). Details in [ARCHITECTURE.md](ARCHITECTURE.md).

Browser tests locally (after `trunk build` in `crates/hast-web`; `PW_CHANNEL=msedge` or `chrome` uses an installed browser instead of downloading one):

```bash
cd e2e && npm install && PW_CHANNEL=msedge npx playwright test
```

## Docs

| doc | for |
|---|---|
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | using the app: accounts, LiveChat, the lab and playground pages, messaging |
| [docs/HBSS.md](docs/HBSS.md) | the signature scheme: keys, signing, verification, sizes, why keys rotate |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | hosting: Docker, TLS proxy (nginx), operations, backups, checklist |
| [docs/BLACKBERRY.md](docs/BLACKBERRY.md) | how the BlackBerry Dynamics mock maps to the real SDK |
| [docs/FAQ.md](docs/FAQ.md) | common questions |
| [ARCHITECTURE.md](ARCHITECTURE.md) | endpoints, protocols, crate internals |

## Pages

Everything needs an account; a sidebar links every module. `/` overview · `/chat` LiveChat (lobby and private rooms) · `/messaging` (end-to-end encrypted channel with a Hamming error-correction demo) · `/hbss-lab` (benchmarks, hash lab, scheme comparison, signing flow) · `/hbss-explained` · `/quantum-playground` · `/cipher-lab` · `/cipher-chat` · `/securecomm` · `/network` · `/blackberry` · `/blackberry/settings` (BB Dynamics).

## Accounts and identity

* **Password** (Argon2id, min 10 characters) proves who you are to the server. **Sessions** are random 256-bit tokens in an `HttpOnly; SameSite=Strict` cookie; only their hash is stored. Failed logins lock a name and an IP for exponentially longer; unknown and known users fail identically. Cross-site POSTs and WebSocket upgrades are refused by `Origin` check.
* **Keys**, all generated in your browser: an HBSS key (rotates every 8 signatures), an SLH-DSA key that co-signs everything the HBSS key signs, and an ML-KEM-768 key others encrypt to (replaced at every handover and at least weekly, for forward secrecy). At signup you sign `hast-register-v2:<name>:<root>:<slh>:<kem>` with both signing keys; the server only ever sees public keys.
* **Keys at rest:** they sit in localStorage in a vault encrypted with XChaCha20-Poly1305 under a key derived from your password (Argon2id), together with your contacts' safety numbers and the key chains your browser has verified, so a copy of the browser profile cannot be edited to plant them. The derived key lives in sessionStorage, so a reload stays unlocked; a new tab or a sign-out asks for the password again. **Export keys** downloads the (still encrypted) vault, and importing it moves the account to another browser without a recovery.
* **Safety numbers:** 60 digits derived from an account's name and SLH-DSA key. Compare them out of band and mark them verified; LiveChat remembers each contact's number and warns when it changes. A contact whose keys came from a recovery (which only the server vouches for), or whose number changed, is shown as **unconfirmed** (amber, never green) until you confirm the new number.
* **Passkeys:** on the Account page you can add a passkey (WebAuthn: fingerprint, face, PIN or security key). From then on the password alone no longer starts a session: the server also asks for the passkey. The encryption keys stay in the password-protected vault either way.
* **Page hardening:** a strict Content-Security-Policy (only HAST's own scripts, plus trunk's inline loader by hash), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin`. Expensive crypto runs in a Web Worker.
* **Key chain:** an account is a chain of keys. Each rotation is signed by the previous HBSS key and the SLH-DSA key; anyone can verify the chain from the account name alone (`GET /api/keys/<name>`, verified again in the browser, which caches verified chains and then fetches only new links with `?since=<root>`). LiveChat only shows a message as verified if its keys are in the sender's chain, and only encrypts to keys from chains it verified.
* **More browsers:** on the Account page, **Link a new browser** shows a one-time code; type it on the new browser after signing in. Each browser gets its own signing and encryption keys, vouched for by your identity key (the SLH-DSA key behind your safety number), so nothing changes for the people you talk to. Messages are sealed to every linked browser.
* **New device, no other browser:** signing in with the password on a browser that has no keys also offers to create new ones. The server records that as a *recovery* link, which carries no signature from the old keys; contacts see "Signed with a key added by account recovery" on those messages, and messages sealed to the old keys cannot be read on the new device. Messages that were signed with the old keys are shown as not verified from then on, because whoever held those keys could have signed them.
* **Operator trust:** the server vouches for recovery links, so a malicious operator can add one. Clients show it; they cannot prevent it.

## LiveChat messages

* **Rooms:** the lobby, and a private room for any two accounts. The server relays and replays a private room's frames only to its two members.
* **Encrypted end to end, with forward secrecy:** every two browsers share a post-quantum double ratchet (ML-KEM-768): each message's key is used once and deleted, and every reply brings fresh ML-KEM keys. Private messages go through it; in the lobby each sender has a sender-key chain, handed out through the ratchet and moved forward with every message. Ciphertexts are bound to the sender's name. The server stores and relays only ciphertext.
* **History lives in your browser:** since the keys are gone after use, each browser keeps what it decrypted in IndexedDB, encrypted under a key in your vault (kept for good, 90 or 30 days: Account page). LiveChat runs in one tab per browser.
* **Signed twice:** both signatures (HBSS and SLH-DSA-SHAKE-128f) cover `hast-msg-v1:<room>:<id>:<sentAt>:<ciphertext>`; the server and every reader check both. If HBSS (unreviewed) had a flaw, the standard SLH-DSA signature still has to be forged.
* **No replays:** the server accepts a message id once and only with a signed send time within 5 minutes of its clock; clients flag duplicates and late deliveries.
* **Edits, deletes and files:** you can edit or delete your own messages and attach files up to 256 KB. Each is an ordinary signed, encrypted message, so the server can't tell which message changed; readers apply a change only if it verified and comes from the original sender, in the same room. Files are saved as bytes and previewed inline only for plain image types.
* **Key history:** the signature inspector shows the sender's whole key chain as your browser verified it: registration, rotations, recoveries (vouched for by the server only), where the safety number changed, and which key signed the message.
* A message is about 50 KB of JSON (signatures travel as base64). Messages are limited to 4000 characters (checked in the browser, since the server cannot read them). History lives in SQLite; the newest 20 frames come on connect and **Load older messages** pages back.

## Signatures

* Private key: 1024 random 64-byte preimages. Leaf = SHA-512(preimage). Public key = Merkle root (64 bytes); the leaf list may accompany it.
* A signature carries the SHA-512 digest, ~60 indices derived from the digest (de-duplicated), the revealed preimages and, for root-only keys (HBSS**), one Merkle multiproof for all of them. LiveChat sends the proof, so anyone can verify with only the root.
* `verify` recomputes digest and indices and authenticates every preimage against the leaf list or up to the root.
* **Bounded use:** each signature reveals about 6% of the preimages, so a key weakens as signatures accumulate (`forgery_gets_easier_as_signatures_leak`). LiveChat therefore rotates keys automatically every 8 signatures.
* Keys carry a `version`; stale ones are ignored.
* The server rejects: messages from a connection that is not the account, an HBSS signature or SLH-DSA co-signature that does not verify, a key that is not the account's current key, plaintext, a room the sender is not in, a reused id or a send time over 5 minutes off, frames over 1 MiB, more than 10 messages (and separately 10 protocol frames) per 10 s.

## BlackBerry Dynamics

The SDK (React Native, `C:\Program Files\BlackBerry_Dynamics_SDK`) is a set of native iOS/Android modules that need a UEM-activated mobile app, so it cannot run in a browser or this server. This project mocks it with the SDK's real shapes: `ApplicationConfig` (`getApplicationConfig()`), a free-form policy object (`getApplicationPolicy()`), AsyncStorage-style key/value storage (localStorage in the UI, a JSON file on the server), and plain `fetch`/WebSocket for networking. The DLP switches in BB Dynamics settings drive `copyPasteOn`, `preventPasteFromNonGDApps`, `preventScreenCapture` and `preventScreenRecording`.
A real BlackBerry client would be a separate React Native/Android app talking to this server.

## Known limits

* Hamming SECDED corrects one bit and detects two per word; three or more flips in a word can still be miscorrected.
* No email: password reset is an operator command. No two-factor sign-in or OAuth.
* The server does not do TLS; run it behind a TLS proxy (and list it in `HAST_TRUSTED_PROXIES` so login throttling sees client IPs).
* History doesn't move between browsers: a newly linked or imported browser, or one whose site data was cleared, sees only messages from then on. People who join later cannot read earlier messages either.
* A conversation the other side never answers stays protected by their long-term ML-KEM key (replaced weekly, kept 7 days after) rather than per message, until they reply.
* One browser per account at a time: importing a key file elsewhere makes the old browser's keys stale.
* HBSS itself is unreviewed; its signatures are always paired with a standard SLH-DSA signature. Sender-key frames cost about 1.5 KB per member, and key chains grow by one link per 8 messages; both suit small to medium groups.
* The messaging channel signs with SLH-DSA only (no HBSS) and seals each message to every member (about 1.5 KB each); at 2% simulated bit errors, Hamming SECDED leaves roughly one byte in forty damaged.
* The CSP hash of trunk's loader is read from `index.html` when the server starts: restart the server after rebuilding the UI.
* The BlackBerry Dynamics SDK itself is not used (see above).
