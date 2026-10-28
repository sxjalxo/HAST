# Architecture

HAST (Hash-based Authentication and Signature Toolkit); HBSS is the signature scheme inside it (`hast_core::hbss`).

```
browser (Leptos/WASM) ──https──► hast-server :8000  one origin
   │                              ├─ /                 built UI
   │                              ├─ /api/register|login|logout|me|recover|password|keys/<name>|directory   accounts
   │                              ├─ /ws               LiveChat (rooms, encrypted + doubly signed messages, rotation)
   │                              └─ /api/messaging/*, /ws/messaging   messaging (E2E, Hamming demo in the browser)
   ├── Web Worker (src/bin/worker.rs) runs hast_core::jobs: Argon2id, SLH-DSA, chain checks
   └── hast-core (the same crate runs in the page, the worker and the server)
        SQLite: accounts, key chains, sessions, chat frames, messaging messages
```

Every response carries a Content-Security-Policy (`script-src 'self' 'wasm-unsafe-eval'` plus the SHA-256 of trunk's
inline loader, read from `index.html` at start), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and
`Referrer-Policy: same-origin`.

`hast-core` has no I/O. Keygen, signing, verification, sealing and key-chain checking are the same code in the browser
and the server, so both sides agree on the rules.

## Accounts and sessions (`hast-server::{auth,db}`)

| endpoint | does |
|---|---|
| `POST /api/register {username, password, link, invite?}` | creates the account; `link` is `identity::register_link`: root, SLH-DSA key, ML-KEM key, and signatures over `hast-register-v2:<lowercase name>:<root>:<slh>:<kem>` by the new HBSS key and the new SLH-DSA key. Sets the session cookie. |
| `POST /api/login {username, password}` | Argon2id check, throttled; sets the session cookie; returns `{username, commitment, slh, kem}` of the current link. With a passkey on the account, returns `{passkey: {pending, options}}` and no cookie instead. |
| `POST /api/login/passkey {pending, id, clientDataJSON, authenticatorData, signature}` | step two: the passkey's assertion for the pending sign-in (one use, 5 minutes); sets the session cookie like login. |
| `GET /api/passkeys`, `POST /api/passkeys/options`, `POST /api/passkeys {name, id, clientDataJSON, attestationObject}`, `DELETE /api/passkeys/<id> {password}` | list, start registering, finish registering, and remove (needs the password) the account's passkeys. |
| `POST /api/logout`, `GET /api/me` | end / read the session (`/api/me` returns the same shape as login). |
| `POST /api/recover {password, root, slh, kem}` | signed in without the keys: appends a **recovery** link with new keys to the primary chain (needs the password again) and removes every other device. |
| `GET /api/devices`, `POST /api/devices/offer {salt, blob}`, `GET /api/devices/offer`, `POST /api/devices {device, name, link}`, `DELETE /api/devices/<device>` | the account's browsers; a link offer (the identity key encrypted under a code, kept 10 minutes); add a browser by the first link of its chain; remove one. |
| `POST /api/password {old, new}` | change password; every other session is ended. |
| `GET /api/keys/<name>[?device=<id>][&since=<root>]` | one device's key chain (the primary one by default; session required), or only the links after `root` (`"full": false`; the whole chain with `"full": true` if `root` is not in it). Clients verify with `identity::verify_chain` / `extend_chain` (or `verify_device` / `extend_device`) and cache what they verified. |
| `GET /api/directory` | every account with its primary root and `devices: [{device, head}]`, its active devices' current roots (session required): whom LiveChat encrypts to, and when a cached chain is stale. |

Sessions: 256-bit random token, SHA-256 stored, `HttpOnly; SameSite=Strict` cookie, sliding expiry. Both `Origin`
checks (POST and WebSocket upgrade) require the origin to equal `Host` (or `HAST_ALLOWED_ORIGINS`). Lockout:
5th consecutive failure for a name locks it for 1 s, doubling per failure up to 5 min; an IP gets 20 free failures.
Signup is limited to 10 per IP per hour. Passwords are 10-256 characters. The IP is the TCP peer, unless the peer is in
`HAST_TRUSTED_PROXIES`; then it is the right-most `X-Forwarded-For` entry that is not a trusted proxy.

Chain links (`hast-core::identity`) name an HBSS root plus the account's long-term keys (`slh`, `kem`):
`register` (HBSS + SLH-DSA signatures by the new keys), `rotate` (`hast-rotate-v2:<old>:<new>:<slh>:<kem>`, signed
by the previous HBSS key and co-signed by the SLH-DSA key; the SLH-DSA key stays, the ML-KEM key is normally new),
`recovery` (server-vouched, no signature, may bring new long-term keys). `verify_chain` accepts a chain only if it starts with a valid registration
and every link continues from the previous root. Links from before long-term keys (`v1`, HBSS only) still verify; such
an account gains long-term keys through its next (v2) rotation, which LiveChat sends automatically.

Devices: the registration's chain is the primary device, `d1`. Its SLH-DSA key is the account's **identity key**: it
gives the safety number, and every browser of the account holds it. Each other browser has a chain of its own (its own
HBSS keys and ML-KEM key) that starts with a `device` link, `hast-device-v1:<name>:<device>:<root>:<slh>:<kem>`, signed
by the browser's first HBSS key and co-signed by the identity key; `identity::verify_device` accepts it only under the
primary chain's current identity key and with no recoveries in it. Linking: a browser with the identity key encrypts it
under a random 10-character code (about 50 bits, Argon2id, XChaCha20-Poly1305) and posts that as the account's offer;
the user types the code on the new browser, which decrypts the key, makes its own keys and posts its `device` link. The
server never sees the code. Envelopes are sealed to `name` for the primary device and `name#<device>` for the others
(`identity::label`); the server adds `device` to every message it relays (it matches the commitment against the
account's active device heads). Removing a device is a server flag: it leaves the directory and can no longer send or
rotate, and its chain stays so its old messages still verify. A recovery always goes to the primary chain and brings a
new identity key, so the other devices stop verifying and the server marks them removed.

Passkeys (`hast-server::passkey`): WebAuthn credentials as a second sign-in factor. Registration options offer
ES256, Ed25519 and RS256 and ask for `"none"` attestation (the authenticator's make is not checked). Every answer is
checked for the ceremony type, the one-time challenge, the origin (equal to the request's `Origin`), the hash of the
relying-party id (`HAST_RP_ID`, else the request's host), user presence, the signature (`ring`) and a signature
counter that must go up. The credential's public key is stored as JSON in the `passkeys` table. Failed assertions
count towards the same lockout as wrong passwords; `hast-server user passkeys-off <name>` removes an account's
passkeys.

Schema changes are numbered steps in `db.rs` (`MIGRATIONS`), applied on start and tracked with `PRAGMA user_version`.

## LiveChat protocol (`/ws`, session cookie required)

The connection *is* the account: there is no `join`. First frames from the server: `system`, `welcome {username,
commitment, slh}` (`slh` null means the account still needs its long-term keys), `senderkeys` (the newest `senderkey`
frame of every sender), `history` (the newest 20 frames this account may see, each with its `seq`), then `users`.

Rooms: `lobby`, or `dm:<a>:<b>` (two lowercase names, sorted; `identity::dm_room`). Frames of a private room are
relayed and replayed only to its two members.

| client frame | fields | rules |
|---|---|---|
| `message` | `room`, `id`, `sentAt`, `sender`, `message`, `signature` (HBSS), `slhSignature` (SLH-DSA, base64), `commitment` | `sender` must be the account and in `room`, `commitment` its **current** key; `message` is a `ratchet::Envelope` or (older clients) a `pq::Envelope` (any room), or a `pq::GroupCt` (lobby); both signatures cover `identity::message_payload(room, id, sentAt, message)`; `id` is accepted once and `sentAt` must be within 5 min of the server clock; max 10 per 10 s; frame ≤ 1 MiB |
| `senderkey` | as `message`, `room` = `lobby` | `message` is an envelope sealing `{id, ck, n}` (the sender's new lobby sender-key chain; older clients `{id, key}`) to the members; stored as the sender's newest key |
| `rotate` | `link` (`identity::rotate_link`) | `identity::verify_next(head, link)` must pass and the link must carry long-term keys; it is appended to the account chain in the database |
| `older` | `before` (a `seq`), `room?` | answers `{type:"older", messages, more}`: up to 20 visible frames before `before` |

`senderkey`, `rotate` and `older` share a second budget of 10 per 10 s, so protocol frames do not use up the message
allowance. Server → client also: `message`, `senderkey` and `rotate` (relayed to everyone who may see them, except
the sending connection, with their `seq`), `error {reason}` (only to the offender; nothing invalid is stored or
relayed). A second connection of the same account sees rotations immediately because the head is read from the
database for every frame.

Frames live in the `chat_frames` table: the newest 5000, plus the newest `senderkey` per sender. A JSON-lines history
file from older versions (`HAST_HISTORY_FILE`) is imported once and renamed.

Sending: the client fetches `/api/directory`, verifies (or extends its cached copy of) each account's chain, and
collects every active device with an ML-KEM key from a verified chain (its own other devices included, itself not);
accounts without one are named in a notice. Messages are forward secret (`hast-core::ratchet`): in a private room the
text is sealed through this browser's **session** with each device (`ratchet::seal`, associated data = lowercase
sender name). In the lobby it is encrypted under the sender's **sender-key chain** (`ratchet::group_seal`, message `i`
under the chain's `i`-th key); when it has none, or the members (device labels and identity keys) changed, or its HBSS
key rotated, it first sends a `senderkey` frame handing a new chain to every device through sessions. Before signing it
rotates if the HBSS key has signed `ROTATE_AFTER` (8) times, counting the extra `senderkey` signature. Each rotation
also replaces the ML-KEM key; retired decryption keys are kept 7 days (at most 200), then deleted. On connect the client
also rotates when the ML-KEM key is over 7 days old or the account has no long-term keys yet.

Sessions (`ratchet::Session`) are a post-quantum double ratchet between two devices. The first epoch is encapsulated to
the recipient device's long-term ML-KEM key; each later epoch starts with a side's first message after hearing from
the other, encapsulated to the other's newest *ratchet key* (a fresh ML-KEM key in every message), mixed into the root
key with SHA3-256. Message keys within an epoch come from a hash chain. Every message of an epoch carries the epoch's
ciphertext and the sender's ratchet key (`Header {s, e, n, init, ct, pk}`), so late messages still open; keys skipped
over are kept up to 1000 per chain for 7 days, 4 receiving epochs per session, 3 sessions per peer device. A key is
deleted once used, and a failed open leaves the session unchanged. The send path saves the ratchet state before any
await. A conversation the other side never answers stays in its first epoch, so its forward secrecy is the long-term
key's (replaced weekly, kept 7 days).

Receiving: clients check each message again: HBSS signature under the carried root, that root is in the sender's
verified chain (re-fetching the chain once if the root is unknown, because the sender may have rotated), and the
SLH-DSA co-signature under the key that chain lists for that root, all over the payload above. Then they open the
envelope through their session with the sending device (accepting a new session with their current or a retired
long-term key), or the group ciphertext with their copy of the sender's chain from a verified `senderkey` frame, and
keep the text (see local history below); older formats still open with the long-term keys while those are kept. Duplicate ids and live messages signed over 5 minutes ago are shown as possible replays.
Messages signed by a key added by a recovery, or whose sender's safety number changed since last seen, carry a notice,
and are **unconfirmed** (amber, `data-status="unconfirmed"`, with a banner naming the sender) until the user marks the
sender's current safety number verified (`contacts::needs_confirmation`); a contact whose chain contains any recovery
starts out unconfirmed. The messaging page applies the same rule.
Messages signed with keys that a *later* recovery replaced are shown as not verified: whoever held the old keys could
have signed them with any send time. Ciphertexts this browser has no key for are shown as sealed. HBSS-only plaintext
messages from before encryption are shown with a notice.

Message content (`hast-core::content`): what is encrypted is plain text, or tagged JSON `{"hast":1,"kind":...}` for
an `edit` (`target`, `text`), a `delete` (`target`) or a `file` (`name`, `mime`, `data` base64, at most 256 KB). Text
that would read back as tagged JSON is itself tagged, so typing JSON can't fake a change. The server sees none of it:
an edit or delete is an ordinary signed, encrypted message, so it can't tell which message was changed, and all the
rules above apply unchanged. Receivers apply a change only if it verified and comes from the target's own sender in
the target's room (`content::may_change`); changes are applied in send order when rendering (`livechat::model::shown`), so
the order they arrive in doesn't matter, and an edited message then shows the edit's signatures. A change that fails
verification is shown as a failed message instead. Files are previewed inline only for PNG, JPEG, GIF and WebP; every
file is saved as `application/octet-stream`, and names lose paths, control characters and bidirectional overrides.

Local history: what a browser decrypted is kept in IndexedDB (`hast-history:<name>`, store `records`, keys
`chat:<sender>:<id>` and `messaging:<id>`), each record XChaCha20-Poly1305-encrypted under a random key in the vault.
LiveChat shows it first on load (signatures and keys are checked again, nothing is decrypted again) and merges what the
server sends; retention is set on the Account page (for good, 90 or 30 days). The ratchet and sender-key state is in
`hast_chat:<name>`, encrypted under the vault key, written only by the tab holding the Web Lock `hast-livechat:<name>`;
a second LiveChat tab shows `data-status="tab-locked"` instead.

Browser storage per account: `hast_vault:<name>` (HBSS key, long-term keys, retired decryption keys, group keys, and
the state that must not be planted: contacts' safety numbers and the verified chains this browser caches, as one
XChaCha20-Poly1305 blob under an Argon2id key from the password), `hast_kek:<name>` in sessionStorage (that key, for
this tab), `hast_key_uses:<name>`. Keys from before the vault (`hast_keys:`, `hast_lt:`) are moved into it at the next
unlock; safety numbers from the old plain `hast_trust:<name>` are moved in when LiveChat next opens, and the old
`hast_chains` cache is dropped (chains are fetched and verified again). Export keys downloads the vault as `{hastKeys: 1, username, vault}`; once imported and unlocked, that browser
is linked as a new device with the file's identity key, and the exported device is removed (copying ratchet state
would reuse keys).

## Messaging (`/api/messaging/messages`, `/ws/messaging`)

End-to-end encrypted, with the error-correction demo moved into the browsers (`hast-web/src/sealed.rs`):

* The sender builds `{mode:"GD", text}` or, in Hamming mode, `{mode:"QuantumMDS", codewords, errorRate}`: the text
  encoded with extended Hamming (`mds::encode_message`) and passed through the simulated noisy channel (2% bit errors).
  That JSON is sealed with `pq::seal` to every account with a verified ML-KEM key (and the sender), and the envelope
  is signed with the sender's SLH-DSA key over `identity::messaging_payload(id, sentAt, body)`. Only the long-term
  key signs here, so this channel never spends HBSS signatures.
* `POST /api/messaging/messages {id, sentAt, body, sig, clientId?}` or WebSocket `{type:"chat", ...same}`. The
  server requires a session, an envelope, a valid id seen once, `sentAt` within 5 minutes, and a signature that
  verifies under the sender's current SLH-DSA key; it stores `{id, senderId, ts, sentAt, body, sig}` and relays it.
  WebSocket errors come back as `{type:"error", reason}` to that connection only. Messages are kept for good in the
  `messages` table; a JSON store from older versions (`HAST_MESSAGING_STORE`) is imported once and renamed
  `*.imported`.
* Receivers verify the signature against the sender's verified chain, open the envelope, and run
  `mds::decode_message` themselves, showing how many bit errors were corrected and how many bytes were beyond repair.
  A signature that only verifies under a key a recovery has since replaced is shown as an integrity failure.
* The sender's browser updates its own unsent copy from the server's echo (matched by `clientId`) only when the echo
  is from that same account; `clientId` is not signed, so it never changes anyone else's message.
* `GET ?since=<ts>` lists up to 50 stored messages; the socket sends a `backlog` of 20 first. Messages from before
  encryption (`text` instead of `body`) carry no signature, so they are shown as unverified, with a note.

## Encryption and co-signing (`hast-core::pq`)

* `LongTermKeys`: SLH-DSA-SHAKE-128f signing key (32-byte public key) and ML-KEM-768 decapsulation key (1184-byte
  encapsulation key), hex-encoded.
* `seal(text, aad, recipients)`: random 32-byte message key, XChaCha20-Poly1305 over the text with `aad`; per recipient
  an ML-KEM encapsulation and the message key wrapped with ChaCha20-Poly1305 under the shared secret (associated data:
  the recipient's lowercase name). `open` reverses it.
* `group_seal` / `group_open` (`GroupCt {g, n, c, i?}`): XChaCha20-Poly1305 under a 32-byte group key named `g`
  (`ratchet::group_seal` sets `i` and uses that chain key).
* `LongTermKeys::rotate_kem`: new ML-KEM key; the old decryption key is retired, old retired keys are dropped.
* `derive_key`: Argon2id (default parameters) for the browser vault.
* `encrypt_local` / `decrypt_local`: XChaCha20-Poly1305 with a random nonce (the vault, and the BlackBerry mock's
  container key).
* `identity::fingerprint(name, slh)`: the 60-digit safety number.
* `identity::VerifiedChain`: what a verified chain leaves for clients: each root and co-signing key, the current
  encryption key, which links are recoveries, and when the server recorded each link (`at`, not signed). The signature
  inspector draws it as the sender's key history.
* `jobs::run`: the expensive operations behind one JSON call, for the Web Worker.

## Signatures (`hast-core::hbss`)

* key: 1024 random 64-byte preimages; leaf = SHA-512(preimage); public key = Merkle root.
* signature: digest, 64 digest-derived indices (de-duplicated, ~60), the revealed preimages, and for root-only keys
  one Merkle multiproof (shared siblings sent once, ~200 nodes instead of ~600).
* verify: recompute digest and indices, check preimage format, rebuild the root from the revealed leaves + proof.
* bounded use: each signature reveals ~6% of the preimages. The client rotates after 8 signatures (`ROTATE_AFTER`): `sign_rotation` / `verify_rotation` let the retiring key vouch for its successor, so an account is a chain of keys (stored server-side, verifiable by anyone).
* wire format: the 64-byte values travel as base64 (hex is still read), and are hex in memory, because the scheme hashes
  the hex text.

## Error correction (`hast-core::mds`)

Hamming(12,8) plus an overall parity bit (SECDED) in a 16-bit container: one flipped bit is corrected, two are
detected and reported, three or more may be miscorrected (inherent to the code).

## Other core modules

`cipher` (Cipher Lab pipeline, reversible byte steps, JSON/QR config), `hashlab` (SHA-256/512, SHA3-512, BLAKE2b),
`multi` (benchmarks and comparisons incl. real SLH-DSA-SHAKE-128f), `bbd` (BlackBerry Dynamics mock shaped like the
real SDK's `ApplicationConfig`).

## Web UI

`crates/hast-web`: Leptos client-side rendering, Tailwind CSS built by `npm run css` (triggered by Trunk's pre-build
hook).

* **Design tokens:** the palette is defined once, as `hast` in `tailwind.config.js` (void black background, graphite
  panels, crimson for primary actions and selection, cold silver text, and separate verified / warning / danger / link
  colours), and exposed to CSS as `--hast-*` in `style/input.css`. Use the `hast-*` classes (`bg-hast-surface`,
  `text-hast-verified`, ...) and the shared component classes (`hast-panel`, `hast-label`, `hast-mono`, `chip-*`,
  `nav-item`) rather than Tailwind's stock colours. Verification status always gets its own colour and a text label,
  never the crimson accent. Text colours pass WCAG AA (4.5:1) on every background; muted grey (`#8591A3`) is the
  dimmest.
* **Accessibility:** keyboard focus is always drawn (a global `:focus-visible` crimson outline, or the component's own
  ring); never remove an outline without a replacement. The shell has a "Skip to content" link (first Tab), a labelled
  sidebar `nav` whose drawer closes with Escape, and `aria-expanded` on the menu button. Inputs carry an accessible
  name (a `<label for>` or `aria-label`), icon-only buttons an `aria-label`, and tab bars `role="tab"` with
  `aria-selected`. In LiveChat the message list is a focusable region, and each message has an eye button that opens
  the inspector (clicking the message does the same with a mouse).
* **LiveChat code:** `pages/livechat/` is split by concern: `mod.rs` (the page and the connection loop), `crypto.rs`
  (signing, sealing, checking, opening, key handovers: the part to review closely), `protocol.rs` (what each server
  frame does, local history on load), `model.rs` (the message as shown, edits and deletes folded in) and
  `inspector.rs` (the signature inspector's views).
* **Shell:** `ui::AppShell` wraps every signed-in page in the sidebar (`ui::MODULES` lists the routes, labels and
  icons; a drawer on small screens) and `ui::PageHeader` gives each page the same header. Every module has its own
  route: `/`, `/chat`, `/messaging`, `/hbss-lab`, `/hbss-explained`, `/quantum-playground`, `/cipher-lab`,
  `/cipher-chat`, `/securecomm`, `/network`, `/blackberry`, `/blackberry/settings`.
* **Logo:** `logo.png` (copied to `/logo.png` by Trunk) is the mark in the sidebar and on the sign-in and loading
  screens; `favicon.ico` is the same emblem for the browser tab.
* **Demos:** modules that run on sample data (Cipher Chat, SecureComm, Network Simulator, BlackBerry SecureChat, BB
  Dynamics) are flagged in `ui::MODULES` and carry a "Demo" tag in the sidebar and on the overview, and
  `PageHeader demo=true` labels the page. The overview itself shows only real data: the member count, this account's
  key chain as verified in the browser, signatures on the current key and the encryption key's age.
* Status markers carry `data-status="verified"` or `"failed"`, which the browser tests use.

Two binaries: the app (`src/main.rs`) and the worker (`src/bin/worker.rs`, loaded from `/worker_loader.js`;
`src/worker.rs` falls back to running jobs in the page if it cannot start). Background tasks must check
`util::alive_flag()` before touching signals after an `.await`; signals are disposed when a page unmounts and touching
one panics.

Browser tests: `e2e/` (Playwright) starts the server on port 8123 with a fresh database and drives several browser
profiles: lobby and private rooms, locked keys, the legacy-account upgrade (seeded with
`cargo run -p hast-server --example seed_legacy`), key-file transfer, history paging, encrypted messaging with
in-browser error correction, a forged `clientId` that must not overwrite another sender's message, messages signed
with keys a recovery replaced, and editing, deleting and sending a file (with the key history in the inspector), a passkey ceremony, linking and removing a second browser, and local history with the one-tab lock (deleting it shows the server copy no longer opens). Each test browser sends its own `X-Forwarded-For` (the test server trusts localhost as
a proxy), so the per-address signup limit does not get in the way.

## Dependency note

`slh-dsa 0.1.0` does not compile against the newest `signature` pre-release, so `Cargo.lock` pins
`signature 2.3.0-pre.4`. Do not `cargo update` that package without checking.
