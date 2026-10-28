# B3 Forward Secrecy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Per-message forward secrecy in LiveChat: keys are deleted once used, and history comes from an encrypted copy kept in each browser.

**Architecture:** `hast-core::ratchet` adds a pairwise post-quantum double ratchet (ML-KEM-768 KEM ratchet, SHA3-256 KDF chains) between devices, and hash-chain sender keys for the lobby. Private messages and sender-key distributions are sealed through the ratchet; lobby messages use the sender-key chain. The browser keeps decrypted messages in IndexedDB, encrypted under a key in the vault.

**Tech Stack:** Rust (hast-core, Leptos CSR + web-sys IndexedDB / Web Locks), axum server, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-28-b3-forward-secrecy-design.md` (Option A, with the decisions listed at its top).

## Global Constraints

- The user commits; never run `git commit`. Give a one-line message at the end.
- No new dependencies (KDF: SHA3-256 with length-prefixed, labelled inputs, from the `sha3` crate already used).
- Skipped message keys: at most 1000 per chain, deleted after 7 days. Receiving chains kept per session: 4.
- Old formats (`pq::Envelope`, `GroupCt` without an index) still open with the long-term keys while they are kept.

---

### Task 1: Core ratchet (`crates/hast-core/src/ratchet.rs`)

**Produces:**
- `Session` (serde): `initiate(peer_kem_hex, peer_identity) -> Option<Session>`, `accept(&Header, &LongTermKeys, peer_identity) -> Option<Session>`, private `next_send`/`receive`.
- `Header {s, e, n, init, ct, pk}`, `Wrapped {header fields + nonce, key}`, `Envelope {nonce, ct, to: BTreeMap<label, Wrapped>}`.
- `seal(text, aad, to: Vec<(label, &mut Session)>) -> Envelope`; `open(&Envelope, my_label, &mut Session, aad, now) -> Option<String>` (session only advances on success); `Envelope::header(label)`.
- `SendKey {id, chain}`, `RecvChain {e, ck, n, skipped}`; `SendKey::new()`, `SendKey::distribution()`, `RecvChain::from_distribution`, `group_seal(&mut SendKey, text, aad) -> pq::GroupCt` (with `i`), `group_open(&mut RecvChain, &GroupCt, aad, now)`.
- `pq`: `kem_pair`, `encapsulate`, `decapsulate` made `pub(crate)`; `GroupCt.i: Option<u32>`.

- [ ] Tests: a conversation with replies in both directions; out-of-order and skipped keys; a used key can't be used again; the skip limit; a copy of the state after message n can't open messages before n; a stolen state stops opening new messages once both sides have replied; crossing first messages (two sessions) both open; a tampered wrap leaves the session unchanged; sender-key chains in and out of order.
- [ ] `cargo test -p hast-core`

### Task 2: Web storage: chat state, local history, tab lock

**Files:** `crates/hast-web/src/auth.rs`, create `crates/hast-web/src/history.rs`, `Cargo.toml` (web-sys Idb* features)

- `auth::ChatState {sessions: HashMap<label, Vec<Session>>, sending: Option<SendKey>, sending_members, sending_root, received: HashMap<sender, Vec<(id, RecvChain)>>}` in its own encrypted entry `hast_chat:<user>`: `load_chat_state`, `save_chat_state`.
- Vault `history_key`; `history::put(user, key, &Value)`, `history::all(user) -> Vec<(String, Value)>`, retention (`history_days` kept in the vault: 0, 90 or 30).
- `util::take_tab_lock(name) -> bool` (Web Locks, `ifAvailable`).

### Task 3: LiveChat and messaging on ratchets

- Send: DMs sealed with `ratchet::seal` to every other device (not to this one); lobby sender keys distributed with `ratchet::seal`, lobby messages with `ratchet::group_seal`. The sent frame and its plaintext go to local history.
- Receive: local history first; else ratchet / chain / legacy open; store what opened.
- Mount: show local history, then merge the server's frames; one-tab lock.
- Import: link as a new device, remove the exported one.
- Messaging page: cache opened messages locally. `KEM_KEEP_MS` 7 days.
- Account page: history retention.

### Task 4: Server, tests, docs

- Server `validate`: accept `ratchet::Envelope`.
- E2E: reload reads local history; a second tab is refused; import links a new device.
- Docs: ARCHITECTURE, README, USER_GUIDE, FAQ; tick B3; stack B report.
