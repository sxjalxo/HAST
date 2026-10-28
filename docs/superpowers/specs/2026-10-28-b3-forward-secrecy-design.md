# B3: per-message forward secrecy

Status: **approved, Option A** (2026-10-28). Roadmap item B3. Implementation plan:
[docs/superpowers/plans/2026-10-28-b3-forward-secrecy.md](../plans/2026-10-28-b3-forward-secrecy.md).

Decided while planning:

* **One LiveChat tab per browser.** Two tabs would advance the same ratchet and reuse keys, so LiveChat takes a Web
  Lock; a second tab says LiveChat is open elsewhere. The ratchet and sender-key state live in their own encrypted
  entry that only that tab writes, so other pages' vault writes can't roll it back.
* **Ratchet state can't be copied.** Importing a key file now links the importing browser as a *new device* (B5) and
  removes the exported one, instead of continuing its chain with a stale ratchet. Its history doesn't travel.
* **Retired ML-KEM keys are kept 7 days** (was 90): they now only open conversation starts and messages that arrive
  while a browser was offline. The messaging page keeps what it decrypted in the same local store.
* **Every message of an epoch carries the epoch's KEM ciphertext and the sender's ratchet key**, so messages that
  arrive out of order (history pages back) still open. Key wraps use random nonces.
* **Quiet members.** A conversation the other side never answers stays in its first epoch, which was encapsulated to
  the recipient's long-term ML-KEM key; its forward secrecy is that key's lifetime (replaced weekly, kept 7 days).
  Everything after a reply is per message.

## Where HAST is today

* Private rooms: each message's key is wrapped with the recipients' current ML-KEM keys. Keys rotate at every HBSS
  handover and at least weekly; retired decryption keys are kept 90 days so history stays readable.
* Lobby: each sender has a group key, replaced at every handover or membership change; messages are encrypted under it.
* History is **re-read from the server and decrypted again on every page load**; nothing is stored locally in
  plaintext.

So someone who steals a browser's vault and its password can read everything sent to it in the last 90 days, and the
lobby messages under any group key it still holds. Forward secrecy means a stolen device can't read messages from
before the theft.

## The product decision

Forward secrecy and "re-read history from the server" are in direct conflict. To have forward secrecy, a browser has to
delete each message key once it has used it. After that, the server's ciphertext can't be opened again, so a reload
has to show history from a **local, encrypted copy** made when the message first arrived.

* **Option A (recommended): local history.** Each browser keeps the messages it received, encrypted under the vault
  key, in IndexedDB. Reloads read from there; the server's copy only fills in what arrived while offline. Clearing site
  data or switching browsers loses history on that browser (as in Signal).
* **Option B: keep server history, shorter windows.** No ratchet: rotate the ML-KEM key at every handover (already done)
  and delete retired decryption keys after 7 days instead of 90. Much smaller, but only "forward secrecy after a week",
  not per message.

## Design (Option A)

### Private rooms: a post-quantum double ratchet

* Session start: the first message to a contact's device encapsulates to that device's current ML-KEM key (as today)
  and derives a root key with HKDF-SHA-512.
* **KEM ratchet:** every message carries a fresh ephemeral ML-KEM-768 public key. The reply encapsulates to the newest
  one it has seen and mixes the shared secret into the root key. Each new direction of conversation gets a new
  ephemeral key, so a stolen state can't decrypt messages from before the last exchange.
* **Symmetric ratchet:** within one direction, each message key is `HKDF(chain_key)` and the chain key moves on; keys
  are deleted as soon as they are used. Skipped message keys (for messages that arrive out of order) are kept for up to
  1000 messages or 7 days, then deleted.
* Ratchet state per (contact device, this device) lives in the vault. Signatures (HBSS and SLH-DSA) and the
  replay rules don't change: they still cover the whole ciphertext.

### Lobby: ratcheting sender keys

* A sender's group key becomes a chain: message `n` is encrypted under `HKDF(chain_n)`, and receivers move their copy
  of the chain forward and delete what they've passed. Sender keys are still replaced at handovers and membership
  changes.

### Local history

* IndexedDB, one object store per account, each record encrypted with XChaCha20-Poly1305 under a key derived from the
  vault key. It holds what was shown (text, files, edits and deletes applied, the verification verdict and the
  signature data the inspector needs).
* Retention setting on the Account page (keep forever, 90 days, 30 days).

## Testing

* Core: a ratchet conversation with out-of-order delivery and skipped keys; a stolen state after message *n* can't
  decrypt messages before *n*; the KEM ratchet heals after a stolen state once both sides have sent.
* Browser: reload shows history from the local store; a second browser of the same account (B5) only sees messages
  sealed after it was linked; deleting site data loses history.

## Risks and costs

* The largest and most delicate change in the roadmap. Ratchets are easy to get subtly wrong. HAST's HBSS is already
  unreviewed; a hand-built PQ ratchet would be too. It should get an external review before anyone relies on it.
* It builds on B5: ratchet sessions are per device pair. Doing B3 after B5 avoids designing it twice.
* Message size: about 1.2 KB more per private message (the ephemeral ML-KEM key).
