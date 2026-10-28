# B5: more than one browser per account (devices)

Status: **proposed**, waiting for approval. Roadmap item B5.

## Problem

An account is one key chain, held by one browser at a time. Moving to another browser either transfers the vault
(Export keys, then the old browser stops working) or creates new keys through a recovery, which only the server vouches
for and which, since B4, makes every contact see you as "Unconfirmed keys". People who use a laptop and a phone
can't be signed in on both.

## Goals

* Several browsers ("devices") active on one account at the same time, each able to send and read new messages.
* Adding a device is vouched for by a device you already have, not by the server, so contacts see no warning and the
  safety number doesn't change.
* Recovery (no device left) still works as today, and still shows as a recovery.
* No change to what the server can see: it still only holds public keys and ciphertext.

Not goals: syncing old history to a new device (it was sealed before the device existed; same as today), or syncing
read state.

## Design

### Keys

* **Identity key (shared):** the account's SLH-DSA key. It co-signs every link today; it becomes the key that vouches
  for devices. All of an account's devices hold it. The safety number stays derived from it, so it doesn't change when
  a device is added.
* **Per device:** its own HBSS chain (each device rotates on its own, so two devices never sign with one few-time key)
  and its own ML-KEM key (each device decrypts only what was sealed to it; rotations need no syncing).

### The chain becomes per device

* Every link gets a `device` id (`d1` for every existing chain, by migration). The server stores links per
  `(account, device)`; a device's chain starts with either the account's registration (the first device) or an
  **add-device** link: `hast-device-v1:<name>:<device>:<root>:<slh>:<kem>`, signed by the identity key and by the
  new device's first HBSS key.
* `identity::verify_devices` checks every device chain: the first device from its registration (or recovery), each
  other device from an add-device link signed by the identity key that is current at that point. A recovery replaces
  the identity key; device chains signed by the old identity stop verifying and must be linked again.
* Removing a device: a flag on the server, which then leaves it out of the directory (so clients stop sealing to it)
  and refuses its messages and rotations. Its old messages still verify. Every device holds the identity key, so a
  lost or stolen device could sign itself back in: only a recovery (a new identity key) cuts it off for sure.
* A recovery (always on the primary chain, `d1`) replaces the identity key, so the server marks every other device
  removed, and clients stop accepting their chains.

### Linking a new browser

1. On a device you already have, the Account page's **Link a new browser** makes a random 10-character code
   (`xxxxx-xxxxx`, about 50 bits), encrypts the identity key under Argon2id(code, random salt) with
   XChaCha20-Poly1305, and posts the result as the account's link offer (one at a time, 10 minutes).
2. On the new browser, sign in (password and passkey). Instead of "Create new key" (a recovery), type the code under
   **Link this browser**. It fetches the offer, decrypts the identity key, makes its own HBSS and ML-KEM keys, signs
   its add-device link with both, and posts it.
3. The server checks the link and the browser is active. The server never sees the code, and guessing it offline
   costs an Argon2id run per try.

*Changed during implementation:* the first draft had the new browser show a 6-digit code, compared by eye before the
existing device sealed the identity key to the new browser's transfer key. A malicious server sees that transfer key,
so it could generate keys of its own until one matched the 6 digits (about a million tries) and receive the identity
key. A typed code that the key is encrypted under has no such shortcut.

### Server

* Migration: `key_chain.device TEXT NOT NULL DEFAULT 'd1'`, uniqueness per `(account, device, seq)`; a
  `link_requests` table (account, device, public parts, sealed identity, expiry).
* `GET /api/keys/<name>` returns every device's chain; `GET /api/directory` returns each account's device heads.
* LiveChat: a message's `commitment` must be the head of one of the account's devices (today: of the account); the
  rotate frame names its device.
* `GET /api/devices`, `POST /api/devices/offer` (existing device), `GET /api/devices/offer` and `POST /api/devices`
  (new device), `DELETE /api/devices/<device>`.

### Clients

* `contacts::Dir` holds every verified device of a contact; `recipients()` returns one ML-KEM key per device, and
  envelopes are sealed to `name#device` labels (sender keys in the lobby too).
* `check()` accepts a root from any of the sender's verified device chains; the key history (C9) groups links by
  device and marks add-device links as "added by another device of this account".
* The vault remembers this browser's device id. The Account page lists devices (this one marked) with Remove.
* The messaging page seals to every device too.

## Testing

* Core: `verify_devices` accepts identity-signed add-device links and rejects ones signed by another identity, links
  after a recovery that weren't relinked, and add-device links with no HBSS signature from the new device.
* Server: two devices of one account both send; a link request can't be approved without the identity key's
  signature; rotations per device don't collide.
* Browser: link a second browser by code, both send and read new messages, contacts see no "Unconfirmed keys", remove
  the second device and it can no longer decrypt new messages.

## Risks and costs

* The largest change in the roadmap: core identity rules, the server's key storage, LiveChat validation, and every
  place that seals or verifies. About as much code as stack C.
* Message size grows with devices: each device adds one ML-KEM ciphertext (about 1 KB) per private message and per
  sender key.
* Anyone who can approve on one of your devices can add a device. The code check is what stops a stranger's request
  from being approved by mistake.
