# Roadmap

Improvements, worked one stack at a time: A, then C, then B, then D. Each stack is finished and reported before the
next one starts. Tick an item when it is done, and note what was decided.

## A. Catch-up

- [x] **A1. Refresh the docs** after the vault, recovery and UI changes.
- [x] **A2. Messaging store in SQLite.** The JSON file was rewritten in full for every message; it is now the
  `messages` table, and an old store is imported once.

## C. Product

- [x] **C7. File attachments, editing and deleting messages.** The FAQ lists these as "not yet". Large, needs a spec.
  *Done (LiveChat):* edits, deletes and files are tagged content inside the encryption (`hast-core::content`), sent as
  ordinary signed messages, so the server and protocol are unchanged and the server can't see what changed. Receivers
  apply a change only if it verified and comes from the author in the same room. Files up to 256 KB; inline previews
  only for PNG/JPEG/GIF/WebP, every file saved as `application/octet-stream`, file names stripped of paths, control and
  bidi characters. A delete hides the message for everyone; the server keeps the ciphertext (it can't read it), within
  the usual 5000-frame window. The messaging page doesn't have these yet.
- [x] **C8. A decision on the demo pages.** BlackBerry SecureChat, SecureComm and Cipher Chat run on fake data
  ("Sarah Connor"). Either label them clearly as demos or remove them, so the product doesn't look like it does more
  than it does. Small, but a product call.
  *Decided: label, don't remove.* Cipher Chat, SecureComm, Network Simulator, BlackBerry SecureChat and BB Dynamics
  carry a "Demo" tag in the sidebar and on the overview, and a "Demo · sample data" label on the page. The overview's
  made-up figures (entropy feed, "3 active", "47 rotations", "98.7%", message center) were replaced by real ones:
  members, your verified key chain, signatures on the current key, encryption key age.
- [x] **C9. A key-chain timeline for each contact:** registration, rotations and recoveries shown visually, with a
  verified status on each link. The design brief asked for key-chain diagrams, and this also makes B4 visible. Medium.
  *Done:* "Key history" in the signature inspector, newest first: each link's kind and how it was vouched for (signed
  by the previous key, or by the server only for a recovery), where the safety number changed, keys a later recovery
  replaced, and the key that signed the selected message. Built from the chain the browser verified; link times are
  now kept in `VerifiedChain::at` (recorded by the server, not signed).

## B. Security and cryptography

- [x] **B3. Per-message forward secrecy.** The FAQ calls it "partial": encryption keys are replaced weekly, but there
  is no Signal-style ratchet. Large, needs a spec.
  *Done, option A* ([spec](superpowers/specs/2026-10-28-b3-forward-secrecy-design.md),
  [plan](superpowers/plans/2026-10-28-b3-forward-secrecy.md)): a post-quantum double ratchet between devices
  (`hast-core::ratchet`), sender-key chains for the lobby, history kept per browser in IndexedDB (encrypted, with a
  retention setting), one LiveChat tab per browser, retired ML-KEM keys kept 7 days, and key-file import linking a new
  device. Hand-built and unreviewed, like HBSS: it should get an external review before anyone relies on it.
- [x] **B4. Recovery hardening.** The server can add a "recovery" link with new keys to any account, and clients only
  show a notice. Options include requiring out-of-band confirmation from contacts, or showing a recovery prominently
  in the contact's key history. Medium.
  *Done:* a contact whose verified chain contains a recovery, or whose safety number changed, is **unconfirmed** until
  you compare safety numbers and mark the current one verified. Their messages show amber "Unconfirmed keys" instead
  of green "Verified" (LiveChat and the messaging page), a banner names them in the room with a Review button, and the
  inspector explains it next to the key history (C9). Confirming turns their messages green at once. Messages are
  still delivered and readable: the warning is visible, not blocking. The trust store moved to `contacts.rs` so both
  pages share it.
- [x] **B5. More than one browser per account.** Today only one browser is active at a time. Large, needs a spec.
  *Done* ([spec](superpowers/specs/2026-10-28-b5-devices-design.md), [plan](superpowers/plans/2026-10-28-b5-devices.md)):
  a shared identity key (the SLH-DSA key, so safety numbers don't change), per-device HBSS chains and ML-KEM keys
  (`identity::verify_device`), envelopes sealed to every active device, and an Account page that lists, removes and
  links browsers. Linking uses a code typed on the new browser, under which the identity key is encrypted (changed from
  the spec's compared 6-digit code, which a malicious server could match by grinding keys). Removal is a server flag;
  only a recovery cuts off a stolen browser for sure.
- [x] **B6. Passkeys or a second sign-in factor.** The FAQ answer is currently "No". Large, needs a spec.
  *Done:* WebAuthn passkeys as a second factor (`hast-server::passkey`, Account page). Once an account has one, a
  correct password only returns a one-time challenge (5 minutes); a valid passkey assertion starts the session.
  Checked: ceremony type, single-use challenge, origin, relying-party id hash, user presence, signature (ES256,
  Ed25519, RS256 via `ring`), and a counter that must go up (cloned passkey). Attestation is not verified (`"none"`).
  Failed passkey attempts count towards the password lockout; removing a passkey needs the password; operators can
  run `hast-server user passkeys-off <name>` for a lost one. `HAST_RP_ID` sets the relying-party id (default: the
  request's host). The vault is still unlocked with the password: a passkey protects signing in, not the vault.

## D. Code health and accessibility

- [x] **D10. Split `livechat.rs`.** It mixes the websocket protocol, the cryptography flow and the screen layout.
  Splitting it would make the security-sensitive code easier to review. Medium refactor.
  *Done:* `pages/livechat/{mod, crypto, protocol, model, inspector}.rs`, code moved unchanged; `crypto.rs` holds
  everything that signs, seals, checks or opens.
- [x] **D11. An accessibility pass:** focus states, keyboard navigation in the sidebar and chat, and the contrast of
  the muted grey text on graphite panels. Small to medium.
  *Done:* a global `:focus-visible` outline and rings on tabs; a "Skip to content" link, a labelled sidebar that
  closes with Escape and `aria-expanded` on the menu button; tab semantics on LiveChat's tabs, a focusable message
  list and an eye button per message for the inspector; accessible names on every input and icon button; muted grey
  raised to `#8591A3` (at least 5.1:1 on every background, was 4.35:1 on raised panels) and small crimson text on
  demo badges replaced. A browser test walks the keyboard path.
