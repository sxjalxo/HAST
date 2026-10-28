# HAST user guide

What each part of HAST does and how to use it. For running the server see the [README](../README.md); for
hosting it see [DEPLOYMENT.md](DEPLOYMENT.md).

## Getting around

The sidebar on the left lists every module, grouped as **Workspace** (Overview, LiveChat, Secure Messaging), **Labs**
(HBSS Lab, HBSS Explained, Quantum Playground, Cipher Lab) and **Tools** (Cipher Chat, SecureComm, Network Simulator,
BlackBerry SecureChat, BB Dynamics). The page you are on is marked in crimson. Your name and the sign-out button are at
the bottom. On a phone the sidebar opens from the menu button at the top left.

Colours always mean the same thing: **green** is a verified signature or a trusted key, **amber** needs your
attention (an unverified identity, a warning), **red** is a failed check or a destructive action, and **blue** marks
links and technical references. Crimson is only for primary buttons and what is selected, never for a security state.

## Your account

Everything in HAST needs an account.

1. Open the site and choose **Create account**.
2. Pick a username (3-32 characters: letters, digits, `_` and `-`; case is ignored) and a password of at least 10
   characters. If the operator set `HAST_SIGNUP=invite` you also need the invite code.
3. Your browser generates your keys: an HBSS signing key, an SLH-DSA co-signing key and an ML-KEM encryption key.
   It signs a registration proof with both signing keys. The server stores the public keys, never the private ones.

Things worth knowing:

* **Your keys live in this browser**, encrypted with your password. A new tab (or signing in again) shows
  **Your keys on this browser are locked**: enter your password to unlock them for that tab. Clearing site data
  deletes them.
* **Using another browser too (laptop and phone):** on a browser you're signed in on, open **Account** and press
  **Link a new browser**. Sign in on the new browser; on the "does not hold your current keys" page, enter your
  password, a name for the browser and the code, and press **Link this browser**. The code works once, for 10 minutes.
  Both browsers then send and read new messages, your safety number stays the same, and nobody sees a recovery.
  Messages from before the link stay unreadable on the new browser. **Account** lists your browsers; **Remove** one
  you no longer use. A lost or stolen browser holds your identity key, so after removing it, also create new keys
  (below) on a browser of yours to cut it off for sure.
* **Moving to another browser:** in LiveChat use **Export keys** (the file is encrypted with your password). In the
  new browser, sign in, choose **Import key file**, then unlock. No recovery is recorded: the new browser is linked as
  a browser of your account and the old one is removed. History doesn't come along (it stays in the old browser).
* **New device without a key file, or cleared browser:** sign in with your password and accept the offer to create
  new keys. This is recorded as a *recovery*. People reading your messages see "Signed with a key added by account
  recovery" and a changed safety number, because your old keys could not vouch for the new ones. Messages sent to your
  old keys can't be read on the new device, and messages you signed with the old keys now show as not verified to
  everyone (whoever has the old keys could have written them). Your other linked browsers stop working; link them
  again.
* **Forgotten password:** there is no email. Ask the operator to run `hast-server user reset <name>`.
* **Changing your password** signs out every other session.
* **Passkeys:** on the **Account** page (`/account`) you can add a passkey: your device's fingerprint, face or PIN, or a
  security key. Once you have one, signing in asks for your password and then the passkey; the password alone no
  longer gets in. You can add several and remove one with your password. Lost every passkey? The operator can remove
  them (`hast-server user passkeys-off <name>`).
* **Failed sign-ins:** after 4 in a row, the name is locked for a short time that doubles with each further failure
  (up to 5 minutes).

## LiveChat (`/chat`)

A chat where every message is end-to-end encrypted and signed twice (HBSS and SLH-DSA). The server checks the
signatures but can't read the text.

* **Conversations:** **# Everyone** is the lobby; **@name** opens a private room with that person, which nobody else
  receives. A number next to a conversation counts unread messages. On narrower screens the conversation list is
  replaced by a picker in the page header.
* Type and send. Your browser encrypts the message for the room's members whose keys it could verify (and for you),
  then signs it, before it leaves. If someone has no verified encryption key yet, a notice names them.
* Each message from someone else is labelled **Verified** (green) or **Not verified** (red, with a red outline).
  Your own messages have a crimson edge. Click any message to open the **signature inspector**: the verdict and each
  check that passed, any notice or reason, the decrypted text, the sender's **safety number**, their **key history**,
  digest, revealed preimages and the public key.
* **Key history** lists the sender's keys, newest first: when the account registered, each rotation (signed by the key
  before it) and each recovery (amber: vouched for by the server only, not by the old keys). It marks where the safety
  number changed, keys a later recovery replaced, and the key that signed the message you're looking at. Your browser
  checks the whole chain itself; the dates come from the server and aren't signed.
* **Editing and deleting:** hover one of your messages and use the pencil to edit it (the composer shows "Editing your
  message"; send to save) or the bin to delete it (you're asked to confirm). Everyone in the room sees the new text
  marked *edited*, or "Message deleted". Only you can change your messages: other browsers check that the change is
  signed by you and was sent in the same room. A delete hides the message everywhere, but can't take back a copy
  someone already saved.
* **Files:** the paperclip attaches a file of up to 256 KB, encrypted and signed like a message. Images (PNG, JPEG, GIF,
  WebP) show a preview; every file has a download button and is saved as a plain file, never opened in the page.
* **Safety numbers:** compare a contact's number with them in person or over another channel, then press **Mark as
  verified**. If it changes later (their keys were replaced), their messages carry a warning. Yours is in the
  **Your Keys** panel.
* **Unconfirmed keys:** when a contact's keys came from an account recovery (which only the server vouches for), or
  their safety number changed, their messages are amber and say **Unconfirmed keys**, and a banner at the top of the
  room names them. Press **Review**, compare the safety number with them out of band, and **Mark as verified**: their
  messages turn green.
* The panel shows **Signatures with this key: n/8**. After 8 signatures your browser rotates to a fresh HBSS key and
  a fresh encryption key, and the old keys sign the handover. It also does this at least weekly. You don't have to
  do anything; the chain is public and anyone can verify it.
* **History is kept in this browser.** Each message's key is deleted once it has been used (forward secrecy), so your
  browser keeps its own encrypted copy of what it decrypted, and that is what you see after a reload. Choose how long
  on the **Account** page (for good, 90 or 30 days). Another browser of yours has its own history, from the day it was
  linked; clearing site data deletes it. **Load older messages** fetches what arrived while you were away. Messages
  sent before you joined, or before this browser was linked, show as "Encrypted message". Messages are limited to 4000
  characters and 10 per 10 seconds.
* **Keyboard:** Tab first reaches "Skip to content". In LiveChat each message has an eye button (next to the sender's
  name) that opens the signature inspector; Escape closes the menu on small screens.
* **One LiveChat tab per browser.** Its keys move forward with every message, so a second tab says "LiveChat is open
  in another tab of this browser"; close the other one.
* Accounts created before encryption get their encryption and co-signing keys automatically when they next open
  LiveChat.

Why rotate at all? Each signature reveals part of the key; see [HBSS.md](HBSS.md#bounded-use-why-keys-rotate).

## Learning pages

* **HBSS Explained (`/hbss-explained`)**: a step-by-step walk through key generation, signing (digest → indices →
  revealed preimages → Merkle path) and verification, with a comparison against traditional signatures.
* **HBSS Lab (`/hbss-lab`)**:
  * *Benchmarks*: key generation, signing and verification times and sizes for the HBSS variants and real
    SLH-DSA-SHAKE-128f, measured in your browser.
  * *Hash lab*: SHA-256, SHA-512, SHA3-512 and BLAKE2b side by side, including the avalanche effect (flip one
    character, watch half the output bits change).
  * *Scheme comparison*: size and speed trade-offs between HBSS and other post-quantum schemes.
  * *Signing flow*: an animation of one signature being made and checked.
* **Quantum Playground (`/quantum-playground`)**:
  * *Run QKD*: a 128-photon BB84 key-distribution run. Some runs (at random) include an eavesdropper; you can spot
    them by the raised error rate on the sifted key, which is how BB84 detects interception.
  * *Send*: a message goes through an encoder, a noisy channel and a decoder in one of three modes (AES
    simulation, BlackBerry GD transport, or the Hamming error-correction demo) and is posted, sealed and signed, to the
    messaging channel.

## Overview (`/`)

The start page: a LiveChat shortcut, four figures about your own account (how many members the server has, your key
chain as your browser verified it, how many signatures your current signing key has made of its 8, and how old your
encryption key is), and a tile for every module.

## Tools

| tool | what it does |
|---|---|
| Cipher Chat (`/cipher-chat`) | a chat channel whose messages pass through your cipher pipeline |
| Cipher Lab (`/cipher-lab`) | build a pipeline from XOR, ROTATE, MASK and SUBSTITUTE steps, test it, and share it as JSON or a QR code; every step is reversible |
| Network Simulator (`/network`) | a topology view of nodes and links for experimenting with message routing; tap a node for its details |
| SecureComm (`/securecomm`) | a secure-messenger demo with a crypto strength indicator and a BlackBerry Dynamics connection panel |
| BlackBerry SecureChat (`/blackberry`) | the chat UI as it would look inside a BlackBerry Dynamics container |
| BB Dynamics (`/blackberry/settings`) | the app configuration and DLP switches of the BlackBerry mock; see [BLACKBERRY.md](BLACKBERRY.md) |

Every tool except Cipher Lab is a **demo**: it runs on sample data, and the sidebar, the overview and the page itself
say so. Nothing in a demo is sent, stored or verified.

The Cipher Lab steps are obfuscation exercises, not encryption. Don't use them to protect real data.

## Messaging (`/messaging`)

A second channel, end-to-end encrypted like LiveChat (sealed to every member with ML-KEM-768, signed with your
SLH-DSA key), that also demonstrates error correction. It needs your long-term keys, so open LiveChat once first.

* **Standard** mode sends the text as is, inside the encryption.
* **MDS (Hamming)** and **Quantum (Hamming)** modes encode each byte with extended Hamming (SECDED) and pass it
  through a simulated noisy channel (2% bit errors) in your browser, then encrypt. The receiving browser decrypts and
  corrects: each message shows how many bit errors were corrected and how many bytes were damaged beyond repair. One
  flipped bit per byte is fixed, two are detected, three or more can be miscorrected.
* A message whose signature does not check out is marked "Integrity check failed". So is a message signed with keys
  that a later account recovery replaced, and an old message from before this channel was encrypted (it has no
  signature at all).
* Messages are kept on the server for good (in its database, as ciphertext).

## Troubleshooting

| symptom | likely cause |
|---|---|
| "Signed with a key added by account recovery" | the sender re-keyed through a password sign-in on a new device. Expected, but confirm with them out of band if it matters. |
| "Encrypted message" | it was sealed before you joined or before you re-keyed on this device, so this browser has no key for it. |
| "Not encrypted to …" notice | those accounts have no verified encryption key yet; they get one when they next open LiveChat. |
| "Safety number changed" | the contact's keys were replaced (usually a recovery). Check the new number with them before trusting it. |
| "Unconfirmed keys" (amber) | the contact's keys came from a recovery or their number changed, and you haven't confirmed it yet. Compare safety numbers, then Mark as verified. |
| "Confirm with your passkey" won't finish | the passkey prompt was cancelled or timed out (press Use passkey again), or this device doesn't hold the passkey. The operator can remove lost passkeys. |
| "Duplicate of an earlier message" or "possible replay" | someone delivered an old message again. Ignore it. |
| "Your keys on this browser are locked" | a new tab or a new sign-in. Enter your password; if it was reset by the operator, use the old one or create new keys. |
| "Not verified" on a message, or "Verification failed" in the inspector | the signature, the key or the sender's key chain didn't check out, or the keys were replaced by a recovery since (the reason is shown). Don't trust the text. |
| "Integrity check failed" on the messaging page | the same, for the messaging channel; also shown on old unsigned messages. |
| Signed out unexpectedly | the session expired (7 days of inactivity by default) or the password was changed elsewhere. |
| "too many attempts" | the name or your IP is locked out for a while after failed sign-ins. Wait and retry. |
| Chat doesn't connect | the page was opened from an origin the server doesn't accept (see `HAST_ALLOWED_ORIGINS`), or a proxy isn't forwarding WebSocket upgrades. |
