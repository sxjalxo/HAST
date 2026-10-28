# FAQ

## General

**What is HAST?**
A Rust toolkit and web app for hash-based signatures. It has a signed group chat (LiveChat), learning and
benchmark pages for the HBSS scheme, an encrypted messaging channel with an error-correction demo, and smaller crypto
playgrounds. See the
[README](../README.md).

**What's the difference between HAST and HBSS?**
HAST is the project. HBSS is the signature scheme it implements ([HBSS.md](HBSS.md)).

**Who is it for?**
Anyone learning or experimenting with post-quantum, hash-based signatures, and small groups that want a chat where
every message is end-to-end encrypted and verifiably signed. It isn't an enterprise messaging product.

## Security

**Are my messages encrypted?**
LiveChat messages are, end to end, with XChaCha20-Poly1305. Every two browsers share a double ratchet built on
ML-KEM-768 (FIPS 203): a private message's key is wrapped through it for each of the other person's browsers (and
your others). In the lobby each sender's chain of keys is handed out the same way to every browser whose key chain the
sender could verify. The messaging page is encrypted end to end too: each message is sealed with ML-KEM-768 to every member and signed
with SLH-DSA, and its Hamming error correction runs in the receiving browser. The server stores and relays only
ciphertext. One thing to know: people who join later (or re-key on a new device) can't read messages sent before
that. Serve HAST over HTTPS anyway ([DEPLOYMENT.md](DEPLOYMENT.md)): it protects sign-in and
everything that isn't sealed.

**Is it quantum-safe?**
The building blocks are: SHA-512 (HBSS), SLH-DSA (FIPS 205) and ML-KEM-768 (FIPS 203) are all designed to resist
quantum attacks. HBSS keys are only safe for a few signatures each, so HAST rotates them every 8; see
[HBSS.md](HBSS.md#bounded-use-why-keys-rotate) for the numbers. TLS and sessions are as quantum-safe as your TLS setup.

**Has the scheme been audited?**
HBSS hasn't: it is not standardised or reviewed by cryptographers. That's why every HBSS signature in HAST comes with
an SLH-DSA co-signature, and messages are only accepted if both verify. The HAST code as a whole hasn't been audited
either.

**Can the server read or forge my messages?**
Not with your keys: the server never sees private keys. But the operator can add a *recovery* link with new keys to
your account. Clients flag messages signed with such keys ("Signed with a key added by account recovery"), and
messages sent after it are also encrypted to the new key. Messages signed with the keys a recovery replaced are shown
as not verified from then on, since the old keys may be in someone else's hands. Treat an unexpected recovery notice
as suspicious.

**Where are my private keys?**
In your browser's `localStorage`, in `hast_vault:<username>`, encrypted with a key derived from your password
(Argon2id). The same vault holds your contacts' safety numbers and the key chains your browser has verified, so
nobody can plant a fake one by editing the browser's storage. They never leave the browser unless you use **Export keys**, which gives you the same encrypted file to
import elsewhere. Clearing site data deletes them, and this browser's history with them; then link the browser again
from another one, or re-key through a password sign-in (a recovery).

**How do I know I'm talking to the right person?**
Compare safety numbers: the inspector shows your contact's, the Your Keys panel shows yours. If they match out of
band, mark the contact verified. HAST warns if a contact's number changes later.

**Does HAST have forward secrecy?**
Yes, per message. Every two browsers run a post-quantum double ratchet: each message key is deleted once used, and
each reply mixes in a fresh ML-KEM key. Someone who copies your browser's keys can't read what you received before,
and once you and the other person have both sent again, can't read what follows either. The lobby uses sender-key
chains handed out through the ratchet. One exception: a conversation the other side has never answered is protected
by their long-term ML-KEM key (replaced weekly, deleted 7 days later) until they reply. Because old keys are gone,
history comes from your browser's own encrypted copy, not the server.

**Why does a new browser of mine show "Encrypted message" for older messages?**
They were sealed to your other browsers' keys, which have been used and deleted. Each browser keeps its own history
from the day it was linked.

**How are passwords stored?**
As Argon2id hashes. Sessions are random tokens in an `HttpOnly; SameSite=Strict` cookie; the database holds only
a hash of each token.

**What stops password guessing?**
The 5th consecutive failure locks a name for 1 second, and each further failure doubles the lock, up to 5 minutes.
An IP address gets 20 free failures before the same backoff applies. Unknown and existing names fail the same way,
so failures don't reveal which accounts exist. Signups are limited to 10 per IP per hour. Behind a reverse proxy, list
it in `HAST_TRUSTED_PROXIES` so these limits see real client addresses.

**Is there two-factor sign-in or OAuth?**
Two-factor yes: add a passkey on the **Account** page (your device's fingerprint, face or PIN, or a security key). After
that, signing in needs your password and the passkey. Passkeys need HTTPS (or `localhost`). If you lose the passkey,
the operator can remove it with `hast-server user passkeys-off <name>`. There is no OAuth.

## Using it

**I forgot my password.**
There is no email. Ask the operator to run `hast-server user reset <name>`.

**I switched browsers and now my messages say "added by account recovery".**
Expected: your new browser made a new key and the old one couldn't vouch for it. The people you talk to see your
messages as **Unconfirmed keys** (amber) until they compare your new safety number with you and mark it verified. Link
the new browser instead (Account, **Link a new browser** on the old one, then type the code), or use **Export keys** and
import the file, and no recovery happens.

**Can I use HAST on my laptop and my phone at the same time?**
Yes: link the second browser with a code from the Account page of the first. Each browser has its own keys; they share
your identity key, so your safety number doesn't change. Messages sent before a browser was linked can't be read
there. The code is the only secret: the server keeps the encrypted identity key for 10 minutes but can't open it.

**Why are someone's messages amber, "Unconfirmed keys"?**
Their keys came from an account recovery, which only the server vouches for, or their safety number changed since you
last saw it. The signatures are fine, but nothing proves those keys are theirs. Compare safety numbers with them in
person or over another channel, then press **Mark as verified** in the signature inspector; their messages turn green.

**Why does a message show "Not verified" or "Verification failed"?**
The signature inspector gives the reason: the signature doesn't verify, the key isn't in the sender's key chain, the
chain itself didn't check out, or the message was signed with keys that a later account recovery replaced. In every
case, don't trust the text. On the messaging page the same thing reads "Integrity check failed"; old messages from
before that channel was encrypted have no signature at all and are marked unverified too.

**Can I send files, edit or delete messages, or make private chats?**
Yes, in LiveChat. Pick **@name** for a private chat. Hover one of your own messages to edit or delete it; the paperclip
attaches a file (up to 256 KB). Edits, deletes and files are encrypted and signed like any message, and other people's
browsers only accept a change that comes from the message's own author. A delete removes the message from everyone's
screen, but it can't take back a copy someone already saved. The messaging page doesn't have these yet.

**Why are some modules marked Demo?**
Cipher Chat, SecureComm, Network Simulator, BlackBerry SecureChat and BB Dynamics run on sample data: they show what an
interface could look like, but nothing in them is sent, stored or verified. LiveChat, Secure Messaging, the labs and
the overview are real.

**Can I use HAST in two browsers at once?**
One at a time. Moving your key file to another browser makes it the active one; the first browser then asks for keys.

**Is there a mobile app?**
No. The web UI runs in any current browser with WebAssembly. A real BlackBerry Dynamics client would be a
separate React Native app; see [BLACKBERRY.md](BLACKBERRY.md).

**Does HAST use the BlackBerry Dynamics SDK?**
No, it mocks the SDK's shapes. The SDK needs native mobile code and a UEM server ([BLACKBERRY.md](BLACKBERRY.md)).

## Running and developing

**How do I run it?**
`docker compose up --build`, then open http://localhost:8000. For development without Docker, see the
[README](../README.md#run).

**How do I run the tests?**
`cargo test --workspace --exclude hast-web`. This covers unit tests and integration tests against a real
server. CI also runs `cargo fmt`, `clippy` (native and wasm) and a release web build.

**Port 8000 is taken.**
Set `PORT`, or change the published port in `docker-compose.yml`.

**Old messages show "Encrypted message".**
They were sealed to keys this browser doesn't hold: you joined after they were sent, or you re-keyed on this device.

**A notice says a message was "not encrypted to" someone.**
Their account has no verified encryption key yet (an account from before encryption gets one the next time its owner
opens LiveChat), or their key chain didn't verify.

**The UI loads but sign-in or chat fails with an origin error.**
The page's origin must match the server's `Host`. That happens when you use `trunk serve` on port 5173 (set
`HAST_ALLOWED_ORIGINS=http://localhost:5173`) or a proxy that rewrites `Host` (forward it unchanged).

**`cargo test` fails on Windows with "access denied" on `hast-server.exe`.**
A running server holds the file. Stop it, then rebuild.

**Can I `cargo update`?**
Yes, except for `signature`: `slh-dsa 0.1.0` breaks on newer pre-releases, so `Cargo.lock` pins
`signature 2.3.0-pre.4`.

**How do I contribute?**
Branch, make the change, and run what CI runs (`.github/workflows/ci.yml`): `cargo fmt --check`, clippy with
`-D warnings` for the native crates and for `hast-web` on `wasm32-unknown-unknown`, and the tests. Then open a
pull request. Keep `hast-core` free of I/O so it keeps running in both the browser and the server.
