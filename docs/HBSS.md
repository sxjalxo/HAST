# HBSS: the signature scheme

HBSS (Hash-Based Stateless Signatures) is the signature scheme inside HAST. It lives in `hast_core::hbss` and runs
unchanged in the browser (WASM) and on the server. It uses nothing but SHA-512, which is why it is a candidate for
post-quantum use: there is no factoring or discrete-log problem for Shor's algorithm to break.

This page explains how it works, what it costs and, just as important, where its limits are.

## Keys

| | |
|---|---|
| private key | `N = 1024` random 64-byte preimages |
| leaf `i` | `SHA-512(preimage_i)` |
| public key | the Merkle root over the 1024 leaves (64 bytes); the leaf list may travel with it |

```rust
let kp = hbss::keygen(hbss::N);          // fresh random key
let pk = kp.root_only();                  // the 64-byte form that gets published
```

Keys carry a `version` (`KEY_VERSION = 2`). Clients throw away stored keys with an older version, so a scheme
change never leaves someone signing with an incompatible key.

## Signing

1. `digest = SHA-512(message)`.
2. Derive 64 indices from the digest: index `i` is the first 32 bits of `SHA-512(digest || i)` modulo 1024.
   Duplicates are dropped, which leaves about 62 distinct indices.
3. Reveal the preimages at those indices.
4. For a root-only key, add **one Merkle multiproof** covering every revealed leaf. Siblings shared between
   paths are sent once, so the proof is about 200 hashes instead of about 600 for separate paths.

```rust
let sig = hbss::sign_with_proofs("hello", &kp);   // verifiable with the root alone
let sig = hbss::sign("hello", &kp.private_key);   // smaller, needs the full leaf list to verify
```

## Verifying

`hbss::verify(message, &sig, &pk)` recomputes the digest and the indices, checks that every revealed value is a
well-formed 64-byte preimage, hashes each one into its leaf, and then either

* looks the leaves up in the leaf list (and checks that list hashes to the root), or
* rebuilds the root from the revealed leaves and the multiproof and compares it with the public key.

A signature is accepted only if the digest matches the message, the indices are exactly the ones the digest
demands, and every leaf authenticates to the root. There is no way to pass verification without the preimages.

## Variants

| name | public key | signature | when to use |
|---|---|---|---|
| **HBSS** | root + 1024 leaves (~64 KB) | preimages only | the verifier already holds the leaf list |
| **HBSS\*** | as HBSS, generated from a seed (`star_keygen`) | as HBSS | reproducible keys for demos and tests; the seed *is* the private key |
| **HBSS\*\*** | 64-byte root | preimages + multiproof | anything published; this is what LiveChat and accounts use |

## Sizes

Counting raw 64-byte hashes (`signature_size`, `public_key_size`):

* HBSS\*\* public key: 64 bytes.
* HBSS signature: about 4 KB. HBSS\*\* signature: about 17 KB (the multiproof dominates).
* On the LiveChat wire the 64-byte values travel as base64 in JSON, so the HBSS signature is about 24 KB (35 KB as
  hex, which is still accepted). With the SLH-DSA co-signature, a LiveChat message comes to about 50 KB.

For timings on your own machine, use the benchmark tab of `/hbss-lab`. It runs HBSS next to a real
SLH-DSA-SHAKE-128f (SPHINCS+) implementation, so the comparison is measured rather than quoted.

## Bounded use: why keys rotate

Every signature reveals about 6% of the preimages. A forger who has collected the preimages from earlier signatures
can keep trying messages until one lands only on preimages they already know. A rough estimate of that work, assuming
indices behave like random draws:

| signatures with one key | preimages revealed | forgery work (classical) |
|---|---|---|
| 1 | 6% | ~2^251 |
| 4 | 22% | ~2^135 |
| **8** | **39%** | **~2^83** |
| 16 | 63% | ~2^41 |
| 32 | 87% | ~2^13 |

The test `forgery_gets_easier_as_signatures_leak` checks that this leakage really grows. A quantum search
(Grover) roughly halves those exponents. So HBSS is *not* a many-time scheme like SLH-DSA. It is safe only when keys
are retired early, and HAST is built around that:

* LiveChat rotates the key automatically once it has made 8 signatures (`ROTATE_AFTER` in
  `crates/hast-web/src/pages/livechat/mod.rs`), counting the lobby's group-key announcements; the handover itself is a
  ninth signature.
* Lower that number if your threat model includes a quantum attacker.
* Every HBSS signature in HAST is paired with an SLH-DSA co-signature (next section), so a forger has to break both.

## Co-signing with SLH-DSA

HBSS has not been reviewed by cryptographers, and no amount of code changes that. So HAST never relies on it alone:
each account also holds an SLH-DSA-SHAKE-128f key (FIPS 205, `hast_core::pq`), and everything the HBSS key signs is
signed by the SLH-DSA key too. That covers registrations, rotations and every LiveChat message. The server and every
reader require both signatures to verify. If HBSS turned out to be broken, an attacker would still have to forge a
standard SLH-DSA signature. If SLH-DSA were broken, HBSS would still stand.

SLH-DSA is a many-time scheme, so this key does not rotate; only a recovery replaces it. The cost is about 17 KB per
signature (23 KB as base64).

## Rotation and key chains

An account is a chain of keys rather than one key. Each link names an HBSS root plus the long-term keys: the
SLH-DSA public key and an ML-KEM-768 key that LiveChat messages are encrypted to.

* `identity::rotate_link(old, new_root, long_term)` signs `hast-rotate-v2:<old root>:<new root>:<slh>:<kem>` with
  the HBSS key being retired, plus the SLH-DSA key. Binding both roots stops a handover from being replayed for a
  different key. A rotation cannot change the SLH-DSA key; it normally brings a new ML-KEM key, so a stolen
  decryption key stops opening new messages, and retired ones are deleted after 90 days (forward secrecy).
* Browsers cache chains they verified and then fetch only new links (`GET /api/keys/<name>?since=<root>`), checked
  with `identity::extend_chain`.
* `identity::verify_next(prev, link)` checks one handover with nothing but the two links.
* Signup proves possession of the first HBSS key and the SLH-DSA key by signing
  `hast-register-v2:<lowercase name>:<root>:<slh>:<kem>` with both.
* Password recovery on a new device adds a *recovery* link with new keys. The old keys cannot sign it (they never
  left the old browser), so the server vouches for it and clients mark messages from such keys.
* Accounts created before co-signing have HBSS-only (`v1`) links. They still verify, and LiveChat upgrades such an
  account by sending a v2 rotation that introduces its long-term keys.

`hast_core::identity::verify_chain(name, links)` accepts a chain only if it starts with a valid registration and
every link continues from the previous root. Anyone can fetch a chain (`GET /api/keys/<name>`) and check it.

## Security assumptions

* SHA-512 is preimage-resistant and second-preimage-resistant (for HBSS), *or* SLH-DSA is unforgeable: with
  co-signing, either one holding is enough.
* The browser's random number generator is sound (`rand` with the `getrandom` JS backend in WASM).
* Each key signs only a few messages (see the table above).
* The private key stays secret. In the web client it sits in `localStorage` in a vault encrypted under a key derived
  from the password (Argon2id); while a tab is unlocked, that key is in sessionStorage. Script running on the HAST
  origin could still read it from an unlocked tab, which is why the server sends a strict Content-Security-Policy.
  Serving the UI from a trusted origin over HTTPS is part of the security model.

## Not claimed

HBSS here is a teaching and experimentation scheme with honest bounds. It has not been reviewed by
cryptographers and is not standardised. That is why HAST pairs every HBSS signature with a standard SLH-DSA
(FIPS 205) one. If you need a standard hash-based signature on its own, use SLH-DSA.
