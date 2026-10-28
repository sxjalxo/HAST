//! Standardised post-quantum primitives used next to HBSS:
//!
//! * SLH-DSA-SHAKE-128f (FIPS 205) co-signs everything an HBSS key signs, so an account's signatures stay
//!   sound even if HBSS (unreviewed) has a flaw. SLH-DSA is many-time, so this key never rotates.
//! * ML-KEM-768 (FIPS 203) + XChaCha20-Poly1305 seal LiveChat messages end to end: a random message key
//!   encrypts the text once and is wrapped for every recipient's encapsulation key.
//!
//! Keys travel as hex, signatures and ciphertexts as base64.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, XChaCha20Poly1305,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use slh_dsa::signature::{Keypair, Signer, Verifier};
use slh_dsa::{Shake128f, SigningKey, VerifyingKey};
use std::collections::BTreeMap;

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

/// Hex length of an SLH-DSA-SHAKE-128f public key (32 bytes).
pub const SLH_PK_HEX: usize = 64;
/// Hex length of an ML-KEM-768 encapsulation key (1184 bytes).
pub const KEM_PK_HEX: usize = 2368;

/// The account's long-term keys. The SLH-DSA key stays until a recovery; the ML-KEM key is replaced at every
/// handover (forward secrecy), and retired decryption keys are kept only for a while so recent history stays readable.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LongTermKeys {
    pub slh_sk: String,
    pub slh_pk: String,
    pub kem_dk: String,
    pub kem_pk: String,
    /// when the current ML-KEM key was made (ms since the epoch; 0 = unknown, treated as old)
    #[serde(default)]
    pub kem_since: f64,
    /// retired decryption keys with the time they were retired, newest first
    #[serde(default)]
    pub retired: Vec<(String, f64)>,
}

/// Retired decryption keys kept at most this many.
pub const MAX_RETIRED: usize = 200;

/// A fresh ML-KEM-768 key pair: (decapsulation key, encapsulation key), hex.
pub(crate) fn kem_pair() -> (String, String) {
    let (dk, ek) = MlKem768::generate(&mut rand::thread_rng());
    (hex::encode(dk.as_bytes()), hex::encode(ek.as_bytes()))
}

impl LongTermKeys {
    pub fn generate() -> LongTermKeys {
        let sk = SigningKey::<Shake128f>::new(&mut rand::thread_rng());
        let (kem_dk, kem_pk) = kem_pair();
        LongTermKeys {
            slh_pk: hex::encode(sk.verifying_key().to_bytes()),
            slh_sk: hex::encode(sk.to_bytes()),
            kem_dk,
            kem_pk,
            kem_since: 0.0,
            retired: vec![],
        }
    }

    /// New ML-KEM key; the old decryption key is retired, and retired keys older than `keep_ms` (or beyond
    /// `MAX_RETIRED`) are deleted, so messages sealed to them can no longer be opened.
    pub fn rotate_kem(&mut self, now_ms: f64, keep_ms: f64) {
        let (dk, pk) = kem_pair();
        let old = std::mem::replace(&mut self.kem_dk, dk);
        self.kem_pk = pk;
        self.kem_since = now_ms;
        self.retired.insert(0, (old, now_ms));
        self.retired.retain(|(_, at)| now_ms - at <= keep_ms);
        self.retired.truncate(MAX_RETIRED);
    }

    pub fn sign(&self, message: &str) -> String {
        let sk = SigningKey::<Shake128f>::try_from(hex::decode(&self.slh_sk).unwrap_or_default().as_slice()).expect("valid SLH-DSA key");
        B64.encode(sk.try_sign(message.as_bytes()).expect("SLH-DSA signing").to_vec())
    }
}

fn slh_pk(hex_pk: &str) -> Option<VerifyingKey<Shake128f>> {
    VerifyingKey::try_from(hex::decode(hex_pk).ok()?.as_slice()).ok()
}

fn kem_pk(hex_pk: &str) -> Option<Ek> {
    let bytes = hex::decode(hex_pk).ok()?;
    Some(Ek::from_bytes(bytes.as_slice().try_into().ok()?))
}

/// A fresh shared secret for the holder of `pk_hex`, and the ciphertext that carries it.
pub(crate) fn encapsulate(pk_hex: &str) -> Option<(Vec<u8>, [u8; 32])> {
    let (ct, ss) = kem_pk(pk_hex)?.encapsulate(&mut rand::thread_rng()).ok()?;
    Some((ct.to_vec(), ss.into()))
}

/// The shared secret in `ct`. ML-KEM never fails here: under the wrong key it gives an unrelated secret, so callers
/// confirm it by opening something encrypted under it.
pub(crate) fn decapsulate(dk_hex: &str, ct: &[u8]) -> Option<[u8; 32]> {
    let dk = Dk::from_bytes(hex::decode(dk_hex).ok()?.as_slice().try_into().ok()?);
    let ct: Ciphertext<MlKem768> = ct.try_into().ok()?;
    Some(dk.decapsulate(&ct).ok()?.into())
}

pub fn is_slh_pk(s: &str) -> bool {
    s.len() == SLH_PK_HEX && slh_pk(s).is_some()
}

pub fn is_kem_pk(s: &str) -> bool {
    s.len() == KEM_PK_HEX && kem_pk(s).is_some()
}

pub fn slh_verify(pk: &str, message: &str, sig: &str) -> bool {
    let (Some(vk), Ok(raw)) = (slh_pk(pk), B64.decode(sig)) else { return false };
    slh_dsa::Signature::<Shake128f>::try_from(raw.as_slice()).is_ok_and(|s| vk.verify(message.as_bytes(), &s).is_ok())
}

/// The message key wrapped for one recipient.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Wrapped {
    /// ML-KEM ciphertext
    pub kem: String,
    /// message key encrypted under the KEM shared secret
    pub key: String,
}

/// An end-to-end encrypted message. `aad` binds it to its context (LiveChat uses the sender's name), so a
/// ciphertext re-sent under another name fails to open.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub nonce: String,
    pub ct: String,
    /// lowercase recipient name -> wrapped key
    pub to: BTreeMap<String, Wrapped>,
}

/// Encrypt `text` for every `(name, encapsulation key)`; recipients with malformed keys are skipped.
pub fn seal(text: &str, aad: &str, recipients: &[(String, String)]) -> Envelope {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(&key.into())
        .encrypt(
            &nonce.into(),
            Payload {
                msg: text.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .expect("encrypt");
    let mut to = BTreeMap::new();
    for (name, pk) in recipients {
        let Some(ek) = kem_pk(pk) else { continue };
        let Ok((kem_ct, shared)) = ek.encapsulate(&mut rng) else { continue };
        let name = name.to_lowercase();
        // every shared secret is fresh, so a fixed nonce is safe
        let wrapped = ChaCha20Poly1305::new_from_slice(shared.as_slice())
            .expect("32-byte secret")
            .encrypt(&[0u8; 12].into(), Payload { msg: &key, aad: name.as_bytes() })
            .expect("wrap");
        to.insert(
            name,
            Wrapped {
                kem: B64.encode(kem_ct),
                key: B64.encode(wrapped),
            },
        );
    }
    Envelope {
        nonce: B64.encode(nonce),
        ct: B64.encode(ct),
        to,
    }
}

/// Decrypt as `me` with the current or a retired decryption key; `None` if the envelope was not addressed to us,
/// was sealed to a key we deleted, or does not authenticate.
pub fn open(env: &Envelope, me: &str, keys: &LongTermKeys, aad: &str) -> Option<String> {
    std::iter::once(&keys.kem_dk)
        .chain(keys.retired.iter().map(|(dk, _)| dk))
        .find_map(|dk| open_with(env, me, dk, aad))
}

fn open_with(env: &Envelope, me: &str, dk_hex: &str, aad: &str) -> Option<String> {
    let me = me.to_lowercase();
    let w = env.to.get(&me)?;
    let dk = Dk::from_bytes(hex::decode(dk_hex).ok()?.as_slice().try_into().ok()?);
    let kem_ct: Ciphertext<MlKem768> = B64.decode(&w.kem).ok()?.as_slice().try_into().ok()?;
    let shared = dk.decapsulate(&kem_ct).ok()?;
    let key = ChaCha20Poly1305::new_from_slice(shared.as_slice())
        .expect("32-byte secret")
        .decrypt(
            &[0u8; 12].into(),
            Payload {
                msg: &B64.decode(&w.key).ok()?,
                aad: me.as_bytes(),
            },
        )
        .ok()?;
    let key: [u8; 32] = key.try_into().ok()?;
    let nonce: [u8; 24] = B64.decode(&env.nonce).ok()?.try_into().ok()?;
    let text = XChaCha20Poly1305::new(&key.into())
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &B64.decode(&env.ct).ok()?,
                aad: aad.as_bytes(),
            },
        )
        .ok()?;
    String::from_utf8(text).ok()
}

pub fn random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Key for encrypting secrets at rest under a password: Argon2id (default parameters) over a random salt.
pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("argon2 parameters");
    key
}

/// A lobby message encrypted under its sender's group key (`g` names the key). The key itself reaches members once,
/// sealed in an `Envelope`, so a message costs the same however many members there are.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GroupCt {
    pub g: String,
    pub n: String,
    pub c: String,
    /// the message's place in its sender-key chain (`ratchet::group_seal`); absent for a fixed group key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i: Option<u32>,
}

pub fn group_seal(key: &[u8; 32], key_id: &str, text: &str, aad: &str) -> GroupCt {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(
            &nonce.into(),
            Payload {
                msg: text.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .expect("encrypt");
    GroupCt {
        g: key_id.to_string(),
        n: B64.encode(nonce),
        c: B64.encode(ct),
        i: None,
    }
}

pub fn group_open(key: &[u8; 32], ct: &GroupCt, aad: &str) -> Option<String> {
    let nonce: [u8; 24] = B64.decode(&ct.n).ok()?.try_into().ok()?;
    let text = XChaCha20Poly1305::new(key.into())
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &B64.decode(&ct.c).ok()?,
                aad: aad.as_bytes(),
            },
        )
        .ok()?;
    String::from_utf8(text).ok()
}

/// A fresh group key and its id (hex).
pub fn new_group_key() -> ([u8; 32], String) {
    let mut key = [0u8; 32];
    let mut id = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut id);
    (key, hex::encode(id))
}

/// Symmetric helpers for local "container" storage (the BlackBerry mock): random nonce || ciphertext, base64.
pub fn encrypt_local(key: &[u8; 32], text: &str) -> String {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(key.into()).encrypt(&nonce.into(), text.as_bytes()).expect("encrypt");
    B64.encode([nonce.as_slice(), &ct].concat())
}

pub fn decrypt_local(key: &[u8; 32], blob: &str) -> Option<String> {
    let raw = B64.decode(blob).ok()?;
    let (nonce, ct) = raw.split_at_checked(24)?;
    let nonce: [u8; 24] = nonce.try_into().ok()?;
    String::from_utf8(XChaCha20Poly1305::new(key.into()).decrypt(&nonce.into(), ct).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slh_signs_and_rejects_tampering() {
        let k = LongTermKeys::generate();
        assert!(is_slh_pk(&k.slh_pk) && is_kem_pk(&k.kem_pk));
        let sig = k.sign("hello");
        assert!(slh_verify(&k.slh_pk, "hello", &sig));
        assert!(!slh_verify(&k.slh_pk, "hellO", &sig));
        assert!(!slh_verify(&LongTermKeys::generate().slh_pk, "hello", &sig), "other key");
        assert!(!slh_verify(&k.slh_pk, "hello", "not base64!"));
        assert!(!is_slh_pk("00") && !is_kem_pk(&"0".repeat(10)));
    }

    #[test]
    fn sealed_messages_open_only_for_recipients_and_the_right_context() {
        let (a, b, eve) = (LongTermKeys::generate(), LongTermKeys::generate(), LongTermKeys::generate());
        let env = seal(
            "secret",
            "alice",
            &[("Alice".into(), a.kem_pk.clone()), ("bob".into(), b.kem_pk.clone()), ("x".into(), "bad".into())],
        );
        assert_eq!(env.to.len(), 2, "malformed recipient keys are skipped");
        assert_eq!(open(&env, "ALICE", &a, "alice").as_deref(), Some("secret"));
        assert_eq!(open(&env, "bob", &b, "alice").as_deref(), Some("secret"));
        assert_eq!(open(&env, "eve", &eve, "alice"), None, "not a recipient");
        assert_eq!(open(&env, "bob", &eve, "alice"), None, "wrong private key");
        assert_eq!(open(&env, "bob", &b, "mallory"), None, "re-sent under another sender");
        let mut swapped = env.clone();
        swapped.to.insert("bob".into(), env.to["alice"].clone());
        assert_eq!(open(&swapped, "bob", &b, "alice"), None, "wrapped keys are bound to their recipient");
        assert!(!serde_json::to_string(&env).unwrap().contains("secret"));
    }

    #[test]
    fn password_keys_depend_on_password_and_salt() {
        let k = derive_key("pw", b"0123456789abcdef");
        assert_eq!(k, derive_key("pw", b"0123456789abcdef"));
        assert_ne!(k, derive_key("pw2", b"0123456789abcdef"));
        assert_ne!(k, derive_key("pw", b"fedcba9876543210"));
    }

    #[test]
    fn retired_kem_keys_open_recent_messages_until_deleted() {
        let mut k = LongTermKeys::generate();
        let old = seal("before rotation", "a", &[("me".into(), k.kem_pk.clone())]);
        k.rotate_kem(1_000.0, 500.0);
        let new = seal("after rotation", "a", &[("me".into(), k.kem_pk.clone())]);
        assert_eq!(open(&old, "me", &k, "a").as_deref(), Some("before rotation"), "retired key still opens it");
        assert_eq!(open(&new, "me", &k, "a").as_deref(), Some("after rotation"));
        k.rotate_kem(1_400.0, 500.0);
        assert_eq!(k.retired.len(), 2);
        k.rotate_kem(2_000.0, 500.0);
        assert_eq!(k.retired.len(), 1, "keys retired more than keep_ms ago are deleted");
        assert_eq!(open(&old, "me", &k, "a"), None, "forward secrecy: deleted keys cannot open old messages");
        for i in 0..(MAX_RETIRED + 5) {
            k.rotate_kem(2_000.0 + i as f64, 1e9);
        }
        assert_eq!(k.retired.len(), MAX_RETIRED);
    }

    #[test]
    fn group_messages_open_with_the_key_and_context_only() {
        let (key, id) = new_group_key();
        let ct = group_seal(&key, &id, "to everyone", "alice");
        assert_eq!(ct.g, id);
        assert_eq!(group_open(&key, &ct, "alice").as_deref(), Some("to everyone"));
        assert_eq!(group_open(&key, &ct, "mallory"), None, "bound to the sender");
        assert_eq!(group_open(&new_group_key().0, &ct, "alice"), None);
        assert!(!serde_json::to_string(&ct).unwrap().contains("everyone"));
    }

    #[test]
    fn local_encryption_round_trips_and_authenticates() {
        let key = [7u8; 32];
        let blob = encrypt_local(&key, "container data");
        assert_eq!(decrypt_local(&key, &blob).as_deref(), Some("container data"));
        assert_eq!(decrypt_local(&[8u8; 32], &blob), None);
        assert_ne!(encrypt_local(&key, "x"), encrypt_local(&key, "x"), "random nonce");
    }
}
