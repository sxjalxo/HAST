//! Forward secrecy for LiveChat: keys are deleted once used.
//!
//! * **Sessions**, a post-quantum double ratchet between two devices. A session's first epoch is encapsulated to the
//!   recipient device's long-term ML-KEM key (from its key chain). After that, each side's first message after hearing
//!   from the other starts a new *epoch*: it encapsulates to the other's newest *ratchet key* (a fresh ML-KEM key every
//!   message carries) and mixes that secret into the root key. Within an epoch, message keys come from a hash chain
//!   that only moves forward. So a device's state at some moment opens nothing sent to it before (those keys are gone),
//!   and once both sides have sent again, nothing after either (the next epoch needs a ratchet key made after it).
//! * **Sender keys** for the lobby: a hash chain per sender, handed to members through sessions; message `i` uses the
//!   chain's `i`-th key, and members keep only the chain after the last key they used.
//!
//! Epochs alternate (the initiator's are even), and a new one from the peer must answer this side's newest. Every
//! message of an epoch repeats the epoch's KEM ciphertext and the sender's ratchet key, so messages that arrive out of
//! order (history paged back later) still open; keys of messages skipped over are kept for a while. A failed open
//! leaves the session as it was. The KDF is SHA3-256 over a label and length-prefixed inputs.
use crate::pq::{self, GroupCt, LongTermKeys};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

/// How far a chain is moved forward at once for a message that arrived early, and how many skipped keys it keeps.
pub const MAX_SKIP: u32 = 1000;
/// Keys of skipped messages are deleted after this (ms).
pub const SKIPPED_KEEP_MS: f64 = 7.0 * 24.0 * 3600.0 * 1000.0;
/// Receiving chains kept per session: late messages of older epochs no longer open.
const KEEP_EPOCHS: usize = 4;
/// Sessions kept per peer device.
pub const KEEP_SESSIONS: usize = 3;

type Key = [u8; 32];

fn kdf(label: &str, parts: &[&[u8]]) -> Key {
    let mut h = Sha3_256::new();
    h.update(b"hast-ratchet-v1:");
    h.update(label.as_bytes());
    for p in parts {
        h.update((p.len() as u32).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

fn key_from(hex_key: &str) -> Option<Key> {
    hex::decode(hex_key).ok()?.try_into().ok()
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// (nonce, ciphertext), base64; the nonce is random, so a key used twice by mistake still leaks nothing.
fn encrypt(key: &Key, msg: &[u8], aad: &[u8]) -> (String, String) {
    let nonce = random::<24>();
    let ct = XChaCha20Poly1305::new(key.into()).encrypt(&nonce.into(), Payload { msg, aad }).expect("encrypt");
    (B64.encode(nonce), B64.encode(ct))
}

fn decrypt(key: &Key, nonce: &str, ct: &str, aad: &[u8]) -> Option<Vec<u8>> {
    let nonce: [u8; 24] = B64.decode(nonce).ok()?.try_into().ok()?;
    XChaCha20Poly1305::new(key.into()).decrypt(&nonce.into(), Payload { msg: &B64.decode(ct).ok()?, aad }).ok()
}

/// A hash chain at message `n`: each step gives that message's key and forgets it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Chain {
    ck: String,
    n: u32,
}

impl Chain {
    fn new(ck: &Key) -> Chain {
        Chain { ck: hex::encode(ck), n: 0 }
    }

    fn next(&mut self) -> (u32, Key) {
        let ck = key_from(&self.ck).unwrap_or_default();
        let n = self.n;
        self.ck = hex::encode(kdf("chain", &[&ck]));
        self.n += 1;
        (n, kdf("message", &[&ck]))
    }
}

/// A chain this device receives on, with the keys of messages it skipped over (they may still arrive).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RecvChain {
    /// the epoch (sessions; 0 for sender keys)
    e: u32,
    chain: Chain,
    /// (message number, key hex, when it was skipped in ms)
    skipped: Vec<(u32, String, f64)>,
}

impl RecvChain {
    fn new(e: u32, ck: &Key) -> RecvChain {
        RecvChain {
            e,
            chain: Chain::new(ck),
            skipped: vec![],
        }
    }

    /// Message `n`'s key, once: a skipped one, or by moving the chain forward (keeping the keys it passes).
    fn key(&mut self, n: u32, now: f64) -> Option<Key> {
        self.skipped.retain(|(_, _, at)| now - at <= SKIPPED_KEEP_MS);
        if n < self.chain.n {
            let i = self.skipped.iter().position(|(m, _, _)| *m == n)?;
            return key_from(&self.skipped.remove(i).1);
        }
        if n - self.chain.n > MAX_SKIP {
            return None;
        }
        let key = loop {
            let (m, k) = self.chain.next();
            if m == n {
                break k;
            }
            self.skipped.push((m, hex::encode(k), now));
        };
        let extra = self.skipped.len().saturating_sub(MAX_SKIP as usize);
        self.skipped.drain(..extra);
        Some(key)
    }
}

/// What a recipient needs to find a message's key in a session.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Header {
    /// session id
    pub s: String,
    /// epoch, and the message's number in it
    pub e: u32,
    pub n: u32,
    /// the epoch was encapsulated to the recipient's long-term key: a session's first
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub init: bool,
    /// the ML-KEM ciphertext that started the epoch (base64)
    pub ct: String,
    /// the sender's ratchet key (hex)
    pub pk: String,
}

/// The message key, wrapped for one recipient device.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Wrapped {
    #[serde(flatten)]
    pub h: Header,
    pub nonce: String,
    pub key: String,
}

/// A message sealed through sessions: the text under a random key, that key wrapped for each recipient device
/// (by label, see `identity::label`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// format version (tells it apart from `pq::Envelope`)
    pub r: u8,
    pub nonce: String,
    pub ct: String,
    pub to: BTreeMap<String, Wrapped>,
}

/// The random key of one sealed message, until it is wrapped for every recipient.
pub struct MessageKey(Key);

fn wrap_aad(label: &str, h: &Header) -> String {
    format!("{label}|{}|{}|{}", h.s, h.e, h.n)
}

/// One side of a session with one peer device.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    /// the peer account's identity key when the session started (a recovery replaces it: then a new session)
    pub peer: String,
    rk: String,
    /// my ratchet key (`dk` is emptied once the peer's epoch to it has opened)
    dk: String,
    pk: String,
    /// the peer's newest ratchet key, and whether my next message starts an epoch to it
    peer_pk: String,
    step_due: bool,
    /// the epoch I send in (`None` until I have sent), the ciphertext that started it, its chain
    send_e: Option<u32>,
    send_ct: String,
    send: Chain,
    init: bool,
    recv: Vec<RecvChain>,
    /// when it last carried a message each way (ms), to pick the one to send on
    pub sent_at: f64,
    pub received_at: f64,
}

impl Session {
    /// A new session to a peer device whose long-term ML-KEM key is `peer_kem` (hex).
    pub fn initiate(peer_kem: &str, peer: &str, now: f64) -> Option<Session> {
        let (ct, ss) = pq::encapsulate(peer_kem)?;
        let id = hex::encode(random::<8>());
        let (dk, pk) = pq::kem_pair();
        Some(Session {
            rk: hex::encode(kdf("init-root", &[&ss, id.as_bytes()])),
            send: Chain::new(&kdf("init-chain", &[&ss, id.as_bytes()])),
            send_e: Some(0),
            send_ct: B64.encode(ct),
            init: true,
            id,
            peer: peer.to_string(),
            dk,
            pk,
            sent_at: now,
            ..Default::default()
        })
    }

    /// The other side of a session the peer started, if `dk` is the long-term key its first epoch was sealed to.
    fn accepted(h: &Header, dk: &str, peer: &str, now: f64) -> Option<Session> {
        let ss = pq::decapsulate(dk, &B64.decode(&h.ct).ok()?)?;
        Some(Session {
            rk: hex::encode(kdf("init-root", &[&ss, h.s.as_bytes()])),
            recv: vec![RecvChain::new(0, &kdf("init-chain", &[&ss, h.s.as_bytes()]))],
            id: h.s.clone(),
            peer: peer.to_string(),
            peer_pk: h.pk.clone(),
            step_due: true,
            received_at: now,
            ..Default::default()
        })
    }

    fn next_send(&mut self, now: f64) -> Option<(Header, Key)> {
        if self.step_due {
            // a new epoch: encapsulated to the peer's newest ratchet key, announcing a fresh one of mine
            let (ct, ss) = pq::encapsulate(&self.peer_pk)?;
            let rk = key_from(&self.rk)?;
            self.rk = hex::encode(kdf("root", &[&rk, &ss]));
            self.send = Chain::new(&kdf("epoch-chain", &[&rk, &ss]));
            self.send_e = Some(self.recv.last().map_or(0, |r| r.e) + 1);
            self.send_ct = B64.encode(ct);
            self.init = false;
            (self.dk, self.pk) = pq::kem_pair();
            self.step_due = false;
        }
        let e = self.send_e?;
        let (n, key) = self.send.next();
        self.sent_at = now;
        let h = Header {
            s: self.id.clone(),
            e,
            n,
            init: self.init,
            ct: self.send_ct.clone(),
            pk: self.pk.clone(),
        };
        Some((h, key))
    }

    fn receive(&mut self, h: &Header, now: f64) -> Option<Key> {
        if h.s != self.id {
            return None;
        }
        if let Some(r) = self.recv.iter_mut().find(|r| r.e == h.e) {
            let k = r.key(h.n, now)?;
            self.received_at = now;
            return Some(k);
        }
        // a new epoch from the peer must answer my newest one, encapsulated to my ratchet key
        if h.init || Some(h.e) != self.send_e.map(|e| e + 1) || !pq::is_kem_pk(&h.pk) {
            return None;
        }
        let ss = pq::decapsulate(&self.dk, &B64.decode(&h.ct).ok()?)?;
        let rk = key_from(&self.rk)?;
        let mut chain = RecvChain::new(h.e, &kdf("epoch-chain", &[&rk, &ss]));
        let k = chain.key(h.n, now)?;
        self.rk = hex::encode(kdf("root", &[&rk, &ss]));
        self.recv.push(chain);
        let extra = self.recv.len().saturating_sub(KEEP_EPOCHS);
        self.recv.drain(..extra);
        self.dk.clear();
        self.peer_pk = h.pk.clone();
        self.step_due = true;
        self.received_at = now;
        Some(k)
    }
}

/// The session to send on to one peer device (whose identity key is `peer`): the one the peer last sent on, so both
/// sides settle on the same one, else the newest.
pub fn pick<'a>(sessions: &'a mut [Session], peer: &str) -> Option<&'a mut Session> {
    sessions
        .iter_mut()
        .filter(|s| s.peer == peer)
        .max_by(|a, b| (a.received_at, a.sent_at).partial_cmp(&(b.received_at, b.sent_at)).unwrap_or(std::cmp::Ordering::Equal))
}

/// Keep the `KEEP_SESSIONS` most recently used sessions.
pub fn prune(sessions: &mut Vec<Session>) {
    sessions.sort_by(|a, b| (b.received_at.max(b.sent_at)).total_cmp(&a.received_at.max(a.sent_at)));
    sessions.truncate(KEEP_SESSIONS);
}

/// Encrypt `text` (bound to `aad`: LiveChat uses the sender's name) under a fresh key; `add` wraps that key for each
/// recipient device.
pub fn seal(text: &str, aad: &str) -> (Envelope, MessageKey) {
    let key = random::<32>();
    let (nonce, ct) = encrypt(&key, text.as_bytes(), aad.as_bytes());
    (
        Envelope {
            r: 1,
            nonce,
            ct,
            to: BTreeMap::new(),
        },
        MessageKey(key),
    )
}

/// Wrap the message key for the device `label` through `session`, which moves on one message.
pub fn add(env: &mut Envelope, key: &MessageKey, label: &str, session: &mut Session, now: f64) -> bool {
    let Some((h, mk)) = session.next_send(now) else { return false };
    let (nonce, wrapped) = encrypt(&mk, &key.0, wrap_aad(label, &h).as_bytes());
    env.to.insert(label.to_string(), Wrapped { h, nonce, key: wrapped });
    true
}

fn open_with(env: &Envelope, label: &str, w: &Wrapped, mk: &Key, aad: &str) -> Option<String> {
    let key: Key = decrypt(mk, &w.nonce, &w.key, wrap_aad(label, &w.h).as_bytes())?.try_into().ok()?;
    String::from_utf8(decrypt(&key, &env.nonce, &env.ct, aad.as_bytes())?).ok()
}

/// Open what `env` holds for `label` in `session`; the session moves on (and forgets the key) only if it opens.
pub fn open(env: &Envelope, label: &str, session: &mut Session, aad: &str, now: f64) -> Option<String> {
    let w = env.to.get(label)?;
    let mut next = session.clone();
    let mk = next.receive(&w.h, now)?;
    let text = open_with(env, label, w, &mk, aad)?;
    *session = next;
    Some(text)
}

/// Open the first message of a session the peer device started, trying this device's current and retired long-term
/// keys; returns the new session with the text.
pub fn open_new(env: &Envelope, label: &str, keys: &LongTermKeys, peer: &str, aad: &str, now: f64) -> Option<(Session, String)> {
    let w = env.to.get(label)?;
    if !w.h.init || w.h.e != 0 || !pq::is_kem_pk(&w.h.pk) {
        return None;
    }
    std::iter::once(&keys.kem_dk).chain(keys.retired.iter().map(|(dk, _)| dk)).find_map(|dk| {
        let mut s = Session::accepted(&w.h, dk, peer, now)?;
        let mk = s.receive(&w.h, now)?;
        let text = open_with(env, label, w, &mk, aad)?;
        Some((s, text))
    })
}

/// A sender's lobby key: a chain whose `i`-th key encrypts its `i`-th message.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SendKey {
    pub id: String,
    chain: Chain,
}

impl SendKey {
    pub fn generate() -> SendKey {
        SendKey {
            id: hex::encode(random::<8>()),
            chain: Chain::new(&random::<32>()),
        }
    }

    /// What members get (sealed through sessions): the chain from here on, so they can't open earlier messages.
    pub fn distribution(&self) -> String {
        serde_json::json!({ "id": self.id, "ck": self.chain.ck, "n": self.chain.n }).to_string()
    }
}

impl RecvChain {
    /// A member's copy of a sender key, from its distribution: (key id, chain).
    pub fn from_distribution(text: &str) -> Option<(String, RecvChain)> {
        let v: serde_json::Value = serde_json::from_str(text).ok()?;
        let ck = key_from(v["ck"].as_str()?)?;
        let mut r = RecvChain::new(0, &ck);
        r.chain.n = u32::try_from(v["n"].as_u64()?).ok()?;
        Some((v["id"].as_str()?.to_string(), r))
    }
}

pub fn group_seal(k: &mut SendKey, text: &str, aad: &str) -> GroupCt {
    let (i, mk) = k.chain.next();
    GroupCt {
        i: Some(i),
        ..pq::group_seal(&mk, &k.id, text, aad)
    }
}

/// Open a lobby message with a member's copy of its sender key, which moves on only if it opens.
pub fn group_open(r: &mut RecvChain, ct: &GroupCt, aad: &str, now: f64) -> Option<String> {
    let mut next = r.clone();
    let mk = next.key(ct.i?, now)?;
    let text = pq::group_open(&mk, ct, aad)?;
    *r = next;
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: f64 = 1_000_000.0;

    /// Two devices: their long-term keys, and the identity each sees for the other.
    fn devices() -> (LongTermKeys, LongTermKeys) {
        (LongTermKeys::generate(), LongTermKeys::generate())
    }

    fn send(s: &mut Session, to: &str, text: &str) -> Envelope {
        let (mut env, key) = seal(text, "aad");
        assert!(add(&mut env, &key, to, s, NOW));
        env
    }

    fn read(s: &mut Session, me: &str, env: &Envelope) -> Option<String> {
        open(env, me, s, "aad", NOW)
    }

    fn epoch(env: &Envelope, to: &str) -> u32 {
        env.to[to].h.e
    }

    /// Alice's session to Bob after Bob accepted her first message, and Bob's.
    fn started() -> (Session, Session, LongTermKeys) {
        let (_, bob) = devices();
        let mut a = Session::initiate(&bob.kem_pk, "bob-id", NOW).unwrap();
        let first = send(&mut a, "bob", "hello");
        let (b, text) = open_new(&first, "bob", &bob, "alice-id", "aad", NOW).unwrap();
        assert_eq!(text, "hello");
        (a, b, bob)
    }

    #[test]
    fn a_conversation_steps_through_epochs() {
        let (mut a, mut b, _) = started();
        let m = send(&mut a, "bob", "still epoch 0");
        assert_eq!((epoch(&m, "bob"), read(&mut b, "bob", &m).as_deref()), (0, Some("still epoch 0")));
        let r = send(&mut b, "alice", "reply");
        assert_eq!((epoch(&r, "alice"), read(&mut a, "alice", &r).as_deref()), (1, Some("reply")));
        let r2 = send(&mut b, "alice", "and more");
        assert_eq!((epoch(&r2, "alice"), read(&mut a, "alice", &r2).as_deref()), (1, Some("and more")));
        let m = send(&mut a, "bob", "answer");
        assert_eq!((epoch(&m, "bob"), read(&mut b, "bob", &m).as_deref()), (2, Some("answer")));
        assert_eq!(read(&mut a, "bob", &m), None, "only the recipient's label opens");
    }

    #[test]
    fn late_messages_open_once_and_too_early_ones_not_at_all() {
        let (mut a, mut b, _) = started();
        let ms: Vec<_> = (0..5).map(|i| send(&mut a, "bob", &format!("m{i}"))).collect();
        for i in [3, 0, 4, 1, 2] {
            assert_eq!(read(&mut b, "bob", &ms[i]), Some(format!("m{i}")));
        }
        assert_eq!(read(&mut b, "bob", &ms[3]), None, "a key opens one message");
        assert_eq!(read(&mut b, "bob", &ms[0]), None);

        let mut far = send(&mut a, "bob", "far");
        far.to.get_mut("bob").unwrap().h.n += MAX_SKIP + 1;
        assert_eq!(read(&mut b, "bob", &far), None, "the chain is not run forward without limit");

        // a whole epoch arriving after the next one started (history paged back)
        let r1 = send(&mut b, "alice", "r1");
        let r2 = send(&mut b, "alice", "r2");
        assert_eq!(read(&mut a, "alice", &r2).as_deref(), Some("r2"));
        let m = send(&mut a, "bob", "next epoch");
        assert_eq!(read(&mut b, "bob", &m).as_deref(), Some("next epoch"));
        assert_eq!(read(&mut a, "alice", &r1).as_deref(), Some("r1"));
    }

    #[test]
    fn a_failed_open_changes_nothing() {
        let (mut a, mut b, _) = started();
        let mut m = send(&mut a, "bob", "x");
        let before = b.clone();
        m.to.get_mut("bob").unwrap().key = B64.encode([0u8; 48]);
        assert_eq!(read(&mut b, "bob", &m), None);
        assert_eq!(b, before);
        let mut r = send(&mut b, "alice", "y");
        r.ct = B64.encode([1u8; 40]);
        let before = a.clone();
        assert_eq!(read(&mut a, "alice", &r), None);
        assert_eq!(a, before, "not even a new epoch is taken");
    }

    #[test]
    fn a_stolen_state_opens_nothing_from_before() {
        let (mut a, mut b, _) = started();
        let r = send(&mut b, "alice", "reply");
        read(&mut a, "alice", &r).unwrap();
        let earlier = send(&mut a, "bob", "before the theft");
        assert_eq!(read(&mut b, "bob", &earlier).as_deref(), Some("before the theft"));
        let mut stolen = b.clone();
        assert_eq!(read(&mut stolen, "bob", &earlier), None, "its key is gone");
        // but the stolen state does read what follows in the same epoch, until the conversation moves on
        let later = send(&mut a, "bob", "after");
        assert_eq!(read(&mut stolen, "bob", &later).as_deref(), Some("after"));
    }

    #[test]
    fn a_stolen_state_stops_opening_once_both_sides_have_sent() {
        let (mut a, mut b, _) = started();
        let mut stolen = a.clone(); // Alice's state, taken by someone who also sees every message
        let r = send(&mut b, "alice", "r");
        assert_eq!(read(&mut a, "alice", &r).as_deref(), Some("r"));
        assert_eq!(read(&mut stolen, "alice", &r).as_deref(), Some("r"), "until Alice answers, the thief follows");
        let m = send(&mut a, "bob", "m"); // Alice's new ratchet key, which the thief doesn't have
        read(&mut b, "bob", &m).unwrap();
        let r2 = send(&mut b, "alice", "healed");
        assert_eq!(read(&mut a, "alice", &r2).as_deref(), Some("healed"));
        assert_eq!(read(&mut stolen, "alice", &r2), None);
    }

    #[test]
    fn sessions_started_from_both_sides_at_once_both_work() {
        let (alice, bob) = devices();
        let mut a1 = Session::initiate(&bob.kem_pk, "bob-id", NOW).unwrap();
        let mut b2 = Session::initiate(&alice.kem_pk, "alice-id", NOW).unwrap();
        let from_a = send(&mut a1, "bob", "hi from alice");
        let from_b = send(&mut b2, "alice", "hi from bob");
        let (mut a2, t) = open_new(&from_b, "alice", &alice, "bob-id", "aad", NOW).unwrap();
        assert_eq!(t, "hi from bob");
        let (mut b1, t) = open_new(&from_a, "bob", &bob, "alice-id", "aad", NOW).unwrap();
        assert_eq!(t, "hi from alice");
        let x = send(&mut a2, "bob", "on bob's session");
        assert_eq!(read(&mut b2, "bob", &x).as_deref(), Some("on bob's session"));
        let y = send(&mut b1, "alice", "on alice's session");
        assert_eq!(read(&mut a1, "alice", &y).as_deref(), Some("on alice's session"));

        let mut mine = vec![a1, a2];
        mine[0].received_at = NOW + 5.0;
        assert_eq!(pick(&mut mine, "bob-id").unwrap().id, y.to["alice"].h.s, "send on the one the peer used last");
        assert!(pick(&mut mine, "someone-else").is_none(), "not on a session with another identity");
    }

    #[test]
    fn a_session_starts_only_with_the_right_long_term_key() {
        let (_, bob) = devices();
        let mut a = Session::initiate(&bob.kem_pk, "bob-id", NOW).unwrap();
        let first = send(&mut a, "bob", "hello");
        assert!(open_new(&first, "bob", &LongTermKeys::generate(), "alice-id", "aad", NOW).is_none());
        let mut rotated = bob.clone();
        rotated.rotate_kem(NOW, 1e12);
        assert!(open_new(&first, "bob", &rotated, "alice-id", "aad", NOW).is_some(), "a retired key still opens it");
        rotated.retired.clear();
        assert!(open_new(&first, "bob", &rotated, "alice-id", "aad", NOW).is_none(), "a deleted one doesn't");
        let second = send(&mut a, "bob", "not a start");
        let (mut b, _) = open_new(&first, "bob", &bob, "alice-id", "aad", NOW).unwrap();
        assert!(
            open_new(&second, "bob", &bob, "alice-id", "aad", NOW).is_some(),
            "every message of the first epoch can start it"
        );
        assert_eq!(read(&mut b, "bob", &second).as_deref(), Some("not a start"));
    }

    #[test]
    fn sender_keys_move_forward() {
        let mut k = SendKey::generate();
        let before = group_seal(&mut k, "before the distribution", "alice");
        let (id, mut r) = RecvChain::from_distribution(&k.distribution()).unwrap();
        assert_eq!(id, k.id);
        let ms: Vec<_> = (0..4).map(|i| group_seal(&mut k, &format!("g{i}"), "alice")).collect();
        assert_eq!(group_open(&mut r, &ms[2], "alice", NOW).as_deref(), Some("g2"));
        assert_eq!(group_open(&mut r, &ms[0], "alice", NOW).as_deref(), Some("g0"));
        assert_eq!(group_open(&mut r, &ms[2], "alice", NOW), None, "once");
        assert_eq!(group_open(&mut r, &ms[1], "bob", NOW), None, "bound to the sender");
        assert_eq!(group_open(&mut r, &ms[1], "alice", NOW).as_deref(), Some("g1"), "and a failed open changed nothing");
        assert_eq!(group_open(&mut r, &before, "alice", NOW), None, "nothing from before the distribution");
        let mut old = pq::group_seal(&[7; 32], &k.id, "fixed key", "alice");
        assert_eq!(group_open(&mut r, &old, "alice", NOW), None);
        old.i = Some(9);
        assert_eq!(group_open(&mut r, &old, "alice", NOW), None);
    }

    #[test]
    fn skipped_keys_expire() {
        let (mut a, mut b, _) = started();
        let ms: Vec<_> = (0..3).map(|i| send(&mut a, "bob", &format!("m{i}"))).collect();
        read(&mut b, "bob", &ms[2]).unwrap();
        let later = NOW + SKIPPED_KEEP_MS + 1.0;
        assert_eq!(open(&ms[0], "bob", &mut b, "aad", later), None);
        assert_eq!(open(&ms[1], "bob", &mut b, "aad", later), None);
        assert_eq!(read(&mut b, "bob", &ms[1]).as_deref(), Some("m1"), "(within the week it would have opened)");
    }

    #[test]
    fn envelopes_are_told_apart_from_the_older_format() {
        let (mut a, _, _) = started();
        let env = serde_json::to_string(&send(&mut a, "bob", "x")).unwrap();
        assert!(serde_json::from_str::<pq::Envelope>(&env).is_err());
        let old = serde_json::to_string(&pq::seal("x", "a", &[("bob".into(), LongTermKeys::generate().kem_pk)])).unwrap();
        assert!(serde_json::from_str::<Envelope>(&old).is_err());
    }
}
