//! Account identity: an account is a name plus a chain of keys.
//!
//! Every link names an HBSS root (rotates often) and the account's long-term keys: an SLH-DSA public key that
//! co-signs, and an ML-KEM encapsulation key that others encrypt to (see `pq`).
//!
//! * `Register`: the first link; the owner signs `hast-register-v2:<name>:<root>:<slh>:<kem>` with the new
//!   HBSS key *and* the new SLH-DSA key, proving they hold both.
//! * `Rotate`: the previous HBSS key signs `hast-rotate-v2:<old root>:<new root>:<slh>:<kem>`, co-signed by the
//!   SLH-DSA key, which stays the same across rotations. The ML-KEM key is usually replaced (forward secrecy).
//! * `Recovery`: the owner logged in with the password on a device without the keys; the *server* vouches
//!   for the new keys. It carries no signature, and clients show it as a re-key event.
//! * `Device`: the first link of another browser ("device") of the account. That browser has its own HBSS chain and
//!   ML-KEM key; it signs `hast-device-v1:<name>:<device>:<root>:<slh>:<kem>` with its new HBSS key, and the account's
//!   SLH-DSA key (the *identity key*, shared by every device) co-signs. The registration's chain is the primary device
//!   (`d1`): it anchors the identity key and is the only one a recovery touches.
//!
//! Links from before long-term keys existed (`v1`, HBSS only) still verify; a v1 head is upgraded by a v2
//! rotation that introduces the long-term keys. Anyone can check a chain with only the account name, so the
//! server cannot invent a continuation of a key chain, only (visibly) record a recovery.
use crate::hbss::{self, KeyPair, PublicKey, Signature, KEY_VERSION};
use crate::pq::{self, LongTermKeys};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkKind {
    #[default]
    Register,
    Rotate,
    Recovery,
    Device,
}

impl LinkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkKind::Register => "register",
            LinkKind::Rotate => "rotate",
            LinkKind::Recovery => "recovery",
            LinkKind::Device => "device",
        }
    }

    pub fn parse(s: &str) -> Option<LinkKind> {
        Some(match s {
            "register" => LinkKind::Register,
            "rotate" => LinkKind::Rotate,
            "recovery" => LinkKind::Recovery,
            "device" => LinkKind::Device,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainLink {
    pub kind: LinkKind,
    pub root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_root: Option<String>,
    /// HBSS signature (by the new key for a registration, by the previous key for a rotation)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    /// SLH-DSA public key (hex); `None` only on links from before long-term keys
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slh: Option<String>,
    /// ML-KEM-768 encapsulation key (hex)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kem: Option<String>,
    /// SLH-DSA co-signature (base64) over the same payload as `signature`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cosig: Option<String>,
    /// Unix seconds, set by the server (informational, not signed).
    #[serde(default)]
    pub at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainError {
    Empty,
    BadRegistration,
    /// link `i` does not continue from the previous key
    Broken(usize),
    /// link `i` is a rotation whose signatures do not verify
    BadRotation(usize),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::Empty => write!(f, "empty key chain"),
            ChainError::BadRegistration => write!(f, "registration proof does not verify"),
            ChainError::Broken(i) => write!(f, "link {i} does not continue the chain"),
            ChainError::BadRotation(i) => write!(f, "rotation {i} is not signed by the previous keys"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedChain {
    /// every root the account has used, oldest first; the last one is current
    pub roots: Vec<String>,
    /// the SLH-DSA key that co-signs for each root (`None` for roots from before long-term keys)
    pub slh: Vec<Option<String>>,
    /// the current encapsulation key, if the account has one
    pub kem: Option<String>,
    /// indices into the chain of recovery re-keys (server-vouched, no signature from the old key)
    pub recoveries: Vec<usize>,
    /// when the server recorded each link (Unix seconds; informational, not signed). Shorter than `roots` for chains
    /// cached before this was kept.
    #[serde(default)]
    pub at: Vec<u64>,
}

/// Safety number: 60 digits (12 groups of 5) derived from the account name and its SLH-DSA key. It changes only when
/// the co-signing key does (a recovery), so people can compare it once, out of band, and be warned if it changes.
pub fn fingerprint(username: &str, slh: &str) -> String {
    let digest = hbss::sha512(&format!("hast-fingerprint-v1:{}:{slh}", username.to_lowercase()));
    let bytes = hex::decode(digest).unwrap_or_default();
    bytes
        .chunks(5)
        .take(12)
        .map(|c| format!("{:05}", c.iter().fold(0u64, |a, &b| a << 8 | b as u64) % 100_000))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn is_root(s: &str) -> bool {
    s.len() == 128 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn root_key(root: &str) -> PublicKey {
    PublicKey {
        commitment_root: root.to_string(),
        commitments: vec![],
        version: KEY_VERSION,
    }
}

/// Names are case-insensitive, so the proof binds the lowercase form.
pub fn registration_payload(username: &str, root: &str, slh: &str, kem: &str) -> String {
    format!("hast-register-v2:{}:{root}:{slh}:{kem}", username.to_lowercase())
}

pub fn rotation_payload(old_root: &str, new_root: &str, slh: &str, kem: &str) -> String {
    format!("hast-rotate-v2:{old_root}:{new_root}:{slh}:{kem}")
}

/// What both signatures on a LiveChat message cover: the room, the sender-chosen id and the send time are bound to
/// the ciphertext, so a message cannot be moved to another room, re-sent under a new id or passed off as recent.
pub fn message_payload(room: &str, id: &str, sent_at: u64, body: &str) -> String {
    format!("hast-msg-v1:{room}:{id}:{sent_at}:{body}")
}

/// What the SLH-DSA signature on a messaging-channel message covers (that channel signs with the long-term key
/// only, so it never spends HBSS signatures).
pub fn messaging_payload(id: &str, sent_at: u64, body: &str) -> String {
    format!("hast-messaging-v1:{id}:{sent_at}:{body}")
}

/// The room everyone is in.
pub const LOBBY: &str = "lobby";

/// The private room of two accounts (order and case do not matter).
pub fn dm_room(a: &str, b: &str) -> String {
    let (a, b) = (a.to_lowercase(), b.to_lowercase());
    if a <= b {
        format!("dm:{a}:{b}")
    } else {
        format!("dm:{b}:{a}")
    }
}

/// The two members of a private room, or `None` for the lobby or a malformed room.
pub fn dm_members(room: &str) -> Option<(&str, &str)> {
    let (a, b) = room.strip_prefix("dm:")?.split_once(':')?;
    (a < b && !b.contains(':') && [a, b].iter().all(|n| !n.is_empty() && *n == n.to_lowercase())).then_some((a, b))
}

/// May `user` see frames of `room`?
pub fn in_room(room: &str, user: &str) -> bool {
    room == LOBBY || dm_members(room).is_some_and(|(a, b)| user.eq_ignore_ascii_case(a) || user.eq_ignore_ascii_case(b))
}

/// Message ids: 1-64 characters of `[A-Za-z0-9_-]`.
pub fn valid_message_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The primary device: the registration's chain, which anchors the identity key and takes recoveries.
pub const PRIMARY: &str = "d1";

/// `d1`, or `d` and 8 lowercase hex digits (chosen by the browser being linked).
pub fn valid_device(d: &str) -> bool {
    d == PRIMARY || (d.len() == 9 && d.starts_with('d') && d[1..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// Whom an envelope is sealed to: the account name for the primary device (as before devices existed),
/// `name#device` for the others.
pub fn label(username: &str, device: &str) -> String {
    if device == PRIMARY {
        username.to_lowercase()
    } else {
        format!("{}#{device}", username.to_lowercase())
    }
}

/// The account name in a label.
pub fn base_name(label: &str) -> &str {
    label.split('#').next().unwrap_or(label)
}

pub fn device_payload(username: &str, device: &str, root: &str, slh: &str, kem: &str) -> String {
    format!("hast-device-v1:{}:{device}:{root}:{slh}:{kem}", username.to_lowercase())
}

/// The first link of another device: signed by its new HBSS key and by the identity key in `lt`.
pub fn device_link(username: &str, device: &str, kp: &KeyPair, lt: &LongTermKeys) -> ChainLink {
    let root = kp.public_key.commitment_root.clone();
    let payload = device_payload(username, device, &root, &lt.slh_pk, &lt.kem_pk);
    ChainLink {
        kind: LinkKind::Device,
        signature: Some(hbss::sign_with_proofs(&payload, kp)),
        cosig: Some(lt.sign(&payload)),
        slh: Some(lt.slh_pk.clone()),
        kem: Some(lt.kem_pk.clone()),
        root,
        ..Default::default()
    }
}

/// A non-primary device's chain: a `Device` link co-signed by `identity_slh` (the primary chain's current SLH-DSA
/// key), then rotations. After a recovery the identity key is new, so devices linked before it no longer verify.
pub fn verify_device(username: &str, device: &str, identity_slh: &str, links: &[ChainLink]) -> Result<VerifiedChain, ChainError> {
    let first = links.first().ok_or(ChainError::Empty)?;
    let ok = first.kind == LinkKind::Device
        && device != PRIMARY
        && valid_device(device)
        && first.old_root.is_none()
        && is_root(&first.root)
        && first.slh.as_deref() == Some(identity_slh)
        && matches!(long_term(first), Ok(Some((slh, kem))) if cosigned(first, &device_payload(username, device, &first.root, slh, kem), &first.root, slh));
    if !ok {
        return Err(ChainError::BadRegistration);
    }
    let v = VerifiedChain {
        roots: vec![first.root.clone()],
        slh: vec![first.slh.clone()],
        kem: first.kem.clone(),
        recoveries: vec![],
        at: vec![first.at],
    };
    extend_device(v, &links[1..])
}

/// `extend_chain` for a non-primary device: only the primary chain takes recoveries.
pub fn extend_device(v: VerifiedChain, more: &[ChainLink]) -> Result<VerifiedChain, ChainError> {
    let v = extend_chain(v, more)?;
    match v.recoveries.first() {
        Some(&i) => Err(ChainError::Broken(i)),
        None => Ok(v),
    }
}

/// What a v1 (HBSS-only) registration signed.
pub fn legacy_registration_payload(username: &str, root: &str) -> String {
    format!("hast-register-v1:{}:{root}", username.to_lowercase())
}

/// The first link of a new account.
pub fn register_link(username: &str, kp: &KeyPair, lt: &LongTermKeys) -> ChainLink {
    let root = kp.public_key.commitment_root.clone();
    let payload = registration_payload(username, &root, &lt.slh_pk, &lt.kem_pk);
    ChainLink {
        kind: LinkKind::Register,
        signature: Some(hbss::sign_with_proofs(&payload, kp)),
        cosig: Some(lt.sign(&payload)),
        slh: Some(lt.slh_pk.clone()),
        kem: Some(lt.kem_pk.clone()),
        root,
        ..Default::default()
    }
}

/// Hand over from `old` to `new_root`; also how a v1 head gains long-term keys.
pub fn rotate_link(old: &KeyPair, new_root: &str, lt: &LongTermKeys) -> ChainLink {
    let old_root = old.public_key.commitment_root.clone();
    let payload = rotation_payload(&old_root, new_root, &lt.slh_pk, &lt.kem_pk);
    ChainLink {
        kind: LinkKind::Rotate,
        root: new_root.to_string(),
        old_root: Some(old_root),
        signature: Some(hbss::sign_with_proofs(&payload, old)),
        cosig: Some(lt.sign(&payload)),
        slh: Some(lt.slh_pk.clone()),
        kem: Some(lt.kem_pk.clone()),
        at: 0,
    }
}

/// Well-formed long-term keys, both present or both absent. Returns them when present.
fn long_term(link: &ChainLink) -> Result<Option<(&str, &str)>, ()> {
    match (&link.slh, &link.kem) {
        (None, None) => Ok(None),
        (Some(s), Some(k)) if pq::is_slh_pk(s) && pq::is_kem_pk(k) => Ok(Some((s, k))),
        _ => Err(()),
    }
}

/// Both signatures over `payload`: HBSS under `root`, SLH-DSA under `slh`.
fn cosigned(link: &ChainLink, payload: &str, root: &str, slh: &str) -> bool {
    link.signature.as_ref().is_some_and(|s| hbss::verify(payload, s, &root_key(root))) && link.cosig.as_ref().is_some_and(|c| pq::slh_verify(slh, payload, c))
}

pub fn verify_registration(username: &str, link: &ChainLink) -> bool {
    if link.kind != LinkKind::Register || link.old_root.is_some() || !is_root(&link.root) {
        return false;
    }
    match long_term(link) {
        Ok(Some((slh, kem))) => cosigned(link, &registration_payload(username, &link.root, slh, kem), &link.root, slh),
        Ok(None) => link
            .signature
            .as_ref()
            .is_some_and(|s| hbss::verify(&legacy_registration_payload(username, &link.root), s, &root_key(&link.root))),
        Err(()) => false,
    }
}

/// Is `link` a valid successor of `prev`? (Root reuse across the whole chain is checked by `verify_chain`.)
pub fn verify_next(prev: &ChainLink, link: &ChainLink) -> Result<(), ChainError> {
    if link.old_root.as_deref() != Some(prev.root.as_str()) || link.root == prev.root || !is_root(&link.root) {
        return Err(ChainError::Broken(0));
    }
    let lt = long_term(link).map_err(|_| ChainError::Broken(0))?;
    match link.kind {
        LinkKind::Register | LinkKind::Device => Err(ChainError::Broken(0)),
        LinkKind::Recovery => Ok(()),
        LinkKind::Rotate => {
            let ok = match lt {
                // v1 rotation between two HBSS-only links
                None => prev.slh.is_none() && link.signature.as_ref().is_some_and(|s| hbss::verify_rotation(&prev.root, &link.root, s)),
                // the co-signing key only changes through a recovery (or appears for the first time)
                Some((slh, kem)) => {
                    (prev.slh.is_none() || prev.slh.as_deref() == Some(slh)) && cosigned(link, &rotation_payload(&prev.root, &link.root, slh, kem), &prev.root, slh)
                }
            };
            if ok {
                Ok(())
            } else {
                Err(ChainError::BadRotation(0))
            }
        }
    }
}

pub fn verify_chain(username: &str, links: &[ChainLink]) -> Result<VerifiedChain, ChainError> {
    let first = links.first().ok_or(ChainError::Empty)?;
    if !verify_registration(username, first) {
        return Err(ChainError::BadRegistration);
    }
    let v = VerifiedChain {
        roots: vec![first.root.clone()],
        slh: vec![first.slh.clone()],
        kem: first.kem.clone(),
        recoveries: vec![],
        at: vec![first.at],
    };
    extend_chain(v, &links[1..])
}

/// Continue an already verified chain with the links that follow it (what `GET /api/keys/<name>?since=<root>`
/// returns), so clients only download and check what is new.
pub fn extend_chain(mut v: VerifiedChain, more: &[ChainLink]) -> Result<VerifiedChain, ChainError> {
    for link in more {
        let i = v.roots.len();
        // all `verify_next` needs of the previous link is in the verified state
        let prev = ChainLink {
            root: v.roots.last().cloned().ok_or(ChainError::Empty)?,
            slh: v.slh.last().cloned().flatten(),
            kem: v.kem.clone(),
            ..Default::default()
        };
        if v.roots.contains(&link.root) {
            return Err(ChainError::Broken(i));
        }
        verify_next(&prev, link).map_err(|e| match e {
            ChainError::BadRotation(_) => ChainError::BadRotation(i),
            _ => ChainError::Broken(i),
        })?;
        if link.kind == LinkKind::Recovery {
            v.recoveries.push(i);
        }
        v.roots.push(link.root.clone());
        v.slh.push(link.slh.clone());
        v.at.push(link.at);
        v.kem = link.kem.clone();
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered(name: &str) -> (KeyPair, LongTermKeys, Vec<ChainLink>) {
        let (kp, lt) = (hbss::keygen(hbss::N), LongTermKeys::generate());
        let link = register_link(name, &kp, &lt);
        (kp, lt, vec![link])
    }

    fn rotate(chain: &mut Vec<ChainLink>, old: &KeyPair, lt: &LongTermKeys) -> KeyPair {
        let next = hbss::keygen(hbss::N);
        chain.push(rotate_link(old, &next.public_key.commitment_root, lt));
        next
    }

    fn recovery(old_root: &str, lt: &LongTermKeys) -> ChainLink {
        ChainLink {
            kind: LinkKind::Recovery,
            old_root: Some(old_root.to_string()),
            root: hbss::keygen(hbss::N).public_key.commitment_root,
            slh: Some(lt.slh_pk.clone()),
            kem: Some(lt.kem_pk.clone()),
            ..Default::default()
        }
    }

    #[test]
    fn registration_is_bound_to_the_name_and_both_keys() {
        let (_, _, chain) = registered("Alice");
        assert!(verify_registration("alice", &chain[0]) && verify_registration("ALICE", &chain[0]));
        assert!(!verify_registration("bob", &chain[0]), "cannot reuse a proof for another name");
        let other = LongTermKeys::generate();
        let mut l = chain[0].clone();
        l.kem = Some(other.kem_pk.clone());
        assert!(!verify_registration("alice", &l), "nor swap the encryption key");
        let mut l = chain[0].clone();
        l.slh = Some(other.slh_pk.clone());
        assert!(!verify_registration("alice", &l), "nor the co-signing key");
        let mut l = chain[0].clone();
        l.cosig = None;
        assert!(!verify_registration("alice", &l), "the SLH-DSA proof is required");
        let mut l = chain[0].clone();
        l.kem = None;
        assert!(!verify_registration("alice", &l), "long-term keys come as a pair");
    }

    #[test]
    fn valid_chain_with_rotations_and_a_recovery() {
        let (k0, lt, mut chain) = registered("alice");
        let k1 = rotate(&mut chain, &k0, &lt);
        let lt2 = LongTermKeys::generate();
        chain.push(recovery(&k1.public_key.commitment_root, &lt2));
        let v = verify_chain("alice", &chain).unwrap();
        assert_eq!(v.roots.len(), 3);
        assert_eq!(v.roots.last(), Some(&chain[2].root));
        assert_eq!(v.recoveries, vec![2]);
        assert_eq!(v.slh, vec![Some(lt.slh_pk.clone()), Some(lt.slh_pk.clone()), Some(lt2.slh_pk.clone())]);
        assert_eq!(v.kem, Some(lt2.kem_pk), "the recovery's encryption key is current");

        // when each link was recorded travels along, for the key history (it is not signed)
        let mut timed = chain.clone();
        for (i, l) in timed.iter_mut().enumerate() {
            l.at = 1000 + i as u64;
        }
        assert_eq!(verify_chain("alice", &timed).unwrap().at, vec![1000, 1001, 1002]);
    }

    #[test]
    fn devices_are_vouched_for_by_the_identity_key() {
        let (_, lt, chain) = registered("alice");
        let mut dev = lt.clone();
        dev.rotate_kem(1.0, 1.0); // the device's own ML-KEM key, the shared identity key
        let k0 = hbss::keygen(hbss::N);
        let mut links = vec![device_link("Alice", "d0123abcd", &k0, &dev)];
        let k1 = rotate(&mut links, &k0, &dev);
        let v = verify_device("alice", "d0123abcd", &lt.slh_pk, &links).unwrap();
        assert_eq!(v.roots, vec![k0.public_key.commitment_root.clone(), k1.public_key.commitment_root.clone()]);
        assert_eq!(v.kem, Some(dev.kem_pk.clone()));
        assert!(v.recoveries.is_empty());

        let other = LongTermKeys::generate();
        assert_eq!(
            verify_device("alice", "d0123abcd", &other.slh_pk, &links),
            Err(ChainError::BadRegistration),
            "another identity (e.g. after a recovery) does not vouch for it"
        );
        let stranger = vec![device_link("alice", "d0123abcd", &k0, &other)];
        assert_eq!(
            verify_device("alice", "d0123abcd", &lt.slh_pk, &stranger),
            Err(ChainError::BadRegistration),
            "signed by another identity key"
        );
        assert!(verify_device("alice", "d99999999", &lt.slh_pk, &links).is_err(), "the link names its device");
        assert!(verify_device("bob", "d0123abcd", &lt.slh_pk, &links).is_err(), "and its account");
        assert!(
            verify_device("alice", PRIMARY, &lt.slh_pk, &links).is_err(),
            "the primary device starts with a registration"
        );
        let mut unsigned = links.clone();
        unsigned[0].signature = None;
        assert!(
            verify_device("alice", "d0123abcd", &lt.slh_pk, &unsigned).is_err(),
            "the new device's HBSS key must sign too"
        );

        let mut recovered = links.clone();
        recovered.push(recovery(&k1.public_key.commitment_root, &dev));
        assert_eq!(
            verify_device("alice", "d0123abcd", &lt.slh_pk, &recovered),
            Err(ChainError::Broken(2)),
            "only the primary chain takes recoveries"
        );

        let mut c = chain.clone();
        c.push(links[0].clone());
        assert!(verify_chain("alice", &c).is_err(), "a device link does not continue a chain");
        assert!(verify_chain("alice", &links).is_err(), "nor start one");
    }

    #[test]
    fn device_ids_and_labels() {
        assert!(valid_device("d1") && valid_device("d0123abcd"));
        assert!(!valid_device("d2") && !valid_device("D0123ABCD") && !valid_device("d0123abcz") && !valid_device(""));
        assert_eq!(label("Alice", PRIMARY), "alice");
        assert_eq!(label("Alice", "d0123abcd"), "alice#d0123abcd");
        assert_eq!(base_name("alice#d0123abcd"), "alice");
        assert_eq!(base_name("alice"), "alice");
    }

    #[test]
    fn rotations_need_both_signatures_and_keep_long_term_keys() {
        let (k0, lt, chain) = registered("alice");
        let next = hbss::keygen(hbss::N).public_key.commitment_root;

        let mut c = chain.clone();
        let mut l = rotate_link(&k0, &next, &lt);
        l.cosig = Some(LongTermKeys::generate().sign("x"));
        c.push(l);
        assert_eq!(verify_chain("alice", &c), Err(ChainError::BadRotation(1)), "bad co-signature");

        let mut c = chain.clone();
        c.push(rotate_link(&hbss::keygen(hbss::N), &next, &lt));
        assert_eq!(verify_chain("alice", &c), Err(ChainError::Broken(1)), "signed by another HBSS key (wrong old root)");

        let mut c = chain.clone();
        let mut l = rotate_link(&k0, &next, &lt);
        l.signature = Some(hbss::sign_with_proofs("other", &k0));
        c.push(l);
        assert_eq!(verify_chain("alice", &c), Err(ChainError::BadRotation(1)), "HBSS signature over something else");

        let mut c = chain.clone();
        c.push(rotate_link(&k0, &next, &LongTermKeys::generate()));
        assert_eq!(verify_chain("alice", &c), Err(ChainError::BadRotation(1)), "a rotation cannot swap the co-signing key");

        let mut c = chain;
        let mut lt2 = lt.clone();
        lt2.rotate_kem(1.0, 1.0);
        c.push(rotate_link(&k0, &next, &lt2));
        assert_eq!(verify_chain("alice", &c).unwrap().kem, Some(lt2.kem_pk), "but it may (and should) bring a new ML-KEM key");
    }

    #[test]
    fn legacy_chains_verify_and_upgrade() {
        let k0 = hbss::keygen(hbss::N);
        let r0 = k0.public_key.commitment_root.clone();
        let mut chain = vec![ChainLink {
            root: r0.clone(),
            signature: Some(hbss::sign_with_proofs(&legacy_registration_payload("alice", &r0), &k0)),
            ..Default::default()
        }];
        let k1 = hbss::keygen(hbss::N);
        let r1 = k1.public_key.commitment_root.clone();
        chain.push(ChainLink {
            kind: LinkKind::Rotate,
            root: r1.clone(),
            old_root: Some(r0),
            signature: Some(hbss::sign_rotation(&k0, &r1)),
            ..Default::default()
        });
        let v = verify_chain("alice", &chain).unwrap();
        assert_eq!((v.slh, v.kem), (vec![None, None], None));

        let lt = LongTermKeys::generate();
        rotate(&mut chain, &k1, &lt);
        let v = verify_chain("alice", &chain).unwrap();
        assert_eq!(v.kem, Some(lt.kem_pk), "a v2 rotation introduces long-term keys");

        // once upgraded, a v1 rotation is no longer accepted
        let k2 = hbss::keygen(hbss::N);
        let r3 = hbss::keygen(hbss::N).public_key.commitment_root;
        let mut c = chain.clone();
        c.push(ChainLink {
            kind: LinkKind::Rotate,
            root: r3.clone(),
            old_root: Some(chain[2].root.clone()),
            signature: Some(hbss::sign_rotation(&k2, &r3)),
            ..Default::default()
        });
        assert_eq!(verify_chain("alice", &c), Err(ChainError::BadRotation(3)));
    }

    #[test]
    fn rejects_bad_chains() {
        let (k0, lt, chain) = registered("alice");
        assert_eq!(verify_chain("alice", &[]), Err(ChainError::Empty));
        assert_eq!(verify_chain("mallory", &chain), Err(ChainError::BadRegistration), "someone else's registration");

        let mut forged = chain.clone();
        forged[0].signature = None;
        assert_eq!(verify_chain("alice", &forged), Err(ChainError::BadRegistration));

        // does not continue from the previous key
        let mut c = chain.clone();
        c.push(recovery(&hbss::keygen(hbss::N).public_key.commitment_root, &lt));
        assert_eq!(verify_chain("alice", &c), Err(ChainError::Broken(1)));

        // a second registration, a repeated key, a malformed root or long-term key
        let mut c = chain.clone();
        c.push(ChainLink {
            kind: LinkKind::Register,
            ..recovery(&k0.public_key.commitment_root, &lt)
        });
        assert_eq!(verify_chain("alice", &c), Err(ChainError::Broken(1)));
        let mut c = chain.clone();
        c.push(ChainLink {
            root: k0.public_key.commitment_root.clone(),
            ..recovery(&k0.public_key.commitment_root, &lt)
        });
        assert_eq!(verify_chain("alice", &c), Err(ChainError::Broken(1)));
        let mut c = chain.clone();
        c.push(ChainLink {
            root: "xyz".into(),
            ..recovery(&k0.public_key.commitment_root, &lt)
        });
        assert_eq!(verify_chain("alice", &c), Err(ChainError::Broken(1)));
        let mut c = chain;
        c.push(ChainLink {
            kem: Some("00".into()),
            ..recovery(&k0.public_key.commitment_root, &lt)
        });
        assert_eq!(verify_chain("alice", &c), Err(ChainError::Broken(1)));
    }

    #[test]
    fn extending_a_verified_chain_equals_verifying_it_whole() {
        let (k0, lt, mut chain) = registered("alice");
        let k1 = rotate(&mut chain, &k0, &lt);
        let start = verify_chain("alice", &chain).unwrap();
        let k2 = rotate(&mut chain, &k1, &lt);
        chain.push(recovery(&k2.public_key.commitment_root, &LongTermKeys::generate()));
        assert_eq!(extend_chain(start.clone(), &chain[2..]), verify_chain("alice", &chain));
        assert_eq!(extend_chain(start.clone(), &[]), Ok(start.clone()));
        let mut forged = chain[2..].to_vec();
        forged[0].cosig = Some(lt.sign("something else"));
        assert_eq!(extend_chain(start.clone(), &forged), Err(ChainError::BadRotation(2)));
        assert_eq!(extend_chain(start, &chain[1..]), Err(ChainError::Broken(2)), "links already known do not continue it");
    }

    #[test]
    fn chain_survives_json() {
        let (k0, lt, mut chain) = registered("alice");
        rotate(&mut chain, &k0, &lt);
        let back: Vec<ChainLink> = serde_json::from_str(&serde_json::to_string(&chain).unwrap()).unwrap();
        assert_eq!(back, chain);
        assert!(verify_chain("alice", &back).is_ok());
    }

    #[test]
    fn fingerprints_are_stable_readable_and_key_specific() {
        let (a, b) = (LongTermKeys::generate(), LongTermKeys::generate());
        let fp = fingerprint("Alice", &a.slh_pk);
        assert_eq!(fp, fingerprint("alice", &a.slh_pk), "names are case-insensitive");
        assert_eq!(fp.len(), 12 * 5 + 11);
        assert!(fp.split(' ').all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit())));
        assert_ne!(fp, fingerprint("alice", &b.slh_pk));
        assert_ne!(fp, fingerprint("bob", &a.slh_pk));
    }

    #[test]
    fn rooms() {
        assert_eq!(dm_room("Bob", "alice"), "dm:alice:bob");
        assert_eq!(dm_room("alice", "Bob"), dm_room("bob", "ALICE"));
        assert_eq!(dm_members("dm:alice:bob"), Some(("alice", "bob")));
        for bad in ["dm:bob:alice", "dm:alice:alice", "dm:alice", "dm::bob", "dm:Alice:bob", "dm:a:b:c", "lobby"] {
            assert_eq!(dm_members(bad), None, "{bad}");
        }
        assert!(in_room(LOBBY, "x") && in_room("dm:alice:bob", "Bob") && !in_room("dm:alice:bob", "carol"));
        assert!(!in_room("dm:bob:alice", "bob"), "only the canonical name is a room");
    }

    #[test]
    fn link_kind_strings() {
        for k in [LinkKind::Register, LinkKind::Rotate, LinkKind::Recovery] {
            assert_eq!(LinkKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(LinkKind::parse("other"), None);
    }
}
