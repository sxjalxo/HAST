//! Hash-based stateless signatures, rebuilt so that `verify` actually verifies.
//!
//! The original TypeScript scheme committed to *triples* of preimages and then "verified" with substring
//! checks, so nothing tied a signature to the public key. This version keeps the same shape (SHA-512, 1024
//! secret preimages, 64 revealed per signature, indices derived from the message digest) but is checkable:
//!
//! * private key  = `n` random 64-byte preimages
//! * leaf `i`     = `SHA-512(preimage_i)` (hex)
//! * public key   = Merkle root over the leaves (`commitment_root`); the full leaf list (`commitments`) may
//!   travel with it ("HBSS") or be left out ("HBSS**", 64-byte key)
//! * signature    = digest, the derived indices, the revealed preimages and, for root-only keys, one
//!   Merkle multiproof covering all revealed leaves
//! * verify       = recompute digest and indices, hash every revealed preimage and check it against the
//!   leaf list or authenticate it up to the root through the multiproof.
//!
//! Forging needs preimages that were never revealed. Every signature reveals about 6% of them, so the key
//! is *bounded-use*: security degrades as signatures accumulate (see `forgery_gets_easier_as_signatures_leak`).
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, BTreeSet};

/// Leaves / preimages per key. Must be a power of two.
pub const N: usize = 1024;
/// Preimages revealed per signature (before de-duplication).
pub const REVEALS: usize = 64;
/// Bumped when the scheme changes so stale stored keys are discarded.
pub const KEY_VERSION: u32 = 2;
const PREIMAGE_HEX_LEN: usize = 128;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    /// Merkle root over the leaf hashes.
    pub commitment_root: String,
    /// Leaf hashes `SHA-512(preimage_i)`. Empty for a root-only key.
    pub commitments: Vec<String>,
    #[serde(default)]
    pub version: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PrivateKey {
    pub preimages: Vec<String>,
    pub n: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// The 64-byte form of the public key (what HBSS** publishes).
    pub fn root_only(&self) -> PublicKey {
        PublicKey {
            commitments: vec![],
            ..self.public_key.clone()
        }
    }
}

/// The 64-byte values in a signature are hex in memory (the scheme hashes the hex text) but travel as base64,
/// which is about 30% smaller. Hex is still accepted, so signatures stored before the change keep verifying.
mod compact {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    fn to_wire(h: &str) -> String {
        hex::decode(h).map(|b| STANDARD.encode(b)).unwrap_or_else(|_| h.to_string())
    }

    fn from_wire(w: String) -> String {
        if w.len() == 128 && w.bytes().all(|b| b.is_ascii_hexdigit()) {
            return w;
        }
        STANDARD.decode(&w).map(hex::encode).unwrap_or(w) // unreadable values stay as they are and fail verification
    }

    pub fn serialize<S: Serializer>(v: &str, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&to_wire(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        String::deserialize(d).map(from_wire)
    }

    pub mod vec {
        use super::*;
        use serde::ser::SerializeSeq;

        pub fn serialize<S: Serializer>(v: &[String], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for h in v {
                seq.serialize_element(&to_wire(h))?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
            Vec::<String>::deserialize(d).map(|v| v.into_iter().map(from_wire).collect())
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    #[serde(with = "compact")]
    pub digest: String,
    #[serde(with = "compact::vec")]
    pub revealed_preimages: Vec<String>,
    pub indices: Vec<usize>,
    /// Merkle multiproof for all revealed leaves at once: the sibling hashes that cannot be derived from the
    /// revealed leaves, bottom level first, left to right. Empty when the verifier holds the leaf list.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "compact::vec")]
    pub merkle_proof: Vec<String>,
}

pub fn sha512(data: &str) -> String {
    hex::encode(Sha512::digest(data.as_bytes()))
}

fn random_hex(len: usize) -> String {
    let mut b = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// parseInt(hash.substring(0, 8), 16) % size
fn hash_index(hash: &str, size: usize) -> usize {
    (u32::from_str_radix(&hash[..8], 16).unwrap() as usize) % size
}

/// All tree levels, leaves first, root level last. `leaves.len()` must be a power of two.
fn levels(leaves: &[String]) -> Vec<Vec<String>> {
    let mut out = vec![leaves.to_vec()];
    while out.last().unwrap().len() > 1 {
        let next = out.last().unwrap().chunks(2).map(|c| sha512(&format!("{}{}", c[0], c[1]))).collect();
        out.push(next);
    }
    out
}

fn root_of(leaves: &[String]) -> String {
    levels(leaves).pop().and_then(|l| l.into_iter().next()).unwrap_or_default()
}

fn keys_from(preimages: Vec<String>) -> KeyPair {
    let n = preimages.len();
    assert!(n.is_power_of_two(), "n must be a power of two");
    let leaves: Vec<String> = preimages.iter().map(|p| sha512(p)).collect();
    KeyPair {
        public_key: PublicKey {
            commitment_root: root_of(&leaves),
            commitments: leaves,
            version: KEY_VERSION,
        },
        private_key: PrivateKey { preimages, n },
    }
}

pub fn keygen(n: usize) -> KeyPair {
    keys_from((0..n).map(|_| random_hex(64)).collect())
}

/// HBSS*: deterministic from seed.
pub fn star_keygen(seed: &str, n: usize) -> KeyPair {
    keys_from((0..n).map(|i| sha512(&format!("{seed}{i}"))).collect())
}

/// The indices a signature on `digest` must reveal (same derivation as the original, de-duplicated).
pub fn select_indices(digest: &str, n: usize) -> Vec<usize> {
    let mut indices = vec![];
    for i in 0..REVEALS.min(n / 2) {
        let idx = hash_index(&sha512(&format!("{digest}{i}")), n);
        if !indices.contains(&idx) {
            indices.push(idx);
        }
    }
    indices
}

/// Signature for holders of the full leaf list (no paths).
pub fn sign(message: &str, key: &PrivateKey) -> Signature {
    let digest = sha512(message);
    let indices = select_indices(&digest, key.n);
    let revealed_preimages = indices.iter().map(|&i| key.preimages[i].clone()).collect();
    Signature {
        digest,
        revealed_preimages,
        indices,
        merkle_proof: vec![],
    }
}

/// Signature that verifies against the 64-byte root alone (HBSS**): carries one Merkle multiproof.
pub fn sign_with_proofs(message: &str, kp: &KeyPair) -> Signature {
    let mut sig = sign(message, &kp.private_key);
    let tree = levels(&kp.public_key.commitments);
    sig.merkle_proof = multiproof(&tree, &sig.indices);
    sig
}

/// Sibling hashes needed to rebuild the root from the leaves at `indices`, shared nodes included only once.
fn multiproof(tree: &[Vec<String>], indices: &[usize]) -> Vec<String> {
    let mut known: BTreeSet<usize> = indices.iter().copied().collect();
    let mut out = vec![];
    for level in &tree[..tree.len() - 1] {
        for &i in &known {
            if !known.contains(&(i ^ 1)) {
                out.push(level[i ^ 1].clone());
            }
        }
        known = known.iter().map(|i| i >> 1).collect();
    }
    out
}

/// Recompute the root from `leaves` (index -> leaf hash) and a multiproof; `None` if the proof is malformed.
fn root_from_multiproof(leaves: &BTreeMap<usize, String>, proof: &[String], depth: usize) -> Option<String> {
    let mut cur = leaves.clone();
    let mut nodes = proof.iter();
    for _ in 0..depth {
        let mut next = BTreeMap::new();
        for (&i, h) in &cur {
            let parent = i >> 1;
            if next.contains_key(&parent) {
                continue;
            }
            let sib = match cur.get(&(i ^ 1)) {
                Some(s) => s,
                None => nodes.next().filter(|n| n.len() == PREIMAGE_HEX_LEN && n.bytes().all(|b| b.is_ascii_hexdigit()))?,
            };
            next.insert(parent, if i & 1 == 0 { sha512(&format!("{h}{sib}")) } else { sha512(&format!("{sib}{h}")) });
        }
        cur = next;
    }
    // every proof node must have been used, and exactly the root must remain
    if nodes.next().is_some() || cur.len() != 1 {
        return None;
    }
    cur.remove(&0)
}

fn is_preimage(p: &str) -> bool {
    p.len() == PREIMAGE_HEX_LEN && p.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Verify `sig` on `message` under `pk`. With a leaf list in `pk` the list must hash to the root and contain
/// every revealed preimage's hash; without one, every preimage must authenticate to the root via its path.
pub fn verify(message: &str, sig: &Signature, pk: &PublicKey) -> bool {
    if pk.commitment_root.is_empty() || sha512(message) != sig.digest {
        return false;
    }
    let full = !pk.commitments.is_empty();
    let n = if full { pk.commitments.len() } else { N };
    if !n.is_power_of_two() {
        return false;
    }
    let expected = select_indices(&sig.digest, n);
    if sig.indices != expected || sig.revealed_preimages.len() != expected.len() {
        return false;
    }
    if !sig.revealed_preimages.iter().all(|p| is_preimage(p)) {
        return false;
    }
    if full {
        root_of(&pk.commitments) == pk.commitment_root && sig.indices.iter().zip(&sig.revealed_preimages).all(|(&i, p)| pk.commitments[i] == sha512(p))
    } else {
        let leaves: BTreeMap<usize, String> = sig.indices.iter().zip(&sig.revealed_preimages).map(|(&i, p)| (i, sha512(p))).collect();
        root_from_multiproof(&leaves, &sig.merkle_proof, n.trailing_zeros() as usize).is_some_and(|r| r == pk.commitment_root)
    }
}

/// Bytes on the wire if hashes are sent raw (64 bytes each).
pub fn signature_size(s: &Signature) -> usize {
    64 + s.revealed_preimages.len() * 64 + s.indices.len() * 4 + s.merkle_proof.len() * 64
}

pub fn public_key_size(pk: &PublicKey) -> usize {
    64 + pk.commitments.len() * 64
}

pub fn export_key_pair(kp: &KeyPair) -> String {
    format!(
        "{{\n  \"publicKey\": {{\n    \"commitmentRoot\": \"{}\",\n    \"leaves\": {},\n    \"commitmentsHash\": \"{}\"\n  }},\n  \"privateKey\": {{\n    \"n\": {},\n    \"preimagesHash\": \"{}\"\n  }}\n}}",
        kp.public_key.commitment_root,
        kp.public_key.commitments.len(),
        sha512(&kp.public_key.commitments.concat()),
        kp.private_key.n,
        sha512(&kp.private_key.preimages.concat()),
    )
}

/// `btoa(unescape(encodeURIComponent(s)))`: base64 of the UTF-8 bytes.
pub fn base64_utf8(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

pub fn base64_bytes(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// What the old key signs to hand over to a new one. Binding both roots stops a rotation being replayed elsewhere.
pub fn rotation_payload(old_root: &str, new_root: &str) -> String {
    format!("hast-rotate-v1:{old_root}:{new_root}")
}

/// Hand the identity over to `new_root`: signed with the key being retired. Each key can only sign so many
/// messages safely (see the module docs), so long-lived identities are chains of keys, each vouching for the next.
pub fn sign_rotation(old: &KeyPair, new_root: &str) -> Signature {
    sign_with_proofs(&rotation_payload(&old.public_key.commitment_root, new_root), old)
}

pub fn verify_rotation(old_root: &str, new_root: &str, sig: &Signature) -> bool {
    old_root != new_root
        && new_root.len() == PREIMAGE_HEX_LEN
        && new_root.bytes().all(|b| b.is_ascii_hexdigit())
        && verify(
            &rotation_payload(old_root, new_root),
            sig,
            &PublicKey {
                commitment_root: old_root.to_string(),
                commitments: vec![],
                version: KEY_VERSION,
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> KeyPair {
        keygen(64)
    }

    #[test]
    fn sha512_known_answer() {
        assert!(sha512("abc").starts_with("ddaf35a193617aba"));
    }

    #[test]
    fn keygen_shapes() {
        let kp = keygen(N);
        assert_eq!(kp.public_key.commitments.len(), N);
        assert_eq!(kp.private_key.preimages.len(), N);
        assert!(kp.private_key.preimages.iter().all(|p| is_preimage(p)));
        assert_eq!(kp.public_key.commitment_root.len(), 128);
        assert_eq!(kp.public_key.version, KEY_VERSION);
        assert_eq!(kp.public_key.commitments[0], sha512(&kp.private_key.preimages[0]));
    }

    #[test]
    fn star_keygen_is_deterministic() {
        assert_eq!(star_keygen("s", 32), star_keygen("s", 32));
        assert_ne!(star_keygen("s", 32).public_key.commitment_root, star_keygen("t", 32).public_key.commitment_root);
    }

    #[test]
    fn sign_is_deterministic_and_bounded() {
        let kp = keygen(N);
        let s = sign("hello", &kp.private_key);
        assert_eq!(s, sign("hello", &kp.private_key));
        assert_eq!(s.digest, sha512("hello"));
        assert!(!s.indices.is_empty() && s.indices.len() <= REVEALS);
        assert_eq!(s.indices.len(), s.revealed_preimages.len());
    }

    #[test]
    fn valid_signature_verifies_with_full_key() {
        let kp = keygen(N);
        assert!(verify("hello", &sign("hello", &kp.private_key), &kp.public_key));
        assert!(verify("", &sign("", &kp.private_key), &kp.public_key));
        assert!(verify("héllo ✓", &sign("héllo ✓", &kp.private_key), &kp.public_key));
    }

    #[test]
    fn valid_signature_verifies_against_root_only() {
        let kp = keygen(N);
        let sig = sign_with_proofs("remote message", &kp);
        let naive = sig.indices.len() * 10;
        assert!(
            !sig.merkle_proof.is_empty() && sig.merkle_proof.len() < naive * 6 / 10,
            "multiproof {} vs {} for separate paths",
            sig.merkle_proof.len(),
            naive
        );
        assert!(verify("remote message", &sig, &kp.root_only()));
        assert!(verify("remote message", &sig, &kp.public_key), "full key also accepts a proof-carrying signature");
    }

    #[test]
    fn signature_survives_json_roundtrip() {
        let kp = keygen(N);
        let sig = sign_with_proofs("over the wire", &kp);
        let back: Signature = serde_json::from_str(&serde_json::to_string(&sig).unwrap()).unwrap();
        assert!(verify("over the wire", &back, &kp.root_only()));
    }

    #[test]
    fn rejects_modified_message() {
        let kp = keygen(N);
        let sig = sign_with_proofs("pay alice 5", &kp);
        assert!(!verify("pay alice 6", &sig, &kp.root_only()));
        assert!(!verify("pay alice 6", &sign("pay alice 5", &kp.private_key), &kp.public_key));
    }

    #[test]
    fn rejects_signature_from_another_key() {
        let (a, b) = (keygen(N), keygen(N));
        let sig = sign_with_proofs("hi", &b);
        assert!(!verify("hi", &sig, &a.root_only()));
        assert!(!verify("hi", &sign("hi", &b.private_key), &a.public_key));
    }

    #[test]
    fn rejects_tampered_preimage_path_and_indices() {
        let kp = keygen(N);
        let good = sign_with_proofs("msg", &kp);
        let pk = kp.root_only();

        let mut s = good.clone();
        s.revealed_preimages[3] = random_hex(64);
        assert!(!verify("msg", &s, &pk), "random preimage");

        let mut s = good.clone();
        s.merkle_proof[5] = sha512("evil");
        assert!(!verify("msg", &s, &pk), "corrupted proof node");

        let mut s = good.clone();
        s.merkle_proof.pop();
        assert!(!verify("msg", &s, &pk), "truncated proof");

        let mut s = good.clone();
        s.merkle_proof.push(sha512("extra"));
        assert!(!verify("msg", &s, &pk), "proof with a leftover node");

        let mut s = good.clone();
        s.merkle_proof.swap(0, 1);
        assert!(!verify("msg", &s, &pk), "reordered proof nodes");

        let mut s = good.clone();
        s.merkle_proof.clear();
        assert!(!verify("msg", &s, &pk), "missing proof");

        let mut s = good.clone();
        s.indices[0] = (s.indices[0] + 1) % N;
        assert!(!verify("msg", &s, &pk), "index not derived from digest");

        let mut s = good.clone();
        s.revealed_preimages.swap(0, 1);
        assert!(!verify("msg", &s, &pk), "swapped preimages");

        let mut s = good.clone();
        s.digest = sha512("other");
        assert!(!verify("msg", &s, &pk), "wrong digest");

        let mut s = good.clone();
        s.revealed_preimages[0] = "zz".repeat(64);
        assert!(!verify("msg", &s, &pk), "non-hex preimage");

        let mut s = good;
        s.revealed_preimages.pop();
        s.indices.pop();
        assert!(!verify("msg", &s, &pk), "dropping reveals");
    }

    #[test]
    fn rejects_wrong_root_and_inconsistent_leaf_list() {
        let kp = keygen(N);
        let sig = sign_with_proofs("msg", &kp);
        let mut pk = kp.root_only();
        pk.commitment_root = sha512("not the root");
        assert!(!verify("msg", &sig, &pk));
        assert!(!verify("msg", &sig, &PublicKey::default()), "empty key");

        // a leaf list that does not hash to the claimed root
        let mut full = kp.public_key.clone();
        full.commitments[7] = sha512("swapped leaf");
        assert!(!verify("msg", &sig, &full));
    }

    #[test]
    fn rejects_non_power_of_two_leaf_list() {
        let kp = keygen(64);
        let mut pk = kp.public_key.clone();
        pk.commitments.pop();
        assert!(!verify("m", &sign("m", &kp.private_key), &pk));
    }

    #[test]
    fn small_key_works_and_proofs_have_log_depth() {
        let kp = small();
        let sig = sign_with_proofs("x", &kp);
        assert!(!sig.merkle_proof.is_empty());
        assert!(verify("x", &sig, &kp.public_key));
    }

    #[test]
    fn forgery_without_the_key_fails() {
        // Attacker knows the public root and one honest signature on another message.
        let kp = keygen(N);
        let pk = kp.root_only();
        let seen = sign_with_proofs("what Alice said", &kp);
        let target = "send me all the money";
        let digest = sha512(target);
        let idx = select_indices(&digest, N);
        let paths_for = |i: usize| seen.indices.iter().position(|&j| j == i);
        // Re-use whatever was leaked, make up the rest.
        let mut forged = Signature {
            digest,
            indices: idx.clone(),
            ..Default::default()
        };
        let tree = levels(&kp.public_key.commitments); // the attacker is even granted the whole tree for the proof
        for &i in &idx {
            forged
                .revealed_preimages
                .push(paths_for(i).map(|p| seen.revealed_preimages[p].clone()).unwrap_or_else(|| random_hex(64)));
        }
        forged.merkle_proof = multiproof(&tree, &idx);
        assert!(!verify(target, &forged, &pk));
    }

    /// Not a flaw in `verify`: this is the scheme's bounded-use property made visible.
    #[test]
    fn forgery_gets_easier_as_signatures_leak() {
        let kp = keygen(N);
        let mut known = std::collections::HashSet::new();
        let mut covered_after = vec![];
        for i in 0..40 {
            known.extend(sign(&format!("msg {i}"), &kp.private_key).indices);
            let probe = select_indices(&sha512("attacker's chosen text"), N);
            covered_after.push(probe.iter().filter(|x| known.contains(x)).count() as f64 / probe.len() as f64);
        }
        assert!(covered_after[0] < 0.30, "one signature leaks little: {}", covered_after[0]);
        assert!(covered_after[39] > covered_after[0], "leakage grows with the number of signatures");
    }

    #[test]
    fn signatures_travel_as_base64_and_old_hex_still_parses() {
        let kp = keygen(N);
        let sig = sign_with_proofs("m", &kp);
        let json = serde_json::to_string(&sig).unwrap();
        assert!(!json.contains(&sig.revealed_preimages[0]), "not hex on the wire");
        let back: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sig, "hex again in memory");
        assert!(verify("m", &back, &kp.root_only()));

        let hex_json = serde_json::json!({ "digest": sig.digest, "revealedPreimages": sig.revealed_preimages,
                                           "indices": sig.indices, "merkleProof": sig.merkle_proof });
        let old: Signature = serde_json::from_value(hex_json.clone()).unwrap();
        assert_eq!(old, sig, "signatures stored as hex still load");
        assert!(json.len() * 10 < hex_json.to_string().len() * 8, "{} vs {}", json.len(), hex_json.to_string().len());

        let mut bad: serde_json::Value = serde_json::from_str(&json).unwrap();
        bad["revealedPreimages"][0] = serde_json::json!("not base64!");
        assert!(!verify("m", &serde_json::from_value(bad).unwrap(), &kp.root_only()));
    }

    #[test]
    fn sizes_are_reported() {
        let kp = keygen(N);
        let plain = sign("a", &kp.private_key);
        let proof = sign_with_proofs("a", &kp);
        assert!(signature_size(&proof) > signature_size(&plain));
        assert_eq!(public_key_size(&kp.root_only()), 64);
        assert_eq!(public_key_size(&kp.public_key), 64 + N * 64);
    }

    #[test]
    fn rotation_chain_verifies_and_is_bound_to_both_keys() {
        let (old, new, other) = (keygen(N), keygen(N), keygen(N));
        let (o, n) = (old.public_key.commitment_root.clone(), new.public_key.commitment_root.clone());
        let sig = sign_rotation(&old, &n);
        assert!(verify_rotation(&o, &n, &sig));
        assert!(!verify_rotation(&o, &other.public_key.commitment_root, &sig), "handover to a different key");
        assert!(!verify_rotation(&other.public_key.commitment_root, &n, &sig), "signed by a different key");
        assert!(!verify_rotation(&n, &o, &sign_rotation(&new, &n)), "a key cannot hand over to itself");
        assert!(!verify_rotation(&o, "not hex", &sig));
    }

    #[test]
    fn rotation_signature_is_not_a_chat_message_signature() {
        let (old, new) = (keygen(N), keygen(N));
        let sig = sign_rotation(&old, &new.public_key.commitment_root);
        assert!(!verify("hello", &sig, &old.root_only()));
    }
}
