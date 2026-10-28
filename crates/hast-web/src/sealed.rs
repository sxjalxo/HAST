//! The messaging channel's end-to-end layer. The sender's browser Hamming-codes the text and simulates the noisy
//! channel (`hast_core::mds`), seals the result to every account whose key chain it verified (ML-KEM-768) and signs
//! it with its SLH-DSA key. Receivers check the signature against the sender's verified chain, open the envelope and
//! run the error correction themselves. The server only ever sees ciphertext.
use crate::auth;
use crate::contacts::{directory, needs_confirmation, recipients, Dir};
use crate::util::*;
use hast_core::{identity, mds, pq, pq::LongTermKeys};
use leptos::prelude::*;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Bit error rate of the simulated channel.
pub const NOISE: f64 = 0.02;

/// A frame ready to send (`{id, sentAt, body, sig}`), or why it could not be made.
pub async fn seal(me: &str, text: &str, hamming: bool, chains: RwSignal<HashMap<String, Dir>>) -> Result<Value, String> {
    let keys = auth::load_lt(me).ok_or("Open LiveChat once to create your encryption keys")?;
    let (to, _) = recipients(me, chains).await.map_err(|_| "Could not load the member list".to_string())?;
    let mut to: Vec<(String, String)> = to.into_iter().map(|r| (r.label, r.kem)).collect();
    to.push((auth::my_label(me), keys.kem_pk.clone()));
    let inner = if hamming {
        let noisy = mds::simulate_noise(&mds::encode_message(text), NOISE);
        json!({ "mode": "QuantumMDS", "codewords": hex::encode(noisy), "errorRate": NOISE })
    } else {
        json!({ "mode": "GD", "text": text })
    };
    let body = serde_json::to_string(&pq::seal(&inner.to_string(), &me.to_lowercase(), &to)).unwrap_or_default();
    let id = format!("{}-{}", now_ms() as u64, rand_id(8));
    let sent_at = now_ms() as u64;
    let sig = crate::worker::run("slh_sign", json!({ "keys": keys, "message": identity::messaging_payload(&id, sent_at, &body) })).await;
    Ok(json!({ "id": id, "sentAt": sent_at, "body": body, "sig": sig }))
}

pub struct Opened {
    pub text: String,
    pub verified: bool,
    /// signed with keys from a recovery (or the safety number changed) that the user hasn't confirmed in LiveChat
    pub unconfirmed: bool,
    pub note: &'static str,
    /// Hamming statistics, when the message used the noisy channel
    pub hamming: Option<(usize, usize)>,
    /// the decrypted inner message, when it was decrypted just now: worth keeping, since retired keys are deleted
    pub opened: Option<String>,
}

/// Which SLH-DSA key in the sender's verified chain `sig` verifies under: `Some(true)` the current one, `Some(false)`
/// one replaced by a recovery (whoever held the old keys could have signed it, with any send time), `None` neither.
async fn signed_by(me: &str, sender: &str, payload: &str, sig: &Value, chains: RwSignal<HashMap<String, Dir>>) -> Option<bool> {
    for force in [false, true] {
        // a second look with a fresh chain, in case the sender recovered since we cached it
        if let Dir::Ok { slh, .. } = directory(me, sender, chains, force).await {
            let current = slh.last().cloned().flatten();
            let mut keys: Vec<String> = slh.into_iter().flatten().collect();
            keys.dedup();
            for k in keys.into_iter().rev() {
                if crate::worker::run("slh_verify", json!({ "pk": k, "message": payload, "sig": sig })).await == json!(true) {
                    return Some(current.as_ref() == Some(&k));
                }
            }
        }
    }
    None
}

const REPLACED: &str = "Signed with a key the sender has since replaced through account recovery";
const UNCONFIRMED: &str = "Keys from an account recovery that you haven't confirmed: compare safety numbers with them in LiveChat";

/// `known`: the inner message as this browser kept it (see `history`), so it isn't decrypted again.
pub async fn open(m: &Value, me: &str, chains: RwSignal<HashMap<String, Dir>>, keys: Option<&LongTermKeys>, known: Option<&str>) -> Opened {
    let sender = m["senderId"].as_str().unwrap_or_default();
    let Some(body) = m["body"].as_str() else {
        return Opened {
            text: m["text"].as_str().unwrap_or_default().to_string(),
            verified: false, // unsigned: nothing shows who wrote it
            unconfirmed: false,
            note: "Sent before this channel was end-to-end encrypted (unsigned)",
            hamming: None,
            opened: None,
        };
    };
    let bad = |note| Opened {
        text: "Encrypted message".into(),
        verified: false,
        unconfirmed: false,
        note,
        hamming: None,
        opened: None,
    };
    let payload = identity::messaging_payload(m["id"].as_str().unwrap_or_default(), m["sentAt"].as_u64().unwrap_or_default(), body);
    let Some(current) = signed_by(me, sender, &payload, &m["sig"], chains).await else {
        return bad("Signature does not verify against the sender's key chain");
    };
    // the same rule as LiveChat: keys only the server vouched for stay amber until the safety number is confirmed
    let unconfirmed = current
        && !sender.eq_ignore_ascii_case(me)
        && match directory(me, sender, chains, false).await {
            Dir::Ok { slh, recoveries, .. } => {
                let fp = slh.last().cloned().flatten().map(|k| identity::fingerprint(sender, &k)).unwrap_or_default();
                needs_confirmation(me, sender, &fp, !recoveries.is_empty())
            }
            Dir::Bad => false,
        };
    let note = |n: &'static str| match (current, unconfirmed) {
        (false, _) => REPLACED,
        (true, true) if n.is_empty() => UNCONFIRMED,
        _ => n,
    };
    let opened = match known {
        Some(_) => None,
        None => serde_json::from_str::<pq::Envelope>(body)
            .ok()
            .and_then(|e| keys.and_then(|k| pq::open(&e, &auth::my_label(me), k, &sender.to_lowercase()))),
    };
    let Some(inner) = known.map(String::from).or(opened.clone()).and_then(|t| serde_json::from_str::<Value>(&t).ok()) else {
        return Opened {
            text: "Encrypted message".into(),
            verified: current,
            unconfirmed,
            note: note("Sealed to keys this browser does not hold (sent before you joined or re-keyed)"),
            hamming: None,
            opened: None,
        };
    };
    if inner["mode"] == "QuantumMDS" {
        // the receiver's half of the channel: Hamming decoding corrects single-bit errors per byte
        let d = mds::decode_message(&hex::decode(inner["codewords"].as_str().unwrap_or_default()).unwrap_or_default());
        return Opened {
            text: d.text,
            verified: current,
            unconfirmed,
            note: note(""),
            hamming: Some((d.corrected, d.uncorrectable)),
            opened,
        };
    }
    Opened {
        text: inner["text"].as_str().unwrap_or_default().to_string(),
        verified: current,
        unconfirmed,
        note: note(""),
        hamming: None,
        opened,
    }
}
