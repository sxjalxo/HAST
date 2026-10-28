//! The security-sensitive flow: signing frames, sealing through ratchet sessions and sender-key chains, checking
//! signatures against verified key chains, opening messages, and key handovers. Review changes here closely.
use super::*;

/// A message or sender-key frame for `room`: a fresh id and send time, both signatures over
/// `identity::message_payload` (the SLH-DSA one in the worker).
pub(super) async fn signed_frame(kind: &str, room: &str, body: &str, name: &str, kp: &KeyPair, keys: &LongTermKeys) -> Value {
    let id = format!("{}-{:08x}", now_ms() as u64, (js_sys::Math::random() * u32::MAX as f64) as u32);
    let sent_at = now_ms() as u64;
    let payload = identity::message_payload(room, &id, sent_at, body);
    let signature = hbss::sign_with_proofs(&payload, kp);
    let cosig = crate::worker::run("slh_sign", json!({ "keys": keys, "message": payload })).await;
    json!({ "type": kind, "room": room, "id": id, "sentAt": sent_at, "sender": name, "senderAvatar": "", "message": body,
            "signature": signature, "slhSignature": cosig, "commitment": kp.public_key.commitment_root })
}

/// Seal `text` through this browser's session with each recipient device (starting one where there is none); the
/// sessions move on in `st`, which the caller saves.
pub(super) fn seal_to(st: &mut auth::ChatState, text: &str, aad: &str, to: &[Recipient]) -> String {
    let (mut env, key) = ratchet::seal(text, aad);
    let now = now_ms();
    for r in to {
        let list = st.sessions.entry(r.label.clone()).or_default();
        if ratchet::pick(list, &r.identity).is_none() {
            list.extend(ratchet::Session::initiate(&r.kem, &r.identity, now));
            ratchet::prune(list);
        }
        if let Some(s) = ratchet::pick(list, &r.identity) {
            ratchet::add(&mut env, &key, &r.label, s, now);
        }
    }
    serde_json::to_string(&env).unwrap_or_default()
}

/// Open a message sealed through sessions: with our session with the sending device, or by accepting the session it
/// starts. The session moves on (forgetting the key) only if the message opens.
pub(super) fn open_sealed(e: &ratchet::Envelope, me: &str, from: &str, sender: &str, identity: &str, keys: Option<&LongTermKeys>) -> Option<String> {
    let label = auth::my_label(me);
    let w = e.to.get(&label)?;
    let mut st = auth::load_chat_state(me);
    let list = st.sessions.entry(from.to_string()).or_default();
    let now = now_ms();
    let text = match list.iter_mut().find(|s| s.id == w.h.s) {
        Some(s) => ratchet::open(e, &label, s, sender, now)?,
        None => {
            let (s, t) = ratchet::open_new(e, &label, keys?, identity, sender, now)?;
            list.push(s);
            ratchet::prune(list);
            t
        }
    };
    auth::save_chat_state(me, &st);
    Some(text)
}

/// A lobby message under a sender-key chain: opened with this browser's copy of that chain, which moves on.
pub(super) fn open_group(g: &pq::GroupCt, me: &str, sender: &str) -> Option<String> {
    let mut st = auth::load_chat_state(me);
    let (_, chain) = st.received.get_mut(sender)?.iter_mut().find(|(id, _)| *id == g.g)?;
    let text = ratchet::group_open(chain, g, sender, now_ms())?;
    auth::save_chat_state(me, &st);
    Some(text)
}

/// Keep what was just decrypted: once its keys are gone, this browser's copy is the only one.
pub(super) async fn keep(me: &str, m: &Value, c: &Checked) {
    if c.opened {
        let key = format!("chat:{}:{}", m["sender"].as_str().unwrap_or_default().to_lowercase(), m["id"].as_str().unwrap_or_default());
        history::put(me, &key, &json!({ "frame": m, "text": c.text, "at": m["sentAt"].as_f64().unwrap_or_else(now_ms) })).await;
    }
}

/// A sender's group key: kept if the frame verifies like a message and its envelope opens for us. The server hands
/// the latest ones out on every connect; one already taken is not opened again (its session key is gone).
pub(super) async fn take_sender_key(f: &Value, me: &str, chains: RwSignal<HashMap<String, Dir>>, keys: Option<&LongTermKeys>) {
    let sender = f["sender"].as_str().unwrap_or_default().to_lowercase();
    let frame = format!("{sender}:{}", f["id"].as_str().unwrap_or_default());
    if auth::load_chat_state(me).taken.contains(&frame) {
        return;
    }
    let c = check(f, me, chains, keys, None).await;
    if !(c.verified && c.readable) {
        return;
    }
    if let Some((id, chain)) = ratchet::RecvChain::from_distribution(&c.text) {
        let mut st = auth::load_chat_state(me);
        st.add_sender_key(&frame, &sender, id, chain);
        auth::save_chat_state(me, &st);
        return;
    }
    // a fixed group key, from before sender-key chains
    let Ok(dist) = serde_json::from_str::<Value>(&c.text) else { return };
    let (Some(id), Some(key)) = (dist["id"].as_str(), dist["key"].as_str()) else { return };
    let mut groups = auth::load_groups(me);
    groups.add(f["sender"].as_str().unwrap_or_default(), id, key, now_ms(), KEM_KEEP_MS);
    auth::save_groups(me, &groups);
}

/// Hand over to a fresh HBSS key and a fresh ML-KEM key; the outgoing keys sign the handover. Also gives an
/// account from before long-term keys its SLH-DSA and ML-KEM keys.
pub(super) async fn rotate(
    name: &str,
    s: &mpsc::UnboundedSender<String>,
    key_pair: RwSignal<Option<KeyPair>>,
    lt: RwSignal<Option<LongTermKeys>>,
    uses: RwSignal<u32>,
    rotate_due: RwSignal<bool>,
) {
    let Some(kp) = key_pair.get_untracked() else { return };
    let mut keys = lt.get_untracked().unwrap_or_else(LongTermKeys::generate);
    keys.rotate_kem(now_ms(), KEM_KEEP_MS);
    let next = hbss::keygen(hbss::N);
    let link = crate::worker::run("rotate_link", json!({ "kp": kp, "newRoot": next.public_key.commitment_root, "keys": keys })).await;
    let _ = s.unbounded_send(json!({"type":"rotate","link":link}).to_string());
    auth::save_keys(name, &next);
    auth::save_lt(name, &keys);
    auth::set_key_uses(name, 0);
    uses.try_set(0);
    rotate_due.try_set(false);
    key_pair.try_set(Some(next));
    lt.try_set(Some(keys));
}

/// Both signatures must verify under the keys the message names, those keys must be in the sender's verified
/// chain, and then the message is opened: `known` is its text from this browser's history, else it is decrypted
/// (through a session, a sender-key chain, or the long-term keys for older formats).
pub(super) async fn check(m: &Value, me: &str, chains: RwSignal<HashMap<String, Dir>>, keys: Option<&LongTermKeys>, known: Option<&str>) -> Checked {
    let body = m["message"].as_str().unwrap_or_default();
    let env = serde_json::from_str::<pq::Envelope>(body).ok();
    let renv = serde_json::from_str::<ratchet::Envelope>(body).ok();
    let bad = |note: &'static str| Checked {
        verified: false,
        unconfirmed: false,
        note,
        text: if env.is_some() || renv.is_some() {
            "Encrypted message".into()
        } else {
            body.to_string()
        },
        cosigned: false,
        recipients: 0,
        group: false,
        readable: false,
        fingerprint: String::new(),
        opened: false,
    };
    if m["signature"].is_null() {
        return bad("Message is unsigned");
    }
    let (sender, root) = (m["sender"].as_str().unwrap_or_default(), m["commitment"].as_str().unwrap_or_default());
    let pk = PublicKey {
        commitment_root: root.to_string(),
        commitments: vec![],
        version: hbss::KEY_VERSION,
    };
    // messages from before replay protection signed only the body
    let sent_at = m["sentAt"].as_u64();
    let signed = match sent_at {
        Some(t) => identity::message_payload(m["room"].as_str().unwrap_or(identity::LOBBY), m["id"].as_str().unwrap_or_default(), t, body),
        None => body.to_string(),
    };
    if !hbss::verify(&signed, &parse_sig(&m["signature"]), &pk) {
        return bad("Signature does not verify");
    }
    // the chain of the device that signed it: the primary one, or another device vouched for by the identity key
    let device = m["device"].as_str().unwrap_or(identity::PRIMARY);
    let key = if device == identity::PRIMARY {
        sender.to_string()
    } else {
        format!("{sender}#{device}")
    };
    let mut dir = directory(me, &key, chains, false).await;
    if matches!(&dir, Dir::Ok { roots, .. } if !roots.iter().any(|r| r == root)) {
        dir = directory(me, &key, chains, true).await; // the sender may have rotated since we last looked
    }
    // `replaced`: a later recovery replaced these keys, so whoever held them could have signed this (any send time)
    let (slh, recovered, replaced) = match dir {
        Dir::Bad if device == identity::PRIMARY => return bad("Sender's key chain could not be verified"),
        Dir::Bad => return bad("Sent from another browser of theirs that doesn't verify (linked before an account recovery, or not vouched for by their identity key)"),
        Dir::Ok { roots, slh, recoveries, .. } => match roots.iter().position(|r| r == root) {
            None => return bad("Key is not in the sender's account key chain"),
            Some(i) => (slh[i].clone(), recoveries.iter().any(|&r| r <= i), recoveries.iter().any(|&r| r > i)),
        },
    };
    // the safety number and any recovery are the account's: from the primary chain
    let (head_slh, has_recovery) = match directory(me, sender, chains, false).await {
        Dir::Ok { slh, recoveries, .. } => (slh.last().cloned().flatten(), !recoveries.is_empty()),
        Dir::Bad => (None, false),
    };
    let sender_identity = head_slh.clone().unwrap_or_default();
    let fingerprint = head_slh.map(|k| identity::fingerprint(sender, &k)).unwrap_or_default();
    if let Some(slh) = &slh {
        if sent_at.is_none() {
            return bad("Message lacks its signed id and send time");
        }
        let ok = crate::worker::run("slh_verify", json!({ "pk": slh, "message": signed, "sig": m["slhSignature"] })).await;
        if ok != json!(true) {
            return bad("SLH-DSA co-signature does not verify");
        }
    }
    let group = serde_json::from_str::<pq::GroupCt>(body).ok();
    let sender_lc = sender.to_lowercase();
    let sealed_to = renv.as_ref().map(|e| e.to.len()).or(env.as_ref().map(|e| e.to.len())).unwrap_or(0);
    let unread = || ("Encrypted message".to_string(), false);
    let ((text, readable), opened) = match (known, &renv, &env, &group, &slh) {
        (Some(t), ..) => ((t.to_string(), true), false),
        (None, Some(e), _, _, Some(_)) => match open_sealed(e, me, &identity::label(sender, device), &sender_lc, &sender_identity, keys) {
            Some(t) => ((t, true), true),
            None => (unread(), false),
        },
        (None, None, Some(e), _, _) => match keys.and_then(|k| pq::open(e, &auth::my_label(me), k, &sender_lc)) {
            Some(t) => ((t, true), true),
            None => (unread(), false),
        },
        (None, None, None, Some(g), Some(_)) => {
            let text = match g.i {
                Some(_) => open_group(g, me, &sender_lc),
                None => auth::load_groups(me).find(sender, &g.g).and_then(|k| pq::group_open(&k, g, &sender_lc)), // a fixed group key
            };
            match text {
                Some(t) => ((t, true), true),
                None => (unread(), false),
            }
        }
        (None, None, None, None, None) => ((body.to_string(), true), false), // from before encryption existed
        _ => return bad("Message is not encrypted"),
    };
    let recipients = sealed_to;
    let changed = safety_changed(me, sender, &fingerprint);
    let unconfirmed = !sender.eq_ignore_ascii_case(me) && needs_confirmation(me, sender, &fingerprint, has_recovery);
    let note = if changed && unconfirmed {
        "Safety number changed since you last saw it: check it with them before trusting this"
    } else if replaced {
        "Signed with a key the sender has since replaced through account recovery"
    } else if !readable {
        "Sealed to keys this browser does not hold (sent before you joined or re-keyed)"
    } else if recovered && unconfirmed {
        "Signed with keys only the server vouched for (account recovery): compare safety numbers with them, then mark them verified"
    } else if unconfirmed {
        "Their key chain includes an account recovery that you haven't confirmed: compare safety numbers with them"
    } else if recovered {
        "Signed with a key added by account recovery (safety number confirmed by you)"
    } else if slh.is_none() {
        "Sent before SLH-DSA co-signing and end-to-end encryption"
    } else {
        ""
    };
    Checked {
        verified: !replaced,
        unconfirmed: unconfirmed && !replaced,
        note,
        text,
        cosigned: slh.is_some(),
        recipients,
        group: group.is_some(),
        readable,
        fingerprint,
        opened,
    }
}
