//! Other accounts' keys as this browser has verified them: chains fetched from the server (only new links when a
//! verified copy is cached), checked in the worker, and the encryption keys to seal messages to. Shared by LiveChat and
//! messaging.
use crate::auth;
use crate::util::*;
use hast_core::identity;
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

/// What the server's key directory says about a sender, after verifying the chain ourselves.
#[derive(Clone)]
pub enum Dir {
    Ok {
        roots: Vec<String>,
        /// co-signing key per root (`None` for roots from before long-term keys)
        slh: Vec<Option<String>>,
        /// current encryption key
        kem: Option<String>,
        recoveries: Vec<usize>,
        /// when the server recorded each link (Unix seconds, not signed; may be shorter than `roots`)
        at: Vec<u64>,
    },
    Bad,
}

/// Chains this browser has verified, kept across visits (roots and keys only, no signatures), so returning
/// visitors download and check only new links. Kept in `me`'s vault: a planted entry would be trusted unchecked.
fn chain_cache_get(me: &str, name: &str) -> Option<identity::VerifiedChain> {
    ls_remove("hast_chains"); // the unprotected cache from before
    auth::load_kept::<HashMap<String, identity::VerifiedChain>>(me, "chains")?.remove(&name.to_lowercase())
}

fn chain_cache_put(me: &str, name: &str, v: &identity::VerifiedChain) {
    let mut all: HashMap<String, identity::VerifiedChain> = auth::load_kept(me, "chains").unwrap_or_default();
    all.insert(name.to_lowercase(), v.clone());
    auth::save_kept(me, "chains", &all);
}

/// A contact's verified chain: `name` for the primary device (its SLH-DSA key is the account's identity key and safety
/// number), `name#device` for another device, whose chain must be vouched for by the current identity key.
pub async fn directory(me: &str, key: &str, chains: RwSignal<HashMap<String, Dir>>, force: bool) -> Dir {
    let Some((name, device)) = key.split_once('#') else {
        return fetch_dir(me, key, None, chains, force).await;
    };
    match fetch_dir(me, name, None, chains, false).await {
        Dir::Ok { slh, .. } => match slh.last().cloned().flatten() {
            Some(identity) => fetch_dir(me, key, Some((device, &identity)), chains, force).await,
            None => Dir::Bad,
        },
        Dir::Bad => Dir::Bad,
    }
}

/// `device`: the device id and the identity key that must vouch for it (`None` for the primary chain).
async fn fetch_dir(me: &str, key: &str, device: Option<(&str, &str)>, chains: RwSignal<HashMap<String, Dir>>, force: bool) -> Dir {
    // a device's chain is only good under the identity key that vouched for it (a recovery replaces that key)
    let vouched = |slh: &[Option<String>]| device.is_none_or(|(_, id)| slh.first().cloned().flatten().as_deref() == Some(id));
    if !force {
        if let Some(d) = chains.with_untracked(|c| c.get(key).cloned()).filter(|d| match d {
            Dir::Ok { slh, .. } => vouched(slh),
            Dir::Bad => true,
        }) {
            return d;
        }
    }
    let name = identity::base_name(key);
    // only the links after the last root we verified are downloaded and checked
    let cached = chain_cache_get(me, key).filter(|v| vouched(&v.slh));
    let since = cached.as_ref().and_then(|v| v.roots.last().cloned());
    let verified = match auth::fetch_chain(name, device.map(|(d, _)| d), since.as_deref()).await {
        Ok((links, full)) => {
            let job = match (full, cached, device) {
                (false, Some(v), None) => json!({ "op": "extend_chain", "verified": v, "links": links }),
                (false, Some(v), Some(_)) => json!({ "op": "extend_device", "verified": v, "links": links }),
                (_, _, None) => json!({ "op": "verify_chain", "username": name, "links": links }),
                (_, _, Some((d, id))) => json!({ "op": "verify_device", "username": name, "device": d, "identity": id, "links": links }),
            };
            serde_json::from_value::<identity::VerifiedChain>(crate::worker::run(job["op"].as_str().unwrap_or_default(), job.clone()).await).ok()
        }
        Err(_) => None,
    };
    if let Some(v) = &verified {
        chain_cache_put(me, key, v);
    }
    let d = match verified {
        Some(v) => Dir::Ok {
            roots: v.roots,
            slh: v.slh,
            kem: v.kem,
            recoveries: v.recoveries,
            at: v.at,
        },
        None => Dir::Bad,
    };
    chains.try_update(|c| {
        c.insert(key.to_string(), d.clone());
    });
    d
}

/// What we know about a contact's safety number: first seen automatically, or confirmed by the user.
#[derive(Clone, Serialize, Deserialize)]
pub struct Trust {
    pub fp: String,
    pub verified: bool,
}

/// Kept in the vault: in plain localStorage, someone with the browser profile could plant a safety number.
pub fn trust_load(me: &str) -> HashMap<String, Trust> {
    if let Some(t) = auth::load_kept(me, "trust") {
        return t;
    }
    // move the numbers remembered before the vault held them (once, when the vault is open)
    let old = format!("hast_trust:{}", me.to_lowercase());
    let t: HashMap<String, Trust> = ls_get(&old).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    auth::save_kept(me, "trust", &t);
    if auth::load_kept::<HashMap<String, Trust>>(me, "trust").is_some() {
        ls_remove(&old);
    }
    t
}

pub fn trust_set(me: &str, who: &str, t: Trust) {
    let mut all = trust_load(me);
    all.insert(who.to_lowercase(), t);
    auth::save_kept(me, "trust", &all);
}

/// Remember a contact's safety number the first time we see it; true if it differs from the one remembered.
pub fn safety_changed(me: &str, who: &str, fp: &str) -> bool {
    if fp.is_empty() || who.eq_ignore_ascii_case(me) {
        return false;
    }
    match trust_load(me).get(&who.to_lowercase()) {
        Some(t) => t.fp != fp,
        None => {
            trust_set(
                me,
                who,
                Trust {
                    fp: fp.to_string(),
                    verified: false,
                },
            );
            false
        }
    }
}

/// Has the user compared `who`'s current safety number `fp` out of band and marked it verified?
pub fn confirmed(me: &str, who: &str, fp: &str) -> bool {
    !fp.is_empty() && trust_load(me).get(&who.to_lowercase()).is_some_and(|t| t.verified && t.fp == fp)
}

/// Keys that only the server vouched for (a recovery), or a safety number that changed since we last saw it, are not
/// trusted until the user confirms the current number. `fp` is the contact's current safety number.
pub fn needs_confirmation(me: &str, who: &str, fp: &str, has_recovery: bool) -> bool {
    (has_recovery || safety_changed(me, who, fp)) && !confirmed(me, who, fp)
}

/// A device to seal to: its label (`identity::label`), its long-term ML-KEM key, and its account's identity key.
pub struct Recipient {
    pub label: String,
    pub kem: String,
    pub identity: String,
}

/// Every active device of every account (this account's other devices included, this browser not) with an encryption
/// key from a chain we verified ourselves, so the server cannot slip in a key of its own (except through a visible
/// recovery). Also returns the names left out.
pub async fn recipients(me: &str, chains: RwSignal<HashMap<String, Dir>>) -> Result<(Vec<Recipient>, Vec<String>), ()> {
    let v = auth::call("GET", "/api/directory", None).await.map_err(|_| ())?;
    let mine = auth::my_label(me);
    let (mut to, mut skipped) = (vec![], vec![]);
    for a in v["accounts"].as_array().cloned().unwrap_or_default() {
        let name = a["username"].as_str().unwrap_or_default();
        // a primary chain that changed (a rotation or a recovery) may have a new identity key: check it first
        let mut primary = directory(me, name, chains, false).await;
        if matches!(&primary, Dir::Ok { roots, .. } if roots.last().map(String::as_str) != a["head"].as_str()) {
            primary = directory(me, name, chains, true).await;
        }
        let identity = match primary {
            Dir::Ok { slh, .. } => slh.last().cloned().flatten().unwrap_or_default(),
            Dir::Bad => String::new(),
        };
        for d in a["devices"].as_array().cloned().unwrap_or_default() {
            let (device, head) = (d["device"].as_str().unwrap_or_default(), d["head"].as_str().unwrap_or_default());
            let label = identity::label(name, device);
            if label == mine {
                continue;
            }
            let key = if device == identity::PRIMARY { name.to_string() } else { format!("{name}#{device}") };
            let mut dir = directory(me, &key, chains, false).await;
            if matches!(&dir, Dir::Ok { roots, .. } if roots.last().map(String::as_str) != Some(head)) {
                dir = directory(me, &key, chains, true).await; // it rotated since we looked
            }
            match dir {
                Dir::Ok { kem: Some(kem), .. } => to.push(Recipient {
                    label,
                    kem,
                    identity: identity.clone(),
                }),
                _ if !skipped.iter().any(|s| s == name) => skipped.push(name.to_string()),
                _ => {}
            }
        }
    }
    Ok((to, skipped))
}
