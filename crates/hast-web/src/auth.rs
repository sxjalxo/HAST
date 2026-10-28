//! Account session, API calls, the per-account key store and the sign-in gate that wraps every page.
//!
//! The password only proves who you are to the server. Signing is done by an HBSS key plus a long-term
//! SLH-DSA key, and messages are decrypted with a long-term ML-KEM key. All are generated in this browser and
//! kept in an encrypted vault per account (see below); the server only ever sees public keys.
use crate::ui::*;
use crate::util::*;
use gloo_net::http::Request;
use gloo_timers::future::TimeoutFuture;
use hast_core::{
    hbss::{self, KeyPair},
    identity::{self, ChainLink},
    pq::{self, LongTermKeys},
    ratchet,
};
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Clone, PartialEq)]
pub enum AuthState {
    Loading,
    Anonymous,
    /// signed in, but this browser does not hold the account's current key
    NeedsKey {
        username: String,
    },
    /// signed in, and this browser has keys for the account, but they are encrypted until the password is entered
    Locked {
        username: String,
    },
    /// the password was right and the account has passkeys: one of them has to answer `options` before the server
    /// starts a session (`pending` names this sign-in)
    Passkey {
        username: String,
        pending: String,
        options: Value,
    },
    User {
        username: String,
    },
}

#[derive(Clone, Copy)]
pub struct Auth {
    pub state: RwSignal<AuthState>,
}

pub fn use_auth() -> Auth {
    use_context::<Auth>().expect("AuthGate must wrap the app")
}

impl Auth {
    /// The signed-in account (reactive).
    pub fn username(&self) -> Option<String> {
        match self.state.get() {
            AuthState::User { username } => Some(username),
            _ => None,
        }
    }

    pub fn username_untracked(&self) -> Option<String> {
        match self.state.get_untracked() {
            AuthState::User { username } => Some(username),
            _ => None,
        }
    }
}

// ---- API ----

pub struct ApiError {
    pub message: String,
}

pub async fn call(method: &str, path: &str, body: Option<Value>) -> Result<Value, ApiError> {
    let net = |e: gloo_net::Error| ApiError {
        message: format!("network error: {e}"),
    };
    let req = match (method, body) {
        ("POST", Some(b)) => Request::post(path).json(&b).map_err(net)?,
        ("POST", None) => Request::post(path).build().map_err(net)?,
        ("DELETE", Some(b)) => Request::delete(path).json(&b).map_err(net)?,
        ("DELETE", None) => Request::delete(path).build().map_err(net)?,
        _ => Request::get(path).build().map_err(net)?,
    };
    let resp = req.send().await.map_err(net)?;
    let status = resp.status();
    let json = resp.json::<Value>().await.unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        Ok(json)
    } else {
        Err(ApiError {
            message: json["error"].as_str().map(String::from).unwrap_or_else(|| format!("request failed ({status})")),
        })
    }
}

/// The account's chain links: all of them, or (with `since`) only those after that root. The flag says whether
/// the server sent the whole chain (it does when `since` is not in it).
/// One device's chain (`device` names a non-primary one), or only the links after `since`.
pub async fn fetch_chain(name: &str, device: Option<&str>, since: Option<&str>) -> Result<(Vec<ChainLink>, bool), String> {
    let mut path = format!("/api/keys/{name}?device={}", device.unwrap_or(identity::PRIMARY));
    if let Some(r) = since {
        path.push_str(&format!("&since={r}"));
    }
    let v = call("GET", &path, None).await.map_err(|e| e.message)?;
    let links = serde_json::from_value(v["chain"].clone()).map_err(|e| e.to_string())?;
    Ok((links, v["full"] != false))
}

// ---- keys, one encrypted vault per account, kept in this browser ----
//
// The vault in localStorage is encrypted (XChaCha20-Poly1305) under a key derived from the password with Argon2id.
// The derived key is kept in sessionStorage, so reloads in this tab stay unlocked, while a closed tab, a sign-out
// or a copy of the browser profile only leaves ciphertext behind.

#[derive(Clone, Default, Serialize, Deserialize)]
struct Secrets {
    hbss: Option<KeyPair>,
    lt: Option<LongTermKeys>,
    #[serde(default)]
    groups: GroupKeys,
    /// state an attacker must not be able to plant (verified key chains, safety numbers), by name
    #[serde(default)]
    kept: std::collections::HashMap<String, Value>,
    /// which of the account's devices this browser is (`None`: the primary one)
    #[serde(default)]
    device: Option<String>,
    /// the key this browser's local history is encrypted under (hex; see `history`)
    #[serde(default)]
    history_key: Option<String>,
}

/// LiveChat's forward-secret state: sessions with other devices and lobby sender keys. Kept in its own entry,
/// encrypted like the vault, and written only by the tab that holds LiveChat (see `util::take_tab_lock`), so no other
/// page's vault write can roll it back: a rolled-back ratchet would use a key twice.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ChatState {
    /// by the peer device's label (`identity::label`)
    #[serde(default)]
    pub sessions: HashMap<String, Vec<ratchet::Session>>,
    /// the lobby sender key this browser sends with, the members it went to, and the HBSS root it started under
    #[serde(default)]
    pub mine: Option<(ratchet::SendKey, String, String)>,
    /// members' sender keys by sender (lowercase): (key id, this browser's copy of the chain), newest last
    #[serde(default)]
    pub received: HashMap<String, Vec<(String, ratchet::RecvChain)>>,
    /// sender-key frames already taken (`sender:id`), so a re-delivered one is not opened again
    #[serde(default)]
    pub taken: Vec<String>,
}

/// Sender keys kept per sender, and sender-key frames remembered as taken.
const KEEP_SENDER_KEYS: usize = 20;
const KEEP_TAKEN: usize = 1000;

impl ChatState {
    pub fn add_sender_key(&mut self, frame: &str, sender: &str, id: String, chain: ratchet::RecvChain) {
        let list = self.received.entry(sender.to_lowercase()).or_default();
        if !list.iter().any(|(i, _)| *i == id) {
            list.push((id, chain));
        }
        let extra = list.len().saturating_sub(KEEP_SENDER_KEYS);
        list.drain(..extra);
        self.taken.push(frame.to_string());
        let extra = self.taken.len().saturating_sub(KEEP_TAKEN);
        self.taken.drain(..extra);
    }
}

fn chat_name(user: &str) -> String {
    format!("hast_chat:{}", user.to_lowercase())
}

pub fn load_chat_state(user: &str) -> ChatState {
    kek(user)
        .and_then(|k| pq::decrypt_local(&k, &ls_get(&chat_name(user))?))
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_chat_state(user: &str, s: &ChatState) {
    if let (Some(k), Ok(json)) = (kek(user), serde_json::to_string(s)) {
        ls_set(&chat_name(user), &pq::encrypt_local(&k, &json));
    }
}

/// The key local history is encrypted under, made the first time it is needed.
pub fn history_key(user: &str) -> Option<[u8; 32]> {
    let mut s = read_secrets(user)?;
    if s.history_key.is_none() {
        s.history_key = Some(hex::encode(pq::random_salt().into_iter().chain(pq::random_salt()).collect::<Vec<u8>>()));
        write_secrets(user, &s);
    }
    hex::decode(read_secrets(user)?.history_key?).ok()?.try_into().ok()
}

/// How long local history is kept, in days (0: for good).
pub fn history_days(user: &str) -> u32 {
    load_kept(user, "history_days").unwrap_or(0)
}

pub fn set_history_days(user: &str, days: u32) {
    save_kept(user, "history_days", &days);
}

/// Lobby group keys: the one this account currently sends with, and those received from others.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct GroupKeys {
    pub mine: Option<MyGroupKey>,
    /// sender (lowercase) -> (key id, key hex, received at ms), newest last
    #[serde(default)]
    pub received: std::collections::HashMap<String, Vec<(String, String, f64)>>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MyGroupKey {
    pub id: String,
    pub key: String,
    /// fingerprint of the members (names and encryption keys) it was sealed to
    pub members: String,
    /// the HBSS root it was made under: a handover always starts a new group key
    pub root: String,
}

impl GroupKeys {
    pub fn find(&self, sender: &str, id: &str) -> Option<[u8; 32]> {
        let (_, k, _) = self.received.get(&sender.to_lowercase())?.iter().find(|(i, _, _)| i == id)?;
        hex::decode(k).ok()?.try_into().ok()
    }

    /// Remember a key; keys older than `keep_ms` and all but the newest 200 per sender are forgotten.
    pub fn add(&mut self, sender: &str, id: &str, key: &str, now: f64, keep_ms: f64) {
        let list = self.received.entry(sender.to_lowercase()).or_default();
        if !list.iter().any(|(i, _, _)| i == id) {
            list.push((id.to_string(), key.to_string(), now));
        }
        list.retain(|(_, _, at)| now - at <= keep_ms);
        let extra = list.len().saturating_sub(200);
        list.drain(..extra);
    }
}

#[derive(Serialize, Deserialize)]
struct Vault {
    salt: String,
    blob: String,
}

fn vault_name(user: &str) -> String {
    format!("hast_vault:{}", user.to_lowercase())
}

fn kek_name(user: &str) -> String {
    format!("hast_kek:{}", user.to_lowercase())
}

/// Where keys lived before vaults existed (plain JSON); moved into the vault at the next unlock.
fn legacy_names(user: &str) -> [String; 2] {
    [format!("hast_keys:{}", user.to_lowercase()), format!("hast_lt:{}", user.to_lowercase())]
}

fn session() -> Option<web_sys::Storage> {
    web_sys::window()?.session_storage().ok().flatten()
}

fn kek(user: &str) -> Option<[u8; 32]> {
    hex::decode(session()?.get_item(&kek_name(user)).ok()??).ok()?.try_into().ok()
}

fn vault(user: &str) -> Option<Vault> {
    serde_json::from_str(&ls_get(&vault_name(user))?).ok()
}

fn read_secrets(user: &str) -> Option<Secrets> {
    let (v, k) = (vault(user)?, kek(user)?);
    serde_json::from_str(&pq::decrypt_local(&k, &v.blob)?).ok()
}

fn store(user: &str, salt: &str, key: &[u8; 32], s: &Secrets) {
    let Ok(json) = serde_json::to_string(s) else { return };
    let v = Vault {
        salt: salt.to_string(),
        blob: pq::encrypt_local(key, &json),
    };
    if let Ok(v) = serde_json::to_string(&v) {
        ls_set(&vault_name(user), &v);
    }
}

fn write_secrets(user: &str, s: &Secrets) {
    if let (Some(v), Some(k)) = (vault(user), kek(user)) {
        store(user, &v.salt, &k, s);
    }
}

/// Argon2id in the worker (it takes about a second).
async fn derive_key(password: &str, salt: &[u8]) -> Option<[u8; 32]> {
    let v = crate::worker::run("derive_key", json!({ "password": password, "salt": hex::encode(salt) })).await;
    hex::decode(v.as_str()?).ok()?.try_into().ok()
}

async fn new_vault(user: &str, password: &str, s: &Secrets) {
    let salt = pq::random_salt();
    let Some(key) = derive_key(password, &salt).await else { return };
    if let Some(st) = session() {
        let _ = st.set_item(&kek_name(user), &hex::encode(key));
    }
    store(user, &hex::encode(salt), &key, s);
    for n in legacy_names(user) {
        ls_remove(&n); // never leave plaintext keys behind
    }
}

/// Open the vault with the password (or create it, moving keys from before vaults into it). False: wrong password.
async fn unlock(user: &str, password: &str) -> bool {
    let Some(v) = vault(user) else {
        let [k, l] = legacy_names(user);
        let legacy = Secrets {
            hbss: ls_get(&k).and_then(|s| serde_json::from_str(&s).ok()),
            lt: ls_get(&l).and_then(|s| serde_json::from_str(&s).ok()),
            ..Default::default()
        };
        new_vault(user, password, &legacy).await;
        return true;
    };
    let Ok(salt) = hex::decode(&v.salt) else { return false };
    let Some(key) = derive_key(password, &salt).await else { return false };
    if pq::decrypt_local(&key, &v.blob).is_none() {
        return false;
    }
    if let Some(st) = session() {
        let _ = st.set_item(&kek_name(user), &hex::encode(key));
    }
    true
}

fn has_stored_keys(user: &str) -> bool {
    vault(user).is_some() || legacy_names(user).iter().any(|n| ls_get(n).is_some())
}

/// Keys from an older scheme version are ignored.
pub fn load_keys(user: &str) -> Option<KeyPair> {
    read_secrets(user)?.hbss.filter(|k| k.public_key.version == hbss::KEY_VERSION)
}

pub fn save_keys(user: &str, kp: &KeyPair) {
    let mut s = read_secrets(user).unwrap_or_default();
    s.hbss = Some(kp.clone());
    write_secrets(user, &s);
}

pub fn load_groups(user: &str) -> GroupKeys {
    read_secrets(user).map(|s| s.groups).unwrap_or_default()
}

pub fn save_groups(user: &str, g: &GroupKeys) {
    let mut s = read_secrets(user).unwrap_or_default();
    s.groups = g.clone();
    write_secrets(user, &s);
}

/// Kept in the vault rather than plain localStorage, so a copy of the browser profile cannot be edited to plant it.
pub fn load_kept<T: serde::de::DeserializeOwned>(user: &str, name: &str) -> Option<T> {
    serde_json::from_value(read_secrets(user)?.kept.remove(name)?).ok()
}

pub fn save_kept<T: Serialize>(user: &str, name: &str, value: &T) {
    let (Some(mut s), Ok(v)) = (read_secrets(user), serde_json::to_value(value)) else {
        return;
    };
    s.kept.insert(name.to_string(), v);
    write_secrets(user, &s);
}

/// Which of the account's devices this browser is (`d1`, the primary one, unless it was linked).
pub fn my_device(user: &str) -> String {
    read_secrets(user).and_then(|s| s.device).unwrap_or_else(|| identity::PRIMARY.into())
}

/// The name messages to this browser are sealed under (see `identity::label`).
pub fn my_label(user: &str) -> String {
    identity::label(user, &my_device(user))
}

/// The account's long-term keys (SLH-DSA co-signing, ML-KEM decryption).
pub fn load_lt(user: &str) -> Option<LongTermKeys> {
    read_secrets(user)?.lt
}

pub fn save_lt(user: &str, lt: &LongTermKeys) {
    let mut s = read_secrets(user).unwrap_or_default();
    s.lt = Some(lt.clone());
    write_secrets(user, &s);
}

/// The encrypted vault as a file. Importing it in another browser moves the account there: that browser is linked as
/// a new device with the file's identity key, and the exported one is removed. The file is as safe as the password.
pub fn export_vault(user: &str) -> Option<String> {
    let v = vault(user)?;
    serde_json::to_string_pretty(&json!({ "hastKeys": 1, "username": user, "vault": v })).ok()
}

/// Store an exported vault for `user`. Once it is unlocked, `settle` links this browser as a new device (`relink`):
/// continuing the exported browser's chain would reuse its one-time-ish HBSS keys and its ratchet state.
pub fn import_vault(user: &str, text: &str) -> Result<(), String> {
    let v: Value = serde_json::from_str(text).map_err(|_| "That is not a HAST key file".to_string())?;
    if v["hastKeys"] != 1 {
        return Err("That is not a HAST key file".into());
    }
    if !v["username"].as_str().is_some_and(|u| u.eq_ignore_ascii_case(user)) {
        return Err(format!("That key file belongs to {}, not {user}", v["username"].as_str().unwrap_or("someone else")));
    }
    let vault: Vault = serde_json::from_value(v["vault"].clone()).map_err(|_| "The key file is damaged".to_string())?;
    ls_set(&vault_name(user), &serde_json::to_string(&vault).unwrap_or_default());
    ls_remove(&chat_name(user));
    if let Some(st) = session() {
        let _ = st.remove_item(&kek_name(user));
    }
    ls_set(&relink_name(user), "1");
    Ok(())
}

fn relink_name(user: &str) -> String {
    format!("hast_relink:{}", user.to_lowercase())
}

/// After importing a key file: link this browser as a new device with the file's identity key, keep the file's old
/// decryption keys (for history sealed to them), and remove the exported device.
async fn relink(auth: Auth, user: String) {
    let r = async {
        let s = read_secrets(&user).ok_or("The key file could not be opened")?;
        let old = s.lt.clone().ok_or("The key file has no encryption keys")?;
        let mut lt = fresh_long_term();
        (lt.slh_sk, lt.slh_pk) = (old.slh_sk.clone(), old.slh_pk.clone());
        lt.retired = std::iter::once((old.kem_dk, now_ms())).chain(old.retired).take(pq::MAX_RETIRED).collect();
        let kp = hbss::keygen(hbss::N);
        let device = format!("d{}", hex::encode(&pq::random_salt()[..4]));
        let link = crate::worker::run("device_link", json!({ "username": user, "device": device, "kp": kp, "keys": lt })).await;
        call("POST", "/api/devices", Some(json!({ "device": device, "name": "Imported browser", "link": link })))
            .await
            .map_err(|e| e.message)?;
        let _ = call("DELETE", &format!("/api/devices/{}", s.device.as_deref().unwrap_or(identity::PRIMARY)), None).await;
        let mut s = s;
        (s.hbss, s.lt, s.device) = (Some(kp), Some(lt), Some(device));
        write_secrets(&user, &s);
        set_key_uses(&user, 0);
        Ok::<(), String>(())
    }
    .await;
    if let Err(e) = r {
        leptos::logging::warn!("linking the imported keys failed: {e}");
    }
    ls_remove(&relink_name(&user));
    refresh(auth).await;
}

pub fn key_uses(user: &str) -> u32 {
    ls_get(&format!("hast_key_uses:{}", user.to_lowercase())).and_then(|s| s.parse().ok()).unwrap_or(0)
}

pub fn set_key_uses(user: &str, n: u32) {
    ls_set(&format!("hast_key_uses:{}", user.to_lowercase()), &n.to_string());
}

fn fresh_long_term() -> LongTermKeys {
    let mut lt = LongTermKeys::generate();
    lt.kem_since = now_ms();
    lt
}

// ---- flows ----

/// Usable only if this browser holds the current HBSS key and, when the account has them, its long-term keys.
/// (An account from before long-term keys is upgraded by LiveChat's next rotation.)
fn settle(auth: Auth, v: &Value) {
    let username = v["username"].as_str().unwrap_or_default().to_string();
    if read_secrets(&username).is_none() && has_stored_keys(&username) {
        auth.state.set(AuthState::Locked { username });
        return;
    }
    if ls_get(&relink_name(&username)).is_some() {
        auth.state.set(AuthState::Loading);
        spawn_local(relink(auth, username));
        return;
    }
    // this browser's device must still be active, with the keys this vault holds
    let device = my_device(&username);
    let mine = v["devices"]
        .as_array()
        .and_then(|d| d.iter().find(|d| d["device"] == device.as_str()))
        .cloned()
        .unwrap_or_default();
    let head = mine["commitment"].as_str().unwrap_or_default();
    let lt_ok = v["slh"].is_null() || load_lt(&username).is_some_and(|lt| v["slh"] == lt.slh_pk.as_str() && mine["kem"] == lt.kem_pk.as_str());
    let have = !head.is_empty() && lt_ok && load_keys(&username).is_some_and(|k| k.public_key.commitment_root == head);
    auth.state.set(if have { AuthState::User { username } } else { AuthState::NeedsKey { username } });
}

pub async fn refresh(auth: Auth) {
    match call("GET", "/api/me", None).await {
        Ok(v) => settle(auth, &v),
        Err(_) => auth.state.set(AuthState::Anonymous),
    }
}

pub async fn login(auth: Auth, username: &str, password: &str) -> Result<(), String> {
    let v = call("POST", "/api/login", Some(json!({ "username": username, "password": password })))
        .await
        .map_err(|e| e.message)?;
    unlock(v["username"].as_str().unwrap_or(username), password).await; // a wrong (e.g. reset) password leaves it locked
    if v["passkey"].is_object() {
        auth.state.set(AuthState::Passkey {
            username: username.to_string(),
            pending: v["passkey"]["pending"].as_str().unwrap_or_default().to_string(),
            options: v["passkey"]["options"].clone(),
        });
        return Ok(());
    }
    settle(auth, &v);
    Ok(())
}

/// Sign-in step two: the passkey answers the server's challenge, and the server starts the session.
async fn finish_with_passkey(auth: Auth, pending: &str, options: &Value) -> Result<(), String> {
    let mut answer = crate::webauthn::assert(options).await?;
    answer["pending"] = pending.into();
    let v = call("POST", "/api/login/passkey", Some(answer)).await.map_err(|e| e.message)?;
    settle(auth, &v);
    Ok(())
}

pub async fn register(auth: Auth, username: &str, password: &str, invite: &str) -> Result<(), String> {
    TimeoutFuture::new(20).await; // let the "creating key" message paint before the blocking keygen
    let (kp, lt) = (hbss::keygen(hbss::N), fresh_long_term());
    let link = crate::worker::run("register_link", json!({ "username": username, "kp": kp, "keys": lt })).await;
    let mut body = json!({ "username": username, "password": password, "link": link });
    if !invite.trim().is_empty() {
        body["invite"] = json!(invite.trim());
    }
    let v = call("POST", "/api/register", Some(body)).await.map_err(|e| e.message)?;
    let name = v["username"].as_str().unwrap_or(username).to_string();
    new_vault(
        &name,
        password,
        &Secrets {
            hbss: Some(kp),
            lt: Some(lt),
            ..Default::default()
        },
    )
    .await;
    set_key_uses(&name, 0);
    auth.state.set(AuthState::User { username: name });
    Ok(())
}

/// Signed in with the password but without the keys: create new ones; the server records them as a recovery (on the
/// primary device, so this browser becomes it).
pub async fn recover(auth: Auth, username: &str, password: &str) -> Result<(), String> {
    TimeoutFuture::new(20).await;
    let (kp, lt) = (hbss::keygen(hbss::N), fresh_long_term());
    let body = json!({ "password": password, "root": kp.public_key.commitment_root, "slh": lt.slh_pk, "kem": lt.kem_pk });
    call("POST", "/api/recover", Some(body)).await.map_err(|e| e.message)?;
    keep_new_keys(auth, username, password, kp, lt, None).await;
    Ok(())
}

/// Store this browser's new keys in the vault and sign in with them.
async fn keep_new_keys(auth: Auth, username: &str, password: &str, kp: KeyPair, lt: LongTermKeys, device: Option<String>) {
    if unlock(username, password).await {
        // keep the old decryption keys, so history sealed to them stays readable here
        let mut lt = lt;
        let mut s = read_secrets(username).unwrap_or_default();
        if let Some(old) = s.lt.take() {
            lt.retired = std::iter::once((old.kem_dk, now_ms())).chain(old.retired).take(pq::MAX_RETIRED).collect();
        }
        (s.hbss, s.lt, s.device) = (Some(kp), Some(lt), device);
        write_secrets(username, &s);
        ls_remove(&chat_name(username)); // sessions belonged to the keys this browser had before
    } else {
        // the old vault was sealed with another password (reset by the operator): start a new one
        new_vault(
            username,
            password,
            &Secrets {
                hbss: Some(kp),
                lt: Some(lt),
                device,
                ..Default::default()
            },
        )
        .await;
    }
    set_key_uses(username, 0);
    auth.state.set(AuthState::User { username: username.to_string() });
}

/// Link codes: 10 characters from an alphabet without look-alikes (about 50 bits), shown as `xxxxx-xxxxx`.
const CODE_ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// What was typed, as the code it was meant to be: case, spaces and dashes ignored, `o`, `i` and `l` read as digits.
fn normalize_code(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_lowercase() {
            'o' => '0',
            'i' | 'l' => '1',
            c => c,
        })
        .collect()
}

/// On a browser that holds the identity key: offer it to a new browser of this account, encrypted under a fresh code
/// (Argon2id, so the server, which keeps the offer for 10 minutes, can't guess the code). Returns the code to type there.
pub async fn offer_link(user: &str) -> Result<String, String> {
    let lt = load_lt(user).ok_or("Open LiveChat once to create your keys")?;
    let code: String = pq::random_salt()[..10].iter().map(|b| CODE_ALPHABET[(*b % 32) as usize] as char).collect();
    let salt = pq::random_salt();
    let key = derive_key(&code, &salt).await.ok_or("Could not protect the key")?;
    let blob = pq::encrypt_local(&key, &json!({ "slhSk": lt.slh_sk, "slhPk": lt.slh_pk }).to_string());
    call("POST", "/api/devices/offer", Some(json!({ "salt": hex::encode(salt), "blob": blob })))
        .await
        .map_err(|e| e.message)?;
    Ok(format!("{}-{}", &code[..5], &code[5..]))
}

/// Signed in on a new browser: open the identity key offered under `code`, make this browser's own HBSS and ML-KEM
/// keys, and add it as a device of the account (vouched for by the identity key, so no recovery is recorded).
pub async fn link_device(auth: Auth, username: &str, password: &str, code: &str, name: &str) -> Result<(), String> {
    let offer = call("GET", "/api/devices/offer", None).await.map_err(|e| e.message)?;
    let salt = hex::decode(offer["salt"].as_str().unwrap_or_default()).map_err(|_| "The link offer is damaged".to_string())?;
    let key = derive_key(&normalize_code(code), &salt).await.ok_or("Could not derive the key")?;
    let identity: Value = pq::decrypt_local(&key, offer["blob"].as_str().unwrap_or_default())
        .and_then(|t| serde_json::from_str(&t).ok())
        .ok_or("That code doesn't match. Check it on your other browser; a code works for 10 minutes.")?;
    TimeoutFuture::new(20).await; // let the "linking" message paint before the blocking keygen
    let mut lt = fresh_long_term();
    lt.slh_sk = identity["slhSk"].as_str().unwrap_or_default().into();
    lt.slh_pk = identity["slhPk"].as_str().unwrap_or_default().into();
    let kp = hbss::keygen(hbss::N);
    let device = format!("d{}", hex::encode(&pq::random_salt()[..4]));
    let link = crate::worker::run("device_link", json!({ "username": username, "device": device, "kp": kp, "keys": lt })).await;
    call("POST", "/api/devices", Some(json!({ "device": device, "name": name.trim(), "link": link })))
        .await
        .map_err(|e| e.message)?;
    keep_new_keys(auth, username, password, kp, lt, Some(device)).await;
    Ok(())
}

pub async fn logout(auth: Auth) {
    if let Some(st) = session() {
        let _ = st.clear(); // forget the vault keys; only ciphertext stays behind
    }
    let _ = call("POST", "/api/logout", None).await;
    auth.state.set(AuthState::Anonymous);
}

// ---- UI ----

#[component]
pub fn AuthGate(children: ChildrenFn) -> impl IntoView {
    let auth = Auth {
        state: RwSignal::new(AuthState::Loading),
    };
    provide_context(auth);
    spawn_local(refresh(auth));
    view! {
        {move || match auth.state.get() {
            AuthState::Loading => view! {
                <div class="min-h-screen flex flex-col items-center justify-center gap-3 bg-hast-bg">
                    <crate::ui::Logo class="w-12 h-12" loading=true />
                    <span class="hast-label">"Loading keys"</span>
                </div>
            }.into_any(),
            AuthState::Anonymous => view! { <AuthPage auth=auth /> }.into_any(),
            AuthState::NeedsKey { username } => view! { <NeedsKeyPage auth=auth username=username /> }.into_any(),
            AuthState::Locked { username } => view! { <LockedPage auth=auth username=username /> }.into_any(),
            AuthState::Passkey { username, pending, options } => view! { <PasskeyPage auth=auth username=username pending=pending options=options /> }.into_any(),
            AuthState::User { .. } => children().into_any(),
        }}
    }
}

fn shell(body: impl IntoView + 'static) -> impl IntoView {
    view! {
        <div class="min-h-screen bg-hast-bg flex items-center justify-center p-4">
            <div class="w-full max-w-md animate-vault-unlock">
                <div class="mb-6 flex justify-center"><crate::ui::Brand large=true /></div>
                <div class=format!("{CARD} p-8")>{body}</div>
                <p class="mt-4 text-center text-xs text-hast-muted">"Keys are created and kept in this browser. The server only sees public keys."</p>
            </div>
        </div>
    }
}

#[component]
fn AuthPage(auth: Auth) -> impl IntoView {
    let register_mode = RwSignal::new(false);
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let invite = RwSignal::new(String::new());
    let show = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let alive = StoredValue::new(alive_flag()); // Copy, so the closures below stay Copy

    let submit = move || {
        if busy.get_untracked() {
            return;
        }
        let (u, p) = (username.get_untracked().trim().to_string(), password.get_untracked());
        if u.is_empty() || p.is_empty() {
            return;
        }
        if register_mode.get_untracked() && p != confirm.get_untracked() {
            error.set("The two passwords do not match".into());
            return;
        }
        busy.set(true);
        error.set(String::new());
        let (reg, inv) = (register_mode.get_untracked(), invite.get_untracked());
        let alive = alive.get_value();
        spawn_local(async move {
            let r = if reg { register(auth, &u, &p, &inv).await } else { login(auth, &u, &p).await };
            if is_alive(&alive) {
                busy.set(false);
                if let Err(e) = r {
                    error.set(e);
                }
            }
        });
    };
    let field = move |label: &'static str, sig: RwSignal<String>, kind: &'static str, autocomplete: &'static str| {
        view! {
            <div class="space-y-1">
                <label class="text-xs font-medium text-hast-secondary">{label}</label>
                <input class=format!("{INPUT} hast-input") type=kind autocomplete=autocomplete aria-label=label prop:value=move || sig.get()
                    on:input=move |e| sig.set(event_target_value(&e)) on:keydown=move |e| if e.key() == "Enter" { submit() } />
            </div>
        }
    };

    shell(view! {
        <div class="space-y-5">
            <div class=format!("{TABS_LIST_MUTED} grid w-full grid-cols-2")>
                <button class=move || format!("{TAB_SM} {}", if !register_mode.get() { TAB_ACTIVE } else { "" }) on:click=move |_| { register_mode.set(false); error.set(String::new()); }>"Sign in"</button>
                <button class=move || format!("{TAB_SM} {}", if register_mode.get() { TAB_ACTIVE } else { "" }) on:click=move |_| { register_mode.set(true); error.set(String::new()); }>"Create account"</button>
            </div>
            <div class="space-y-4">
                {field("Username", username, "text", "username")}
                <div class="space-y-1">
                    <label class="text-xs font-medium text-hast-secondary">"Password"</label>
                    <div class="relative">
                        <input class=format!("{INPUT} hast-input pr-12") type=move || if show.get() { "text" } else { "password" } aria-label="Password"
                            autocomplete=move || if register_mode.get() { "new-password" } else { "current-password" }
                            prop:value=move || password.get() on:input=move |e| password.set(event_target_value(&e)) on:keydown=move |e| if e.key() == "Enter" { submit() } />
                        <button type="button" on:click=move |_| show.update(|s| *s = !*s) class="absolute right-3 top-1/2 transform -translate-y-1/2 text-hast-muted hover:text-hast-text transition-colors"
                            aria-label="Show password" aria-pressed=move || show.get().to_string()>
                            {move || if show.get() { view! { <Icon name="eye-off" class="w-5 h-5" /> }.into_any() } else { view! { <Icon name="eye" class="w-5 h-5" /> }.into_any() }}
                        </button>
                    </div>
                </div>
                {move || register_mode.get().then(|| view! {
                    <div class="space-y-4">
                        {field("Confirm password", confirm, "password", "new-password")}
                        {field("Invite code (if the server asks for one)", invite, "text", "off")}
                        <p class="text-xs leading-relaxed text-hast-muted">"At least 10 characters. Your signing and encryption keys are created in this browser; the server only receives their public parts."</p>
                    </div>
                })}
                {move || (!error.get().is_empty()).then(|| view! { <div class="flex items-start gap-2 rounded-md border px-3 py-2 text-sm chip-danger"><Icon name="alert-triangle" class="w-4 h-4 mt-0.5 shrink-0" /><span>{move || error.get()}</span></div> })}
                <button class=format!("{BTN} {BTN_DEFAULT} w-full") disabled=move || busy.get() || username.get().trim().is_empty() || password.get().is_empty() on:click=move |_| submit()>
                    {move || match (busy.get(), register_mode.get()) {
                        (true, true) => "Creating your signing key...",
                        (true, false) => "Signing in...",
                        (false, true) => "Create account",
                        (false, false) => "Sign in",
                    }}
                </button>
            </div>
        </div>
    })
}

#[component]
fn PasskeyPage(auth: Auth, username: String, pending: String, options: Value) -> impl IntoView {
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let alive = StoredValue::new(alive_flag());
    let step = StoredValue::new((pending, options));
    let go = move || {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        error.set(String::new());
        let ((pending, options), alive) = (step.get_value(), alive.get_value());
        spawn_local(async move {
            let r = finish_with_passkey(auth, &pending, &options).await;
            if is_alive(&alive) {
                busy.set(false);
                if let Err(e) = r {
                    error.set(e);
                }
            }
        });
    };
    go(); // most browsers show their passkey prompt straight away; the button is there to try again
    shell(view! {
        <div class="space-y-4">
            <div class="flex items-center gap-3">
                <div class="flex h-10 w-10 items-center justify-center rounded-md border border-hast-border bg-hast-elevated"><Icon name="fingerprint" class="w-5 h-5 text-hast-text" /></div>
                <div>
                    <p class="text-sm font-medium text-hast-text">"Confirm with your passkey"</p>
                    <p class="text-xs text-hast-muted">{format!("Password accepted for {username}. This account also needs one of its passkeys.")}</p>
                </div>
            </div>
            {move || (!error.get().is_empty()).then(|| view! { <div class="flex items-start gap-2 rounded-md border px-3 py-2 text-sm chip-danger"><Icon name="alert-triangle" class="w-4 h-4 mt-0.5 shrink-0" /><span>{move || error.get()}</span></div> })}
            <button class=format!("{BTN} {BTN_DEFAULT} w-full") disabled=move || busy.get() on:click=move |_| go()>
                {move || if busy.get() { "Waiting for your passkey..." } else { "Use passkey" }}
            </button>
            <button class=format!("{BTN} {BTN_OUTLINE} w-full") on:click=move |_| auth.state.set(AuthState::Anonymous)>"Cancel"</button>
            <p class="text-xs leading-relaxed text-hast-muted">"Lost the passkey? Ask the operator to run hast-server user passkeys-off with your name; your password then signs in alone again."</p>
        </div>
    })
}

#[component]
fn LockedPage(auth: Auth, username: String) -> impl IntoView {
    let password = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let alive = StoredValue::new(alive_flag());
    let name = StoredValue::new(username.clone());
    let go = move || {
        if busy.get_untracked() || password.get_untracked().is_empty() {
            return;
        }
        busy.set(true);
        error.set(String::new());
        let (p, n, alive) = (password.get_untracked(), name.get_value(), alive.get_value());
        spawn_local(async move {
            let ok = unlock(&n, &p).await;
            if !is_alive(&alive) {
                return;
            }
            if ok {
                refresh(auth).await;
            } else {
                busy.set(false);
                error.set("That password does not open the keys stored here. If your password was reset, use the old one, or create new keys.".into());
            }
        });
    };
    shell(view! {
        <div class="space-y-4">
            <p class="text-sm text-hast-text">{format!("Signed in as {username}. Your keys on this browser are locked.")}</p>
            <p class="text-xs leading-relaxed text-hast-muted">"They are stored encrypted with your password. Enter it to unlock them for this tab."</p>
            <input class=format!("{INPUT} hast-input") type="password" placeholder="Password" aria-label="Password" autocomplete="current-password"
                prop:value=move || password.get() on:input=move |e| password.set(event_target_value(&e)) on:keydown=move |e| if e.key() == "Enter" { go() } />
            {move || (!error.get().is_empty()).then(|| view! { <div class="flex items-start gap-2 rounded-md border px-3 py-2 text-sm chip-danger"><Icon name="alert-triangle" class="w-4 h-4 mt-0.5 shrink-0" /><span>{move || error.get()}</span></div> })}
            <button class=format!("{BTN} {BTN_DEFAULT} w-full") disabled=move || busy.get() || password.get().is_empty() on:click=move |_| go()>
                {move || if busy.get() { "Unlocking..." } else { "Unlock" }}
            </button>
            <div class="flex gap-2">
                <button class=format!("{BTN} {BTN_OUTLINE} flex-1") on:click=move |_| { spawn_local(logout(auth)); }>"Sign out"</button>
                <button class=format!("{BTN} {BTN_OUTLINE} flex-1") on:click=move |_| auth.state.set(AuthState::NeedsKey { username: name.get_value() })>"Create new keys"</button>
            </div>
        </div>
    })
}

#[component]
fn NeedsKeyPage(auth: Auth, username: String) -> impl IntoView {
    let password = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let alive = StoredValue::new(alive_flag());
    let name = StoredValue::new(username.clone());
    let code = RwSignal::new(String::new());
    let device_name = RwSignal::new(String::new());
    let linking = RwSignal::new(false);
    let go = move || {
        if busy.get_untracked() || password.get_untracked().is_empty() {
            return;
        }
        busy.set(true);
        error.set(String::new());
        let (p, n, alive) = (password.get_untracked(), name.get_value(), alive.get_value());
        spawn_local(async move {
            let r = recover(auth, &n, &p).await;
            if is_alive(&alive) {
                busy.set(false);
                if let Err(e) = r {
                    error.set(e);
                }
            }
        });
    };
    let link = move || {
        if busy.get_untracked() || password.get_untracked().is_empty() || code.get_untracked().is_empty() {
            return;
        }
        busy.set(true);
        linking.set(true);
        error.set(String::new());
        let (p, n, c, d, alive) = (
            password.get_untracked(),
            name.get_value(),
            code.get_untracked(),
            device_name.get_untracked(),
            alive.get_value(),
        );
        spawn_local(async move {
            let r = link_device(auth, &n, &p, &c, &d).await;
            if is_alive(&alive) {
                busy.set(false);
                linking.set(false);
                if let Err(e) = r {
                    error.set(e);
                }
            }
        });
    };
    shell(view! {
        <div class="space-y-4">
            <p class="text-sm text-hast-text">{format!("Signed in as {username}, but this browser does not hold your current keys.")}</p>
            <input class=format!("{INPUT} hast-input") type="password" placeholder="Password" aria-label="Password" autocomplete="current-password"
                prop:value=move || password.get() on:input=move |e| password.set(event_target_value(&e)) />
            {move || (!error.get().is_empty()).then(|| view! { <div class="flex items-start gap-2 rounded-md border px-3 py-2 text-sm chip-danger"><Icon name="alert-triangle" class="w-4 h-4 mt-0.5 shrink-0" /><span>{move || error.get()}</span></div> })}
            <div class="rounded-md border border-hast-border bg-hast-elevated/40 p-3 space-y-2">
                <div class="text-sm font-medium text-hast-text">"Link this browser"</div>
                <p class="text-xs leading-relaxed text-hast-muted">"Already signed in on another browser? There, open Account and press Link a new browser, then type the code it shows. This browser gets keys of its own, and nobody sees a recovery."</p>
                <input class=format!("{INPUT} hast-input font-mono") placeholder="Code, e.g. 7k2mq-x9a4f" aria-label="Link code" autocomplete="off" spellcheck="false"
                    prop:value=move || code.get() on:input=move |e| code.set(event_target_value(&e)) />
                <input class=format!("{INPUT} hast-input") placeholder="Name for this browser, e.g. Phone" aria-label="Name for this browser" maxlength="40"
                    prop:value=move || device_name.get() on:input=move |e| device_name.set(event_target_value(&e)) on:keydown=move |e| if e.key() == "Enter" { link() } />
                <button class=format!("{BTN} {BTN_DEFAULT} w-full") disabled=move || busy.get() || password.get().is_empty() || code.get().trim().is_empty() || device_name.get().trim().is_empty() on:click=move |_| link()>
                    {move || if linking.get() { "Linking..." } else { "Link this browser" }}
                </button>
            </div>
            <p class="text-xs leading-relaxed text-hast-muted">"No other browser? You can create new keys here. The server records them as an account recovery, everyone you talk to will see that your keys were replaced that way, and your other browsers stop working until you link them again. Messages sealed to your old keys cannot be read here."</p>
            <div class="flex gap-2">
                <button class=format!("{BTN} {BTN_OUTLINE} flex-1") on:click=move |_| { spawn_local(logout(auth)); }>"Sign out"</button>
                <button class=format!("{BTN} {BTN_DEFAULT} flex-1") disabled=move || busy.get() || password.get().is_empty() on:click=move |_| go()>
                    {move || if busy.get() { "Creating key..." } else { "Create new key" }}
                </button>
            </div>
            <div class="border-t border-hast-border pt-4 space-y-2">
                <p class="text-xs leading-relaxed text-hast-muted">"Moving from another browser? There, open LiveChat and use Export keys, then import the file here. No recovery is recorded, and recent history stays readable."</p>
                <label class=format!("{BTN} {BTN_OUTLINE} w-full cursor-pointer")>
                    "Import key file"
                    <input type="file" accept=".json,application/json" class="hidden" on:change=move |e| {
                        let Some(file) = event_target::<web_sys::HtmlInputElement>(&e).files().and_then(|f| f.get(0)) else { return };
                        let (n, alive) = (name.get_value(), alive.get_value());
                        spawn_local(async move {
                            let text = wasm_bindgen_futures::JsFuture::from(file.text()).await.ok().and_then(|t| t.as_string()).unwrap_or_default();
                            let r = import_vault(&n, &text);
                            if !is_alive(&alive) {
                                return;
                            }
                            match r {
                                Ok(()) => refresh(auth).await,
                                Err(m) => error.set(m),
                            }
                        });
                    } />
                </label>
            </div>
        </div>
    })
}
