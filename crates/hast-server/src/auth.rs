//! Accounts and sessions.
//!
//! * Password: Argon2id, per-account salt, constant work for unknown users (a dummy hash is verified).
//! * Session: random 256-bit token in an `HttpOnly; SameSite=Strict` cookie; only its SHA-256 is stored.
//! * Brute force: failed logins lock a name (and an IP, more leniently) for exponentially longer. Behind a
//!   reverse proxy listed in `trusted_proxies`, the IP is taken from `X-Forwarded-For`.
//! * CSRF: browsers always send `Origin` on cross-site POSTs and WebSocket upgrades; it must match `Host`.
//! * Passkeys: once an account has one, the password alone no longer signs in (see `passkey`).
//! * Keys: signup carries a registration link proving the owner holds the first HBSS key and the long-term
//!   SLH-DSA key; recovery (password login on a device without the keys) appends a server-vouched, visibly
//!   flagged link to the chain.
use crate::db::{Account, CreateError, Db};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hast_core::{
    identity::{self, ChainLink, LinkKind},
    pq,
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const COOKIE: &str = "hast_session";
const MIN_PASSWORD_CHARS: usize = 10;
const MAX_PASSWORD_CHARS: usize = 256;
const NAME_FREE_FAILURES: u32 = 4;
const IP_FREE_FAILURES: u32 = 20;
const MAX_LOCK_SECS: u64 = 300;
const SIGNUPS_PER_IP_PER_HOUR: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signup {
    Open,
    Invite,
    Closed,
}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub signup: Signup,
    pub invite_code: Option<String>,
    /// add `Secure` to the cookie (turn on behind HTTPS)
    pub cookie_secure: bool,
    pub session_ttl_secs: u64,
    /// extra `Origin` values allowed besides the request's own host (e.g. a dev proxy)
    pub extra_origins: Vec<String>,
    /// reverse proxies whose `X-Forwarded-For` is believed
    pub trusted_proxies: Vec<IpAddr>,
    /// WebAuthn relying-party id (the site's domain); `None` uses the request's host
    pub rp_id: Option<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            signup: Signup::Open,
            invite_code: None,
            cookie_secure: false,
            session_ttl_secs: 7 * 24 * 3600,
            extra_origins: vec![],
            trusted_proxies: vec![],
            rp_id: None,
        }
    }
}

struct Throttle {
    fails: u32,
    locked_until: Option<Instant>,
    last: Instant,
}

pub struct Auth {
    pub db: Db,
    pub cfg: AuthConfig,
    throttle: Mutex<HashMap<String, Throttle>>,
    signups: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    dummy_hash: String,
    /// passkey challenges waiting for their answer
    pub(crate) pending: Mutex<HashMap<String, crate::passkey::Pending>>,
    /// device link offers, by account
    pub(crate) offers: Mutex<HashMap<i64, crate::devices::Offer>>,
}

impl Auth {
    pub fn new(db: Db, cfg: AuthConfig) -> Arc<Auth> {
        db.purge_expired_sessions();
        Arc::new(Auth {
            db,
            cfg,
            throttle: Default::default(),
            signups: Default::default(),
            dummy_hash: hash_password("a password nobody has chosen"),
            pending: Default::default(),
            offers: Default::default(),
        })
    }

    fn locked_for(&self, key: &str) -> Option<u64> {
        let t = self.throttle.lock().unwrap();
        let until = t.get(key)?.locked_until?;
        until.checked_duration_since(Instant::now()).map(|d| d.as_secs() + 1)
    }

    fn record_failure(&self, key: &str, free: u32) {
        let mut t = self.throttle.lock().unwrap();
        if t.len() > 10_000 {
            t.retain(|_, v| v.last.elapsed() < Duration::from_secs(3600));
        }
        let e = t.entry(key.to_string()).or_insert(Throttle {
            fails: 0,
            locked_until: None,
            last: Instant::now(),
        });
        e.fails += 1;
        e.last = Instant::now();
        if e.fails > free {
            let secs = (1u64 << (e.fails - free - 1).min(20)).min(MAX_LOCK_SECS);
            e.locked_until = Some(Instant::now() + Duration::from_secs(secs));
        }
    }

    pub(crate) fn record_success(&self, key: &str) {
        self.throttle.lock().unwrap().remove(key);
    }

    pub(crate) fn issue_session(&self, account_id: i64) -> String {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = hex::encode(raw);
        self.db.new_session(account_id, &hash_token(&token), self.cfg.session_ttl_secs);
        token
    }

    pub(crate) fn cookie(&self, token: &str, max_age: u64) -> HeaderValue {
        let secure = if self.cfg.cookie_secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!("{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}")).unwrap()
    }
}

pub fn hash_password(pw: &str) -> String {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let salt = SaltString::encode_b64(&salt).expect("salt");
    Argon2::default().hash_password(pw.as_bytes(), &salt).expect("argon2").to_string()
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn token_from(headers: &HeaderMap) -> Option<String> {
    let all = headers.get(header::COOKIE)?.to_str().ok()?;
    all.split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty())
}

/// The account behind the request's session cookie, if any (and the stored token hash, for logout).
pub fn authenticate(a: &Auth, headers: &HeaderMap) -> Option<(Account, String)> {
    let th = hash_token(&token_from(headers)?);
    a.db.session(&th, a.cfg.session_ttl_secs).map(|acc| (acc, th))
}

/// The client's address: the peer, unless the peer is a trusted proxy, in which case the right-most
/// `X-Forwarded-For` entry that is not itself a trusted proxy (entries further left are client-controlled).
pub fn client_ip(cfg: &AuthConfig, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    if !cfg.trusted_proxies.contains(&peer) {
        return peer;
    }
    let hops: Vec<IpAddr> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|ip| ip.trim().parse().ok())
        .collect();
    hops.into_iter().rev().find(|ip| !cfg.trusted_proxies.contains(ip)).unwrap_or(peer)
}

/// Cross-site requests from browsers carry an `Origin` that differs from `Host`; refuse them.
/// Requests without `Origin` (curl, native clients, same-origin GETs) cannot be CSRF.
pub fn origin_ok(a: &Auth, headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else { return true };
    let origin = origin.to_str().unwrap_or("");
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    origin.split_once("://").is_some_and(|(_, h)| h == host) || a.cfg.extra_origins.iter().any(|o| o == origin)
}

pub(crate) fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn too_many(secs: u64) -> Response {
    let mut r = err(StatusCode::TOO_MANY_REQUESTS, "too many attempts, try again later");
    r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(secs));
    r
}

fn valid_username(u: &str) -> bool {
    (3..=32).contains(&u.chars().count()) && u.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn valid_password(p: &str) -> Result<(), &'static str> {
    match p.chars().count() {
        n if n < MIN_PASSWORD_CHARS => Err("password must be at least 10 characters"),
        n if n > MAX_PASSWORD_CHARS => Err("password is too long"),
        _ => Ok(()),
    }
}

pub fn router(a: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/recover", post(recover))
        .route("/api/password", post(change_password))
        .route("/api/me", get(me))
        .route("/api/keys/:name", get(keys))
        .route("/api/directory", get(directory))
        .with_state(a)
}

#[derive(Deserialize)]
struct RegisterBody {
    username: String,
    password: String,
    link: ChainLink,
    invite: Option<String>,
}

/// What the client needs about its own account: name, the primary device's current keys (its SLH-DSA key is the
/// identity key) and every active device's, so a browser can tell whether it holds the current keys of one.
pub(crate) fn account_json(a: &Auth, acc: &Account) -> serde_json::Value {
    let head = a.db.head_link(acc.id).unwrap_or_default();
    let devices: Vec<_> =
        a.db.active_heads(acc.id)
            .into_iter()
            .map(|(device, l)| json!({ "device": device, "commitment": l.root, "kem": l.kem }))
            .collect();
    json!({ "username": acc.username, "commitment": head.root, "slh": head.slh, "kem": head.kem, "devices": devices })
}

async fn register(State(a): State<Arc<Auth>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(b): Json<RegisterBody>) -> Response {
    let ip = client_ip(&a.cfg, addr.ip(), &headers);
    if !origin_ok(&a, &headers) {
        return err(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    match a.cfg.signup {
        Signup::Closed => return err(StatusCode::FORBIDDEN, "signup is disabled"),
        Signup::Invite if a.cfg.invite_code.as_deref().is_none_or(|c| b.invite.as_deref() != Some(c)) => return err(StatusCode::FORBIDDEN, "a valid invite code is required"),
        _ => {}
    }
    {
        let mut s = a.signups.lock().unwrap();
        let recent = s.entry(ip).or_default();
        recent.retain(|t| t.elapsed() < Duration::from_secs(3600));
        if recent.len() >= SIGNUPS_PER_IP_PER_HOUR {
            return too_many(3600);
        }
        recent.push(Instant::now());
    }
    if !valid_username(&b.username) {
        return err(StatusCode::BAD_REQUEST, "username must be 3-32 characters: letters, digits, _ or -");
    }
    if let Err(m) = valid_password(&b.password) {
        return err(StatusCode::BAD_REQUEST, m);
    }
    // new accounts always carry long-term keys; HBSS-only registrations are only read back from old data
    if b.link.slh.is_none() || !identity::verify_registration(&b.username, &b.link) {
        return err(StatusCode::BAD_REQUEST, "registration proof does not verify");
    }
    let pw = b.password.clone();
    let hash = tokio::task::spawn_blocking(move || hash_password(&pw)).await.unwrap();
    match a.db.create_account(&b.username, &hash, &b.link) {
        Ok(acc) => {
            let token = a.issue_session(acc.id);
            let mut r = (StatusCode::CREATED, Json(account_json(&a, &acc))).into_response();
            r.headers_mut().insert(header::SET_COOKIE, a.cookie(&token, a.cfg.session_ttl_secs));
            r
        }
        Err(CreateError::UsernameTaken) => err(StatusCode::CONFLICT, "username is taken"),
        Err(CreateError::KeyTaken) => err(StatusCode::CONFLICT, "that key is already registered"),
        Err(CreateError::Other(e)) => {
            eprintln!("register: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "could not create the account")
        }
    }
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

/// Throttle check shared by every endpoint that takes a password.
pub(crate) fn throttled(a: &Auth, user_key: &str, ip: IpAddr) -> Option<Response> {
    a.locked_for(user_key).or_else(|| a.locked_for(&format!("ip:{ip}"))).map(too_many)
}

pub(crate) fn failed(a: &Auth, user_key: &str, ip: IpAddr) -> Response {
    a.record_failure(user_key, NAME_FREE_FAILURES);
    a.record_failure(&format!("ip:{ip}"), IP_FREE_FAILURES);
    err(StatusCode::UNAUTHORIZED, "invalid username or password")
}

async fn login(State(a): State<Arc<Auth>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(b): Json<LoginBody>) -> Response {
    if !origin_ok(&a, &headers) {
        return err(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    let ip = client_ip(&a.cfg, addr.ip(), &headers);
    let key = format!("u:{}", b.username.to_lowercase());
    if let Some(r) = throttled(&a, &key, ip) {
        return r;
    }
    let found = a.db.find(&b.username);
    // unknown users cost the same as known ones
    let hash = found.as_ref().map(|f| f.1.clone()).unwrap_or_else(|| a.dummy_hash.clone());
    let pw = b.password.clone();
    let ok = tokio::task::spawn_blocking(move || verify_password(&pw, &hash)).await.unwrap();
    let Some((acc, _)) = found.filter(|_| ok) else { return failed(&a, &key, ip) };
    a.record_success(&key);
    // with a passkey on the account, the password is only the first step
    if !a.db.passkeys(acc.id).is_empty() {
        return crate::passkey::login_challenge(&a, &headers, acc.id);
    }
    let token = a.issue_session(acc.id);
    let mut r = Json(account_json(&a, &acc)).into_response();
    r.headers_mut().insert(header::SET_COOKIE, a.cookie(&token, a.cfg.session_ttl_secs));
    r
}

async fn logout(State(a): State<Arc<Auth>>, headers: HeaderMap) -> Response {
    if !origin_ok(&a, &headers) {
        return err(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    if let Some((_, th)) = authenticate(&a, &headers) {
        a.db.end_session(&th);
    }
    let mut r = StatusCode::NO_CONTENT.into_response();
    r.headers_mut().insert(header::SET_COOKIE, a.cookie("", 0));
    r
}

async fn me(State(a): State<Arc<Auth>>, headers: HeaderMap) -> Response {
    match authenticate(&a, &headers) {
        Some((acc, _)) => Json(account_json(&a, &acc)).into_response(),
        None => err(StatusCode::UNAUTHORIZED, "not signed in"),
    }
}

#[derive(Deserialize)]
struct KeysQuery {
    since: Option<String>,
    device: Option<String>,
}

/// One device's key chain (`?device=`, the primary one by default). With `?since=<root>`, only the links after that
/// root (`"full": false`); if the root is not in the chain, the whole chain (`"full": true`).
async fn keys(State(a): State<Arc<Auth>>, headers: HeaderMap, Path(name): Path<String>, Query(q): Query<KeysQuery>) -> Response {
    if authenticate(&a, &headers).is_none() {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    }
    let Some((acc, _)) = a.db.find(&name) else {
        return err(StatusCode::NOT_FOUND, "no such account");
    };
    let device = q.device.unwrap_or_else(|| identity::PRIMARY.into());
    let chain = a.db.chain(acc.id, &device);
    if chain.is_empty() {
        return err(StatusCode::NOT_FOUND, "no such device");
    }
    let after = q.since.and_then(|r| chain.iter().position(|l| l.root == r)).map(|i| i + 1);
    match after {
        Some(i) => Json(json!({ "username": acc.username, "device": device, "chain": &chain[i..], "full": false })).into_response(),
        None => Json(json!({ "username": acc.username, "device": device, "chain": chain, "full": true })).into_response(),
    }
}

/// Every account with its primary root and its active devices' roots, so LiveChat clients know whom to encrypt to
/// (and when to refetch a chain).
async fn directory(State(a): State<Arc<Auth>>, headers: HeaderMap) -> Response {
    if authenticate(&a, &headers).is_none() {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    }
    let accounts: Vec<_> =
        a.db.directory()
            .into_iter()
            .map(|(u, h, devices)| {
                let devices: Vec<_> = devices.into_iter().map(|(d, head)| json!({ "device": d, "head": head })).collect();
                json!({ "username": u, "head": h, "devices": devices })
            })
            .collect();
    Json(json!({ "accounts": accounts })).into_response()
}

#[derive(Deserialize)]
struct RecoverBody {
    password: String,
    root: String,
    slh: String,
    kem: String,
}

/// Password login on a device that has no key for the account: the server records a new key as a recovery on the
/// primary chain. The identity key is new, so every other device (linked under the old one) is removed.
async fn recover(State(a): State<Arc<Auth>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(b): Json<RecoverBody>) -> Response {
    if !origin_ok(&a, &headers) {
        return err(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    let Some((acc, _)) = authenticate(&a, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let ip = client_ip(&a.cfg, addr.ip(), &headers);
    let key = format!("u:{}", acc.username.to_lowercase());
    if let Some(r) = throttled(&a, &key, ip) {
        return r;
    }
    let hash = a.db.find(&acc.username).map(|f| f.1).unwrap_or_default();
    let pw = b.password.clone();
    if !tokio::task::spawn_blocking(move || verify_password(&pw, &hash)).await.unwrap() {
        return failed(&a, &key, ip);
    }
    a.record_success(&key);
    if !identity::is_root(&b.root) || !pq::is_slh_pk(&b.slh) || !pq::is_kem_pk(&b.kem) {
        return err(StatusCode::BAD_REQUEST, "invalid key");
    }
    let Some(head) = a.db.head(acc.id) else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "account has no key");
    };
    let link = ChainLink {
        kind: LinkKind::Recovery,
        root: b.root.clone(),
        old_root: Some(head),
        slh: Some(b.slh),
        kem: Some(b.kem),
        ..Default::default()
    };
    match a.db.append_link(acc.id, identity::PRIMARY, &link) {
        Ok(()) => {
            a.db.recovered(acc.id);
            Json(json!({ "commitment": b.root })).into_response()
        }
        Err(e) => err(StatusCode::CONFLICT, &e),
    }
}

#[derive(Deserialize)]
struct PasswordBody {
    old: String,
    new: String,
}

async fn change_password(State(a): State<Arc<Auth>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(b): Json<PasswordBody>) -> Response {
    if !origin_ok(&a, &headers) {
        return err(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    let Some((acc, th)) = authenticate(&a, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let ip = client_ip(&a.cfg, addr.ip(), &headers);
    let key = format!("u:{}", acc.username.to_lowercase());
    if let Some(r) = throttled(&a, &key, ip) {
        return r;
    }
    if let Err(m) = valid_password(&b.new) {
        return err(StatusCode::BAD_REQUEST, m);
    }
    let hash = a.db.find(&acc.username).map(|f| f.1).unwrap_or_default();
    let old = b.old.clone();
    if !tokio::task::spawn_blocking(move || verify_password(&old, &hash)).await.unwrap() {
        return failed(&a, &key, ip);
    }
    a.record_success(&key);
    let new = b.new.clone();
    let new_hash = tokio::task::spawn_blocking(move || hash_password(&new)).await.unwrap();
    a.db.set_password(acc.id, &new_hash);
    a.db.end_sessions_except(acc.id, &th); // every other device must sign in again
    StatusCode::NO_CONTENT.into_response()
}

/// Operator action for a forgotten password (there is no email): new password, every session ended.
/// The account's key chain is untouched; a device without the key goes through recovery on its next login.
pub fn admin_reset_password(db: &Db, username: &str, new_password: &str) -> Result<(), String> {
    valid_password(new_password).map_err(String::from)?;
    let (acc, _) = db.find(username).ok_or_else(|| format!("no account named {username}"))?;
    db.set_password(acc.id, &hash_password(new_password));
    db.end_sessions_except(acc.id, "");
    Ok(())
}

/// Operator action for a lost passkey: removes all of the account's passkeys, so the password signs in alone again.
pub fn admin_remove_passkeys(db: &Db, username: &str) -> Result<usize, String> {
    let (acc, _) = db.find(username).ok_or_else(|| format!("no account named {username}"))?;
    Ok(db.remove_passkeys(acc.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_hash_verify_and_salt() {
        let h1 = hash_password("correct horse battery");
        assert!(h1.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &h1));
        assert!(!verify_password("correct horse batterz", &h1));
        assert!(!verify_password("x", "not a hash"));
        assert_ne!(h1, hash_password("correct horse battery"), "salted");
    }

    #[test]
    fn validators() {
        assert!(valid_username("Alice_01-x") && !valid_username("al") && !valid_username("a b c") && !valid_username(&"x".repeat(33)) && !valid_username("é√é"));
        assert!(valid_password("0123456789").is_ok() && valid_password("short").is_err() && valid_password(&"x".repeat(257)).is_err());
    }

    #[test]
    fn client_ip_believes_only_trusted_proxies() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let cfg = AuthConfig {
            trusted_proxies: vec![ip("10.0.0.1"), ip("10.0.0.2")],
            ..Default::default()
        };
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 1.2.3.4, 10.0.0.2".parse().unwrap());
        assert_eq!(
            client_ip(&cfg, ip("10.0.0.1"), &h),
            ip("1.2.3.4"),
            "right-most untrusted hop; the left part is client-controlled"
        );
        assert_eq!(client_ip(&cfg, ip("9.9.9.9"), &h), ip("9.9.9.9"), "headers from untrusted peers are ignored");
        assert_eq!(client_ip(&cfg, ip("10.0.0.1"), &HeaderMap::new()), ip("10.0.0.1"));
        assert_eq!(client_ip(&AuthConfig::default(), ip("10.0.0.1"), &h), ip("10.0.0.1"), "no proxies trusted by default");
    }

    #[test]
    fn cookie_parsing_and_origin_rule() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "a=1; hast_session=tok123; b=2".parse().unwrap());
        assert_eq!(token_from(&h).as_deref(), Some("tok123"));
        assert_eq!(token_from(&HeaderMap::new()), None);

        let a = Auth::new(
            Db::memory().unwrap(),
            AuthConfig {
                extra_origins: vec!["http://localhost:5173".into()],
                ..Default::default()
            },
        );
        let mk = |origin: Option<&str>| {
            let mut h = HeaderMap::new();
            h.insert(header::HOST, "localhost:8000".parse().unwrap());
            if let Some(o) = origin {
                h.insert(header::ORIGIN, o.parse().unwrap());
            }
            h
        };
        assert!(origin_ok(&a, &mk(None)));
        assert!(origin_ok(&a, &mk(Some("http://localhost:8000"))));
        assert!(origin_ok(&a, &mk(Some("http://localhost:5173"))), "configured extra origin");
        assert!(!origin_ok(&a, &mk(Some("http://evil.example"))));
        assert!(!origin_ok(&a, &mk(Some("null"))));
        assert!(!origin_ok(&a, &mk(Some("http://localhost:9999"))));
    }

    #[test]
    fn throttle_locks_after_free_failures_and_clears_on_success() {
        let a = Auth::new(Db::memory().unwrap(), AuthConfig::default());
        for _ in 0..NAME_FREE_FAILURES {
            a.record_failure("u:alice", NAME_FREE_FAILURES);
            assert!(a.locked_for("u:alice").is_none());
        }
        a.record_failure("u:alice", NAME_FREE_FAILURES);
        assert!(a.locked_for("u:alice").is_some());
        assert!(a.locked_for("u:bob").is_none(), "other names are unaffected");
        a.record_success("u:alice");
        assert!(a.locked_for("u:alice").is_none());
    }

    #[test]
    fn admin_reset_changes_the_password_and_ends_sessions() {
        let db = Db::memory().unwrap();
        let link = ChainLink {
            kind: LinkKind::Register,
            root: "a".repeat(128),
            ..Default::default()
        };
        let acc = db.create_account("alice", &hash_password("the old password"), &link).unwrap();
        db.new_session(acc.id, "tok", 1000);
        assert!(admin_reset_password(&db, "Alice", "short").is_err());
        assert!(admin_reset_password(&db, "nobody", "a long enough password").is_err());
        admin_reset_password(&db, "Alice", "a brand new password").unwrap();
        let (_, hash) = db.find("alice").unwrap();
        assert!(verify_password("a brand new password", &hash) && !verify_password("the old password", &hash));
        assert!(db.session("tok", 1000).is_none());
    }
}
