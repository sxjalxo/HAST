//! Passkeys (WebAuthn) as a second sign-in factor.
//!
//! * Registering (signed in): `POST /api/passkeys/options` gives creation options with a one-time challenge;
//!   `POST /api/passkeys` checks the authenticator's answer and stores the credential's public key. Attestation is
//!   not checked (the options ask for `"none"`), so the server trusts the key, not the make of the authenticator.
//! * Signing in: once an account has a passkey, a correct password no longer starts a session. `POST /api/login`
//!   answers with a pending token and request options; `POST /api/login/passkey` starts the session only for a valid
//!   assertion. Failures count towards the same lockout as wrong passwords.
//! * Every check: the ceremony type, the one-time challenge (5 minutes), the origin (the page's `Origin`), the
//!   relying-party id hash, user presence, the signature (ES256, Ed25519 or RS256) and, when the authenticator keeps
//!   one, a signature counter that only goes up (a passkey that went backwards may have been cloned).
use crate::auth::{account_json, authenticate, client_ip, err, failed, origin_ok, throttled, verify_password, Auth};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64U, Engine};
use ciborium::Value as Cbor;
use rand::RngCore;
use ring::signature::{self as sig, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

const CHALLENGE_TTL: Duration = Duration::from_secs(300);
/// COSE algorithm ids, in the order the options offer them.
const ES256: i64 = -7;
const EDDSA: i64 = -8;
const RS256: i64 = -257;
const USER_PRESENT: u8 = 0x01;
const ATTESTED: u8 = 0x40;

/// A credential's public key, as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "alg")]
pub enum CoseKey {
    /// uncompressed SEC1 point, base64url
    #[serde(rename = "ES256")]
    Es256 { point: String },
    #[serde(rename = "EdDSA")]
    Ed25519 { x: String },
    #[serde(rename = "RS256")]
    Rs256 { n: String, e: String },
}

/// A challenge waiting for its answer: registering (`reg:<account id>`) or signing in (`login:<token>`).
pub struct Pending {
    pub account_id: i64,
    pub challenge: String,
    pub expires: Instant,
}

fn int_key(map: &[(Cbor, Cbor)], key: i64) -> Option<&Cbor> {
    map.iter().find(|(k, _)| k.as_integer().map(i128::from) == Some(key as i128)).map(|(_, v)| v)
}

fn int_of(v: Option<&Cbor>) -> Option<i64> {
    v?.as_integer().and_then(|i| i64::try_from(i128::from(i)).ok())
}

fn bytes_of(v: Option<&Cbor>) -> Option<&[u8]> {
    v?.as_bytes().map(Vec::as_slice)
}

/// A COSE_Key the server can check signatures with.
fn parse_cose(v: &Cbor) -> Result<CoseKey, &'static str> {
    let m = v.as_map().ok_or("malformed credential key")?;
    let (kty, alg) = (int_of(int_key(m, 1)), int_of(int_key(m, 3)));
    match (kty, alg) {
        (Some(2), Some(ES256)) if int_of(int_key(m, -1)) == Some(1) => {
            let (x, y) = (bytes_of(int_key(m, -2)), bytes_of(int_key(m, -3)));
            match (x, y) {
                (Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => Ok(CoseKey::Es256 {
                    point: B64U.encode([&[4u8][..], x, y].concat()),
                }),
                _ => Err("malformed P-256 key"),
            }
        }
        (Some(1), Some(EDDSA)) if int_of(int_key(m, -1)) == Some(6) => match bytes_of(int_key(m, -2)) {
            Some(x) if x.len() == 32 => Ok(CoseKey::Ed25519 { x: B64U.encode(x) }),
            _ => Err("malformed Ed25519 key"),
        },
        (Some(3), Some(RS256)) => match (bytes_of(int_key(m, -1)), bytes_of(int_key(m, -2))) {
            (Some(n), Some(e)) if n.len() >= 256 && !e.is_empty() => Ok(CoseKey::Rs256 {
                n: B64U.encode(n),
                e: B64U.encode(e),
            }),
            _ => Err("RSA keys must be at least 2048 bits"),
        },
        _ => Err("unsupported passkey algorithm (use ES256, Ed25519 or RS256)"),
    }
}

struct AuthData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    /// (credential id, public key), present when registering
    attested: Option<(Vec<u8>, CoseKey)>,
}

fn parse_auth_data(b: &[u8]) -> Result<AuthData, &'static str> {
    if b.len() < 37 {
        return Err("authenticator data too short");
    }
    let flags = b[32];
    let attested = if flags & ATTESTED != 0 {
        let rest = &b[37..];
        let len = rest.get(16..18).map(|l| u16::from_be_bytes([l[0], l[1]]) as usize).ok_or("malformed credential data")?;
        let id = rest.get(18..18 + len).ok_or("malformed credential id")?.to_vec();
        let mut key_bytes = std::io::Cursor::new(&rest[18 + len..]);
        let key: Cbor = ciborium::de::from_reader(&mut key_bytes).map_err(|_| "malformed credential key")?;
        Some((id, parse_cose(&key)?))
    } else {
        None
    };
    Ok(AuthData {
        rp_id_hash: b[..32].try_into().unwrap_or_default(),
        flags,
        sign_count: u32::from_be_bytes([b[33], b[34], b[35], b[36]]),
        attested,
    })
}

/// What the browser says it did: the right ceremony, for our challenge, on our origin.
fn check_client_data(json: &[u8], kind: &str, challenge: &str, origin: &str) -> Result<(), &'static str> {
    let v: Value = serde_json::from_slice(json).map_err(|_| "malformed client data")?;
    if v["type"] != kind {
        return Err("wrong WebAuthn ceremony");
    }
    if v["challenge"].as_str().map(|c| c.trim_end_matches('=')) != Some(challenge) {
        return Err("challenge does not match");
    }
    if v["origin"].as_str() != Some(origin) || v["crossOrigin"] == true {
        return Err("origin does not match");
    }
    Ok(())
}

fn check_auth_data(ad: &AuthData, rp_id: &str) -> Result<(), &'static str> {
    if ad.rp_id_hash[..] != Sha256::digest(rp_id.as_bytes())[..] {
        return Err("the passkey belongs to another site");
    }
    if ad.flags & USER_PRESENT == 0 {
        return Err("the authenticator did not confirm user presence");
    }
    Ok(())
}

/// Checks a registration answer; returns the credential id, its public key and its signature counter.
pub fn verify_registration(
    rp_id: &str,
    origin: &str,
    challenge: &str,
    client_data_json: &[u8],
    attestation_object: &[u8],
    claimed_id: &[u8],
) -> Result<(Vec<u8>, CoseKey, u32), &'static str> {
    check_client_data(client_data_json, "webauthn.create", challenge, origin)?;
    let att: Cbor = ciborium::de::from_reader(attestation_object).map_err(|_| "malformed attestation")?;
    let auth_data = att
        .as_map()
        .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("authData")))
        .and_then(|(_, v)| v.as_bytes())
        .ok_or("attestation has no authenticator data")?;
    let ad = parse_auth_data(auth_data)?;
    check_auth_data(&ad, rp_id)?;
    let (id, key) = ad.attested.ok_or("no credential in the attestation")?;
    if id != claimed_id {
        return Err("credential id does not match");
    }
    Ok((id, key, ad.sign_count))
}

fn signature_ok(key: &CoseKey, message: &[u8], signature: &[u8]) -> bool {
    let d = |s: &str| B64U.decode(s).ok();
    match key {
        CoseKey::Es256 { point } => d(point).is_some_and(|p| UnparsedPublicKey::new(&sig::ECDSA_P256_SHA256_ASN1, p).verify(message, signature).is_ok()),
        CoseKey::Ed25519 { x } => d(x).is_some_and(|x| UnparsedPublicKey::new(&sig::ED25519, x).verify(message, signature).is_ok()),
        CoseKey::Rs256 { n, e } => match (d(n), d(e)) {
            (Some(n), Some(e)) => RsaPublicKeyComponents { n: &n, e: &e }.verify(&sig::RSA_PKCS1_2048_8192_SHA256, message, signature).is_ok(),
            _ => false,
        },
    }
}

/// Checks a sign-in answer against a stored credential; returns the new signature counter.
#[allow(clippy::too_many_arguments)]
pub fn verify_assertion(
    rp_id: &str,
    origin: &str,
    challenge: &str,
    key: &CoseKey,
    stored_count: u32,
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
) -> Result<u32, &'static str> {
    check_client_data(client_data_json, "webauthn.get", challenge, origin)?;
    let ad = parse_auth_data(authenticator_data)?;
    check_auth_data(&ad, rp_id)?;
    let signed = [authenticator_data, &Sha256::digest(client_data_json)[..]].concat();
    if !signature_ok(key, &signed, signature) {
        return Err("the passkey's signature does not verify");
    }
    // authenticators that keep no counter always send 0
    if (ad.sign_count != 0 || stored_count != 0) && ad.sign_count <= stored_count {
        return Err("the passkey's counter went backwards (it may have been copied)");
    }
    Ok(ad.sign_count)
}

fn new_challenge() -> String {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    B64U.encode(raw)
}

/// The relying-party id: `HAST_RP_ID`, or the host the request was made to (without its port).
fn rp_id(a: &Auth, headers: &HeaderMap) -> String {
    if let Some(id) = &a.cfg.rp_id {
        return id.clone();
    }
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or_default();
    match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default().to_string(),
        None => host.split(':').next().unwrap_or_default().to_string(),
    }
}

fn origin_of(headers: &HeaderMap) -> Option<String> {
    headers.get(header::ORIGIN).and_then(|o| o.to_str().ok()).map(String::from)
}

impl Auth {
    fn put_pending(&self, key: String, account_id: i64, challenge: String) {
        let mut p = self.pending.lock().unwrap();
        p.retain(|_, v| v.expires > Instant::now());
        p.insert(
            key,
            Pending {
                account_id,
                challenge,
                expires: Instant::now() + CHALLENGE_TTL,
            },
        );
    }

    /// One use only, and only while fresh.
    fn take_pending(&self, key: &str) -> Option<Pending> {
        self.pending.lock().unwrap().remove(key).filter(|p| p.expires > Instant::now())
    }
}

/// Sign-in step two, when the password was right and the account has passkeys: what the browser needs to ask for one.
pub fn login_challenge(a: &Auth, headers: &HeaderMap, account_id: i64) -> Response {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = hex::encode(raw);
    let challenge = new_challenge();
    a.put_pending(format!("login:{token}"), account_id, challenge.clone());
    let allow: Vec<Value> = a.db.passkeys(account_id).into_iter().map(|p| json!({ "type": "public-key", "id": p.cred_id })).collect();
    Json(json!({
        "passkey": {
            "pending": token,
            "options": { "challenge": challenge, "rpId": rp_id(a, headers), "allowCredentials": allow, "userVerification": "preferred", "timeout": 60000 },
        }
    }))
    .into_response()
}

pub fn router(a: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/passkeys", post(register_finish).get(list))
        .route("/api/passkeys/options", post(register_options))
        .route("/api/passkeys/:id", delete(remove))
        .route("/api/login/passkey", post(login_finish))
        .with_state(a)
}

async fn list(State(a): State<Arc<Auth>>, headers: HeaderMap) -> Response {
    let Some((acc, _)) = authenticate(&a, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let keys: Vec<Value> =
        a.db.passkeys(acc.id)
            .into_iter()
            .map(|p| json!({ "id": p.cred_id, "name": p.name, "createdAt": p.created_at }))
            .collect();
    Json(json!({ "passkeys": keys })).into_response()
}

async fn register_options(State(a): State<Arc<Auth>>, headers: HeaderMap) -> Response {
    if !origin_ok(&a, &headers) {
        return err(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    let Some((acc, _)) = authenticate(&a, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let challenge = new_challenge();
    a.put_pending(format!("reg:{}", acc.id), acc.id, challenge.clone());
    let exclude: Vec<Value> = a.db.passkeys(acc.id).into_iter().map(|p| json!({ "type": "public-key", "id": p.cred_id })).collect();
    Json(json!({
        "challenge": challenge,
        "rp": { "id": rp_id(&a, &headers), "name": "HAST" },
        "user": { "id": B64U.encode(acc.id.to_be_bytes()), "name": acc.username, "displayName": acc.username },
        "pubKeyCredParams": ([ES256, EDDSA, RS256].map(|alg| json!({ "type": "public-key", "alg": alg }))),
        "excludeCredentials": exclude,
        "authenticatorSelection": { "residentKey": "discouraged", "userVerification": "preferred" },
        "attestation": "none",
        "timeout": 60000,
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterBody {
    name: Option<String>,
    id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    attestation_object: String,
}

async fn register_finish(State(a): State<Arc<Auth>>, headers: HeaderMap, Json(b): Json<RegisterBody>) -> Response {
    if !origin_ok(&a, &headers) {
        return err(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    let Some((acc, _)) = authenticate(&a, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let (Some(origin), Some(pending)) = (origin_of(&headers), a.take_pending(&format!("reg:{}", acc.id))) else {
        return err(StatusCode::BAD_REQUEST, "no passkey registration in progress (or it expired)");
    };
    let d = |s: &str| B64U.decode(s.trim_end_matches('=')).unwrap_or_default();
    let checked = verify_registration(
        &rp_id(&a, &headers),
        &origin,
        &pending.challenge,
        &d(&b.client_data_json),
        &d(&b.attestation_object),
        &d(&b.id),
    );
    let (id, key, count) = match checked {
        Ok(c) => c,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    let name: String = b.name.unwrap_or_default().trim().chars().filter(|c| !c.is_control()).take(60).collect();
    let name = if name.is_empty() { "Passkey".to_string() } else { name };
    match a.db.add_passkey(acc.id, &B64U.encode(&id), &serde_json::to_string(&key).unwrap_or_default(), count, &name) {
        Ok(()) => (StatusCode::CREATED, Json(json!({ "id": B64U.encode(&id), "name": name }))).into_response(),
        Err(e) => err(StatusCode::CONFLICT, &e),
    }
}

#[derive(Deserialize)]
struct PasswordOnly {
    password: String,
}

/// Removing a passkey weakens sign-in, so it needs the password again.
async fn remove(State(a): State<Arc<Auth>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap, Path(id): Path<String>, Json(b): Json<PasswordOnly>) -> Response {
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
    if !tokio::task::spawn_blocking(move || verify_password(&b.password, &hash)).await.unwrap() {
        return failed(&a, &key, ip);
    }
    if a.db.remove_passkey(acc.id, &id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        err(StatusCode::NOT_FOUND, "no such passkey")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginPasskeyBody {
    pending: String,
    id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

async fn login_finish(State(a): State<Arc<Auth>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(b): Json<LoginPasskeyBody>) -> Response {
    if !origin_ok(&a, &headers) {
        return err(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    let ip = client_ip(&a.cfg, addr.ip(), &headers);
    let (Some(origin), Some(pending)) = (origin_of(&headers), a.take_pending(&format!("login:{}", b.pending))) else {
        return err(StatusCode::UNAUTHORIZED, "sign-in expired: enter your password again");
    };
    let Some(acc) = a.db.account(pending.account_id) else {
        return err(StatusCode::UNAUTHORIZED, "sign-in expired: enter your password again");
    };
    let key = format!("u:{}", acc.username.to_lowercase());
    if let Some(r) = throttled(&a, &key, ip) {
        return r;
    }
    let d = |s: &str| B64U.decode(s.trim_end_matches('=')).unwrap_or_default();
    let stored = a.db.passkeys(acc.id).into_iter().find(|p| p.cred_id == b.id.trim_end_matches('='));
    let checked = stored.as_ref().ok_or("not a passkey of this account").and_then(|p| {
        let k: CoseKey = serde_json::from_str(&p.public_key).map_err(|_| "stored passkey is damaged")?;
        verify_assertion(
            &rp_id(&a, &headers),
            &origin,
            &pending.challenge,
            &k,
            p.sign_count,
            &d(&b.client_data_json),
            &d(&b.authenticator_data),
            &d(&b.signature),
        )
    });
    let count = match checked {
        Ok(c) => c,
        Err(e) => {
            failed(&a, &key, ip);
            return err(StatusCode::UNAUTHORIZED, e);
        }
    };
    if let Some(p) = stored {
        a.db.set_passkey_count(&p.cred_id, count);
    }
    a.record_success(&key);
    let token = a.issue_session(acc.id);
    let mut r = Json(account_json(&a, &acc)).into_response();
    r.headers_mut().insert(header::SET_COOKIE, a.cookie(&token, a.cfg.session_ttl_secs));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cbor(v: &Cbor) -> Vec<u8> {
        let mut out = vec![];
        ciborium::ser::into_writer(v, &mut out).unwrap();
        out
    }

    fn ec_key(x: &[u8], y: &[u8]) -> Cbor {
        Cbor::Map(vec![
            (1.into(), 2.into()),
            (3.into(), ES256.into()),
            ((-1).into(), 1.into()),
            ((-2).into(), Cbor::Bytes(x.to_vec())),
            ((-3).into(), Cbor::Bytes(y.to_vec())),
        ])
    }

    #[test]
    fn keys_parse_only_for_supported_algorithms() {
        assert!(matches!(parse_cose(&ec_key(&[1; 32], &[2; 32])), Ok(CoseKey::Es256 { .. })));
        assert!(parse_cose(&ec_key(&[1; 31], &[2; 32])).is_err(), "short coordinate");
        let ed = Cbor::Map(vec![
            (1.into(), 1.into()),
            (3.into(), EDDSA.into()),
            ((-1).into(), 6.into()),
            ((-2).into(), Cbor::Bytes(vec![7; 32])),
        ]);
        assert!(matches!(parse_cose(&ed), Ok(CoseKey::Ed25519 { .. })));
        let weak_rsa = Cbor::Map(vec![
            (1.into(), 3.into()),
            (3.into(), RS256.into()),
            ((-1).into(), Cbor::Bytes(vec![1; 128])),
            ((-2).into(), Cbor::Bytes(vec![1, 0, 1])),
        ]);
        assert!(parse_cose(&weak_rsa).is_err(), "1024-bit RSA");
        let other = Cbor::Map(vec![(1.into(), 2.into()), (3.into(), (-35).into())]);
        assert!(parse_cose(&other).is_err(), "ES384 is not offered");
    }

    #[test]
    fn client_data_must_match_ceremony_challenge_and_origin() {
        let cd = |t: &str, c: &str, o: &str| json!({ "type": t, "challenge": c, "origin": o }).to_string();
        assert!(check_client_data(cd("webauthn.get", "abc", "https://h").as_bytes(), "webauthn.get", "abc", "https://h").is_ok());
        assert!(check_client_data(cd("webauthn.create", "abc", "https://h").as_bytes(), "webauthn.get", "abc", "https://h").is_err());
        assert!(check_client_data(cd("webauthn.get", "abd", "https://h").as_bytes(), "webauthn.get", "abc", "https://h").is_err());
        assert!(check_client_data(cd("webauthn.get", "abc", "https://evil").as_bytes(), "webauthn.get", "abc", "https://h").is_err());
        let cross = json!({ "type": "webauthn.get", "challenge": "abc", "origin": "https://h", "crossOrigin": true }).to_string();
        assert!(check_client_data(cross.as_bytes(), "webauthn.get", "abc", "https://h").is_err());
    }

    #[test]
    fn authenticator_data_is_bound_to_the_site_and_needs_presence() {
        let mut ad = Sha256::digest(b"example.org").to_vec();
        ad.push(USER_PRESENT);
        ad.extend(7u32.to_be_bytes());
        let parsed = parse_auth_data(&ad).unwrap();
        assert_eq!(parsed.sign_count, 7);
        assert!(check_auth_data(&parsed, "example.org").is_ok());
        assert!(check_auth_data(&parsed, "evil.org").is_err());
        ad[32] = 0;
        assert!(check_auth_data(&parse_auth_data(&ad).unwrap(), "example.org").is_err());
        assert!(parse_auth_data(&ad[..20]).is_err());
    }

    #[test]
    fn registration_and_assertion_with_a_software_authenticator() {
        use ring::{rand::SystemRandom, signature::EcdsaKeyPair, signature::KeyPair};
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&sig::ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&sig::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let pk = kp.public_key().as_ref();
        let (rp, origin, cred_id) = ("example.org", "https://example.org", vec![9u8; 16]);

        let mut ad = Sha256::digest(rp.as_bytes()).to_vec();
        ad.push(USER_PRESENT | ATTESTED);
        ad.extend(0u32.to_be_bytes());
        ad.extend([0u8; 16]);
        ad.extend((cred_id.len() as u16).to_be_bytes());
        ad.extend(&cred_id);
        ad.extend(cbor(&ec_key(&pk[1..33], &pk[33..])));
        let att = cbor(&Cbor::Map(vec![
            ("fmt".into(), "none".into()),
            ("attStmt".into(), Cbor::Map(vec![])),
            ("authData".into(), Cbor::Bytes(ad)),
        ]));
        let cd = json!({ "type": "webauthn.create", "challenge": "c1", "origin": origin }).to_string();
        let (id, key, count) = verify_registration(rp, origin, "c1", cd.as_bytes(), &att, &cred_id).unwrap();
        assert_eq!((id, count), (cred_id.clone(), 0));
        assert!(verify_registration(rp, origin, "c1", cd.as_bytes(), &att, &[1; 16]).is_err(), "another credential's id");

        let assert = |count: u32, challenge: &str| {
            let mut ad = Sha256::digest(rp.as_bytes()).to_vec();
            ad.push(USER_PRESENT);
            ad.extend(count.to_be_bytes());
            let cd = json!({ "type": "webauthn.get", "challenge": challenge, "origin": origin }).to_string();
            let s = kp.sign(&rng, &[&ad[..], &Sha256::digest(cd.as_bytes())[..]].concat()).unwrap();
            (cd, ad, s.as_ref().to_vec())
        };
        let (cd, ad, s) = assert(5, "c2");
        assert_eq!(verify_assertion(rp, origin, "c2", &key, 0, cd.as_bytes(), &ad, &s), Ok(5));
        assert!(verify_assertion(rp, origin, "c2", &key, 5, cd.as_bytes(), &ad, &s).is_err(), "counter must go up");
        let mut forged = s.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(verify_assertion(rp, origin, "c2", &key, 0, cd.as_bytes(), &ad, &forged).is_err());
        assert!(verify_assertion(rp, origin, "c3", &key, 0, cd.as_bytes(), &ad, &s).is_err(), "another challenge");
    }
}
