//! Devices: more than one browser per account (see `identity::verify_device`).
//!
//! * Linking: a browser that already holds the account's identity key posts a link *offer*, that key encrypted under a
//!   random code (Argon2id, XChaCha20-Poly1305) the user types on the new browser. The server keeps one offer per
//!   account for `OFFER_SECS` and never sees the code. The new browser decrypts the key, makes its own HBSS and ML-KEM
//!   keys and posts the first link of its chain, co-signed with the identity key; the server checks it like clients do.
//! * Removing: a flag. A removed device leaves the directory (nobody seals to it) and can no longer send or rotate;
//!   its chain stays so its old messages still verify. It still holds the identity key, so only a recovery (a new
//!   identity key) cuts off a device someone else has.
use crate::auth::{authenticate, err, origin_ok, Auth};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get},
    Json, Router,
};
use hast_core::identity::{self, ChainLink};
use serde::Deserialize;
use serde_json::json;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// How long a link offer waits for the new browser.
pub const OFFER_SECS: u64 = 600;
/// The encrypted identity key is a few hundred characters.
const MAX_BLOB: usize = 4096;

pub struct Offer {
    salt: String,
    blob: String,
    expires: Instant,
}

pub fn router(a: Arc<Auth>) -> Router {
    Router::new()
        .route("/api/devices", get(list).post(add))
        .route("/api/devices/offer", get(get_offer).post(post_offer))
        .route("/api/devices/:device", delete(remove))
        .with_state(a)
}

async fn list(State(a): State<Arc<Auth>>, headers: HeaderMap) -> Response {
    let Some((acc, _)) = authenticate(&a, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let devices: Vec<_> =
        a.db.devices(acc.id)
            .into_iter()
            .map(|d| json!({ "device": d.device, "name": d.name, "createdAt": d.created_at, "removed": d.removed, "head": d.head }))
            .collect();
    Json(json!({ "devices": devices })).into_response()
}

#[derive(Deserialize)]
struct OfferBody {
    salt: String,
    blob: String,
}

async fn post_offer(State(a): State<Arc<Auth>>, headers: HeaderMap, Json(b): Json<OfferBody>) -> Response {
    if !origin_ok(&a, &headers) {
        return err(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    let Some((acc, _)) = authenticate(&a, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    if b.salt.len() != 32 || !b.salt.bytes().all(|c| c.is_ascii_hexdigit()) || b.blob.is_empty() || b.blob.len() > MAX_BLOB {
        return err(StatusCode::BAD_REQUEST, "malformed offer");
    }
    let mut offers = a.offers.lock().unwrap();
    offers.retain(|_, o| o.expires > Instant::now());
    offers.insert(
        acc.id,
        Offer {
            salt: b.salt,
            blob: b.blob,
            expires: Instant::now() + Duration::from_secs(OFFER_SECS),
        },
    );
    Json(json!({ "expiresIn": OFFER_SECS })).into_response()
}

async fn get_offer(State(a): State<Arc<Auth>>, headers: HeaderMap) -> Response {
    let Some((acc, _)) = authenticate(&a, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    match a.offers.lock().unwrap().get(&acc.id).filter(|o| o.expires > Instant::now()) {
        Some(o) => Json(json!({ "salt": o.salt, "blob": o.blob })).into_response(),
        None => err(StatusCode::NOT_FOUND, "no link code is waiting: start one on a browser that is already signed in"),
    }
}

#[derive(Deserialize)]
struct AddBody {
    device: String,
    name: String,
    link: ChainLink,
}

async fn add(State(a): State<Arc<Auth>>, headers: HeaderMap, Json(b): Json<AddBody>) -> Response {
    if !origin_ok(&a, &headers) {
        return err(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    let Some((acc, _)) = authenticate(&a, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 40 || name.chars().any(char::is_control) {
        return err(StatusCode::BAD_REQUEST, "name this browser (1-40 characters)");
    }
    if b.device == identity::PRIMARY || !identity::valid_device(&b.device) {
        return err(StatusCode::BAD_REQUEST, "invalid device id");
    }
    let Some(slh) = a.db.head_link(acc.id).and_then(|h| h.slh) else {
        return err(StatusCode::CONFLICT, "open LiveChat once on your first browser to create your keys");
    };
    // the server checks what every client will check: the identity key vouches for this device
    if identity::verify_device(&acc.username, &b.device, &slh, std::slice::from_ref(&b.link)).is_err() {
        return err(StatusCode::BAD_REQUEST, "device link does not verify");
    }
    if let Err(e) = a.db.add_device(acc.id, &b.device, name, &b.link) {
        return err(StatusCode::CONFLICT, &e);
    }
    a.offers.lock().unwrap().remove(&acc.id);
    (StatusCode::CREATED, Json(json!({ "device": b.device }))).into_response()
}

async fn remove(State(a): State<Arc<Auth>>, headers: HeaderMap, Path(device): Path<String>) -> Response {
    if !origin_ok(&a, &headers) {
        return err(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    let Some((acc, _)) = authenticate(&a, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    if a.db.remove_device(acc.id, &device) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        err(StatusCode::NOT_FOUND, "no such device")
    }
}
