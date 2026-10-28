//! This browser's copy of what it decrypted: LiveChat messages (`chat:<sender>:<id>`) and messaging-page messages
//! (`messaging:<id>`), in IndexedDB, each record encrypted under a key kept in the vault (`auth::history_key`). With
//! forward secrecy the keys that opened a message are deleted, so this copy is the history: reloads read it, and the
//! server's ciphertext only fills in what arrived while the browser was away. Clearing site data deletes it.
use crate::auth;
use crate::util::now_ms;
use hast_core::pq;
use serde_json::Value;
use wasm_bindgen::{prelude::*, JsCast};
use web_sys::{IdbDatabase, IdbObjectStore, IdbRequest, IdbTransactionMode};

const STORE: &str = "records";
const DAY_MS: f64 = 24.0 * 3600.0 * 1000.0;

/// Wait for an IndexedDB request; its result, or `None` if it failed.
async fn done(req: &IdbRequest) -> Option<JsValue> {
    let p = js_sys::Promise::new(&mut |resolve, reject| {
        let ok = Closure::once_into_js(move |_: web_sys::Event| {
            let _ = resolve.call0(&JsValue::NULL);
        });
        let bad = Closure::once_into_js(move |_: web_sys::Event| {
            let _ = reject.call0(&JsValue::NULL);
        });
        req.set_onsuccess(Some(ok.unchecked_ref()));
        req.set_onerror(Some(bad.unchecked_ref()));
    });
    wasm_bindgen_futures::JsFuture::from(p).await.ok()?;
    req.result().ok()
}

async fn open(user: &str) -> Option<IdbDatabase> {
    let req = web_sys::window()?
        .indexed_db()
        .ok()??
        .open_with_u32(&format!("hast-history:{}", user.to_lowercase()), 1)
        .ok()?;
    let r = req.clone();
    let upgrade = Closure::once_into_js(move |_: web_sys::Event| {
        if let Some(db) = r.result().ok().and_then(|d| d.dyn_into::<IdbDatabase>().ok()) {
            let _ = db.create_object_store(STORE);
        }
    });
    req.set_onupgradeneeded(Some(upgrade.unchecked_ref()));
    done(&req).await?.dyn_into().ok()
}

fn store(db: &IdbDatabase) -> Option<IdbObjectStore> {
    db.transaction_with_str_and_mode(STORE, IdbTransactionMode::Readwrite).ok()?.object_store(STORE).ok()
}

/// Keep `record` (it should carry `at`, the message's time in ms, for the retention setting).
pub async fn put(user: &str, key: &str, record: &Value) {
    let Some(k) = auth::history_key(user) else { return };
    let Some(s) = open(user).await.as_ref().and_then(store) else { return };
    if let Ok(req) = s.put_with_key(&JsValue::from_str(&pq::encrypt_local(&k, &record.to_string())), &JsValue::from_str(key)) {
        done(&req).await;
    }
}

/// Every record with its key; records older than the retention setting (`auth::history_days`) are deleted instead.
pub async fn all(user: &str) -> Vec<(String, Value)> {
    let Some(k) = auth::history_key(user) else { return vec![] };
    let Some(db) = open(user).await else { return vec![] };
    let Some(s) = store(&db) else { return vec![] };
    // both requests go out before either is awaited, in one transaction
    let (Ok(kr), Ok(vr)) = (s.get_all_keys(), s.get_all()) else { return vec![] };
    let (Some(keys), Some(values)) = (done(&kr).await, done(&vr).await) else {
        return vec![];
    };
    let (keys, values) = (js_sys::Array::from(&keys), js_sys::Array::from(&values));
    let days = auth::history_days(user);
    let (mut out, mut expired) = (vec![], vec![]);
    for (key, value) in keys.iter().zip(values.iter()) {
        let Some(rec) = value
            .as_string()
            .and_then(|b| pq::decrypt_local(&k, &b))
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        else {
            continue;
        };
        if days > 0 && now_ms() - rec["at"].as_f64().unwrap_or(0.0) > days as f64 * DAY_MS {
            expired.push(key);
        } else if let Some(key) = key.as_string() {
            out.push((key, rec));
        }
    }
    if let Some(s) = store(&db) {
        for key in expired {
            let _ = s.delete(&key);
        }
    }
    out
}
