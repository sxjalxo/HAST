//! The browser's WebAuthn API (`navigator.credentials`), taking the server's options and returning its answers as
//! JSON, with binary fields as base64url (see `hast_server::passkey`).
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64U, Engine};
use js_sys::{Object, Reflect, Uint8Array, JSON};
use serde_json::{json, Value};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

fn bytes(b64: &str) -> JsValue {
    Uint8Array::from(B64U.decode(b64.trim_end_matches('=')).unwrap_or_default().as_slice()).into()
}

fn b64(buffer: &JsValue) -> String {
    B64U.encode(Uint8Array::new(buffer).to_vec())
}

fn get(o: &JsValue, key: &str) -> JsValue {
    Reflect::get(o, &key.into()).unwrap_or(JsValue::UNDEFINED)
}

fn set(o: &JsValue, key: &str, v: &JsValue) {
    let _ = Reflect::set(o, &key.into(), v);
}

/// The server's options as the JS object WebAuthn wants: the same JSON, with ids and the challenge as bytes.
fn options(server: &Value) -> Result<JsValue, String> {
    let o = JSON::parse(&server.to_string()).map_err(|_| "malformed passkey options".to_string())?;
    set(&o, "challenge", &bytes(server["challenge"].as_str().unwrap_or_default()));
    if let Some(id) = server["user"]["id"].as_str() {
        set(&get(&o, "user"), "id", &bytes(id));
    }
    for list in ["excludeCredentials", "allowCredentials"] {
        for (i, item) in server[list].as_array().into_iter().flatten().enumerate() {
            let entry = Reflect::get_u32(&get(&o, list), i as u32).unwrap_or(JsValue::UNDEFINED);
            set(&entry, "id", &bytes(item["id"].as_str().unwrap_or_default()));
        }
    }
    let wrapper = Object::new();
    set(&wrapper, "publicKey", &o);
    Ok(wrapper.into())
}

/// A message a person can act on, from a WebAuthn `DOMException`.
fn explain(e: JsValue) -> String {
    match get(&e, "name").as_string().unwrap_or_default().as_str() {
        "NotAllowedError" => "The passkey request was cancelled or timed out".into(),
        "InvalidStateError" => "This authenticator already holds a passkey for your account".into(),
        "NotSupportedError" => "This browser or authenticator can't make a supported passkey".into(),
        "SecurityError" => "Passkeys need HTTPS (or localhost) on the site's own name".into(),
        _ => get(&e, "message").as_string().unwrap_or_else(|| "The passkey request failed".into()),
    }
}

fn credentials() -> Result<web_sys::CredentialsContainer, String> {
    web_sys::window().map(|w| w.navigator().credentials()).ok_or_else(|| "no browser window".into())
}

/// Does this browser have WebAuthn at all?
pub fn supported() -> bool {
    web_sys::window().is_some_and(|w| Reflect::has(&w, &"PublicKeyCredential".into()).unwrap_or(false))
}

/// Make a passkey: `{id, clientDataJSON, attestationObject}` for `POST /api/passkeys`.
pub async fn create(server: &Value) -> Result<Value, String> {
    let promise = credentials()?.create_with_options(options(server)?.unchecked_ref()).map_err(explain)?;
    let cred = JsFuture::from(promise).await.map_err(explain)?;
    let r = get(&cred, "response");
    Ok(json!({
        "id": b64(&get(&cred, "rawId")),
        "clientDataJSON": b64(&get(&r, "clientDataJSON")),
        "attestationObject": b64(&get(&r, "attestationObject")),
    }))
}

/// Use a passkey: `{id, clientDataJSON, authenticatorData, signature}` for `POST /api/login/passkey`.
pub async fn assert(server: &Value) -> Result<Value, String> {
    let promise = credentials()?.get_with_options(options(server)?.unchecked_ref()).map_err(explain)?;
    let cred = JsFuture::from(promise).await.map_err(explain)?;
    let r = get(&cred, "response");
    Ok(json!({
        "id": b64(&get(&cred, "rawId")),
        "clientDataJSON": b64(&get(&r, "clientDataJSON")),
        "authenticatorData": b64(&get(&r, "authenticatorData")),
        "signature": b64(&get(&r, "signature")),
    }))
}
