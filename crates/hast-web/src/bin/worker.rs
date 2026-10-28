//! Web Worker: runs `hast_core::jobs` off the page's thread. Requests and replies are JSON strings
//! (`{id, ...request}` in, `{id, result}` out); "ready" is posted once the module has loaded.
use wasm_bindgen::{prelude::*, JsCast};

fn main() {
    console_error_panic_hook::set_once();
    let scope: web_sys::DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let reply = scope.clone();
    let on_message = Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        let Some(text) = e.data().as_string() else { return };
        let req: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        let out = serde_json::json!({ "id": req["id"], "result": hast_core::jobs::run(&req) });
        let _ = reply.post_message(&JsValue::from_str(&out.to_string()));
    });
    scope.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
    let _ = scope.post_message(&JsValue::from_str("ready"));
}
