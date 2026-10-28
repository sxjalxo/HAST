//! Expensive crypto (`hast_core::jobs`) runs in a Web Worker (`src/bin/worker.rs`), so key derivation, SLH-DSA and
//! chain checks do not freeze the page. If the worker cannot start, or fails, jobs run here instead.
use futures::channel::oneshot;
use serde_json::Value;
use std::{cell::RefCell, collections::HashMap};
use wasm_bindgen::{prelude::*, JsCast};

#[derive(Default)]
struct State {
    worker: Option<web_sys::Worker>,
    ready: bool,
    next: u64,
    /// requests waiting for the worker to load
    queue: Vec<String>,
    pending: HashMap<u64, (Value, oneshot::Sender<Value>)>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

/// The worker is gone: answer everything it still owed here.
fn give_up() {
    let pending = STATE.with(|s| {
        let mut s = s.borrow_mut();
        let st = s.get_or_insert_with(State::default);
        st.worker = None;
        st.queue.clear();
        std::mem::take(&mut st.pending)
    });
    for (_, (req, tx)) in pending {
        let _ = tx.send(hast_core::jobs::run(&req));
    }
}

fn start() -> Option<web_sys::Worker> {
    let w = web_sys::Worker::new("/worker_loader.js").ok()?;
    let on_message = Closure::<dyn FnMut(web_sys::MessageEvent)>::new(|e: web_sys::MessageEvent| {
        let Some(text) = e.data().as_string() else { return };
        if text == "ready" {
            STATE.with(|s| {
                if let Some(st) = s.borrow_mut().as_mut() {
                    st.ready = true;
                    for m in st.queue.drain(..) {
                        if let Some(w) = &st.worker {
                            let _ = w.post_message(&JsValue::from_str(&m));
                        }
                    }
                }
            });
            return;
        }
        let v: Value = serde_json::from_str(&text).unwrap_or_default();
        let tx = STATE.with(|s| s.borrow_mut().as_mut().and_then(|st| v["id"].as_u64().and_then(|id| st.pending.remove(&id))));
        if let Some((_, tx)) = tx {
            let _ = tx.send(v["result"].clone());
        }
    });
    w.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
    let on_error = Closure::<dyn FnMut(web_sys::Event)>::new(|_| give_up());
    w.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    on_error.forget();
    Some(w)
}

/// Run job `op` with `args` (see `hast_core::jobs::run`).
pub async fn run(op: &str, mut args: Value) -> Value {
    args["op"] = op.into();
    let rx = STATE.with(|s| {
        let mut s = s.borrow_mut();
        if s.is_none() {
            *s = Some(State {
                worker: start(),
                ..Default::default()
            });
        }
        let st = s.as_mut()?;
        let w = st.worker.clone()?;
        st.next += 1;
        let id = st.next;
        args["id"] = id.into();
        let text = args.to_string();
        let (tx, rx) = oneshot::channel();
        st.pending.insert(id, (args.clone(), tx));
        if st.ready {
            let _ = w.post_message(&JsValue::from_str(&text));
        } else {
            st.queue.push(text);
        }
        Some(rx)
    });
    match rx {
        Some(rx) => rx.await.unwrap_or(Value::Null),
        None => hast_core::jobs::run(&args),
    }
}
