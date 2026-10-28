//! The messaging channel: end-to-end encrypted like LiveChat, but with the "Quantum MDS" error-correction demo.
//!
//! Everything about the text happens in browsers: the sender Hamming-codes it, simulates the noisy channel,
//! seals the result to every member's ML-KEM key (`pq::Envelope`) and signs it with its SLH-DSA key; receivers
//! open it and do the error correction. The server checks the sender, the signature and replay rules, then stores
//! (in the database, `messages`) and relays ciphertext.
use crate::auth::{authenticate, origin_ok, Auth};
use crate::chat::MAX_SKEW_MS;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, State, WebSocketUpgrade,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use hast_core::{identity, pq};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;

/// Where the JSON store from before the database kept the history: one key, the whole history as a JSON string.
const OLD_STORE_KEY: &str = "chat_history";
const MAX_FRAME_BYTES: usize = 1 << 20;

pub struct Messaging {
    auth: Arc<Auth>,
    tx: broadcast::Sender<String>,
    /// `sender:id` accepted within the skew window
    seen: std::sync::Mutex<HashMap<String, u64>>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

impl Messaging {
    /// `import` is the JSON store from before messages lived in the database: imported once (when the database has
    /// no messages yet) and renamed to `<name>.imported`.
    pub fn new(auth: Arc<Auth>, import: Option<PathBuf>) -> Arc<Messaging> {
        if let Some(path) = import.filter(|p| p.exists()) {
            if auth.db.message_count() == 0 {
                let old: HashMap<String, Value> = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
                let history: Vec<Value> = old
                    .get(OLD_STORE_KEY)
                    .and_then(Value::as_str)
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_default();
                for msg in &history {
                    auth.db.push_message(msg);
                }
            }
            let mut done = path.clone().into_os_string();
            done.push(".imported");
            let _ = std::fs::rename(&path, done);
        }
        Arc::new(Messaging {
            auth,
            tx: broadcast::channel(256).0,
            seen: Default::default(),
        })
    }

    /// Checks a sealed, signed message from `sender`; returns what is stored and relayed.
    fn validate(&self, sender: &str, p: &Value) -> Result<Value, &'static str> {
        let body = p["body"].as_str().ok_or("body is required")?;
        if serde_json::from_str::<pq::Envelope>(body).map_or(true, |e| e.to.is_empty()) {
            return Err("body must be an encrypted envelope");
        }
        let id = p["id"]
            .as_str()
            .filter(|i| identity::valid_message_id(i))
            .ok_or("message id must be 1-64 letters, digits, _ or -")?;
        let sent_at = p["sentAt"].as_u64().ok_or("sentAt is required")?;
        let now = now_ms();
        if sent_at.abs_diff(now) > MAX_SKEW_MS {
            return Err("message time is too far from the server's clock");
        }
        let (acc, _) = self.auth.db.find(sender).ok_or("unknown sender")?;
        let slh = self.auth.db.head_link(acc.id).and_then(|h| h.slh).ok_or("open LiveChat once to create your keys")?;
        let sig = p["sig"].as_str().unwrap_or_default();
        if !pq::slh_verify(&slh, &identity::messaging_payload(id, sent_at, body), sig) {
            return Err("signature does not verify");
        }
        {
            let mut seen = self.seen.lock().unwrap();
            seen.retain(|_, at| now.saturating_sub(*at) <= 2 * MAX_SKEW_MS);
            if seen.insert(format!("{}:{id}", sender.to_lowercase()), now).is_some() {
                return Err("duplicate message id");
            }
        }
        Ok(json!({ "id": id, "senderId": sender, "ts": now, "sentAt": sent_at, "body": body, "sig": sig }))
    }

    /// Validates, stores and broadcasts a message.
    async fn post(&self, sender: &str, p: &Value) -> Result<Value, &'static str> {
        let mut msg = self.validate(sender, p)?;
        self.auth.db.push_message(&msg);
        // lets the sender match the broadcast to the message it already shows locally
        if let Some(c) = p["clientId"].as_str().filter(|c| !c.is_empty() && c.len() <= 64) {
            msg["clientId"] = c.into();
        }
        let _ = self.tx.send(json!({ "type": "message", "message": msg }).to_string());
        Ok(msg)
    }
}

pub fn router(m: Arc<Messaging>) -> Router {
    Router::new()
        .route("/api/messaging/messages", get(get_messages).post(post_message))
        .route("/ws/messaging", get(ws_handler))
        .with_state(m)
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

async fn post_message(State(m): State<Arc<Messaging>>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !origin_ok(&m.auth, &headers) {
        return error(StatusCode::FORBIDDEN, "cross-site request refused");
    }
    let Some((acc, _)) = authenticate(&m.auth, &headers) else {
        return error(StatusCode::UNAUTHORIZED, "not signed in");
    };
    match m.post(&acc.username, &body).await {
        Ok(msg) => Json(msg).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
}

async fn get_messages(State(m): State<Arc<Messaging>>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if authenticate(&m.auth, &headers).is_none() {
        return error(StatusCode::UNAUTHORIZED, "not signed in");
    }
    let since: u64 = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    Json(json!({ "messages": m.auth.db.messages_since(since, 50) })).into_response()
}

async fn ws_handler(ws: WebSocketUpgrade, State(m): State<Arc<Messaging>>, headers: HeaderMap) -> Response {
    if !origin_ok(&m.auth, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some((acc, _)) = authenticate(&m.auth, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    ws.max_message_size(MAX_FRAME_BYTES).on_upgrade(move |socket| client(socket, m, acc.username))
}

async fn client(socket: WebSocket, m: Arc<Messaging>, sender: String) {
    let (mut sink, mut stream) = socket.split();
    let mut rx = m.tx.subscribe();
    let (own_tx, mut own_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let backlog = json!({ "type": "backlog", "messages": m.auth.db.messages_since(0, 20) });
    let _ = sink.send(Message::Text(backlog.to_string())).await;
    let writer = tokio::spawn(async move {
        loop {
            let next = tokio::select! {
                b = rx.recv() => match b {
                    Ok(t) => t,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                },
                o = own_rx.recv() => match o {
                    Some(t) => t,
                    None => break,
                },
            };
            if sink.send(Message::Text(next)).await.is_err() {
                break;
            }
        }
    });
    while let Some(Ok(Message::Text(txt))) = stream.next().await {
        let Ok(p) = serde_json::from_str::<Value>(&txt) else { continue };
        if p["type"] == "chat" {
            // errors go only to this connection; nothing invalid is stored or relayed
            if let Err(reason) = m.post(&sender, &p).await {
                let _ = own_tx.send(json!({ "type": "error", "reason": reason }).to_string());
            }
        }
    }
    writer.abort();
}
