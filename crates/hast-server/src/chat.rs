//! HAST LiveChat: WebSocket chat where every message is end-to-end encrypted and doubly signed.
//!
//! A connection is an authenticated account (session cookie). The text is sealed in the browser to every
//! account's ML-KEM key (`pq::Envelope`), so the server only ever sees ciphertext. It enforces what it can:
//! the message must be from that account, under the account's current key, with an HBSS signature and an
//! SLH-DSA co-signature that both verify over `identity::message_payload` (id, send time, envelope). A message id
//! is accepted once, and the send time must be close to the server's clock, so captured frames cannot be replayed.
//! Each message names its room: the lobby, or a private room of two accounts (`identity::dm_room`), whose frames
//! are only relayed and replayed to those two. Lobby messages may be encrypted under the sender's group key
//! (`pq::GroupCt`); that key reaches members in a `senderkey` frame (an envelope, signed like a message). The
//! latest one per sender is handed to every new connection, since the messages using it may outlive it in history.
//! Frames are size- and rate-limited and kept in the database (`chat_frames`, the newest `KEEP_FRAMES`); a
//! connection gets the newest `HISTORY_ON_CONNECT` it may see and can page back with `{type:"older", before, room?}`.
use crate::auth::{authenticate, origin_ok, Auth};
use crate::db::Account;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use hast_core::{
    hbss::{self, PublicKey, Signature},
    identity::{self, ChainLink, LinkKind},
    pq, ratchet,
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;

/// Frames kept in the database (sender keys are kept separately, the newest per sender).
pub const KEEP_FRAMES: usize = 5000;
const HISTORY_ON_CONNECT: usize = 20;
const PAGE: usize = 20;
pub const MAX_FRAME_BYTES: usize = 1 << 20;
const RATE_BURST: usize = 10;
const RATE_WINDOW_SECS: u64 = 10;
/// How far a message's signed send time may be from the server's clock.
pub const MAX_SKEW_MS: u64 = 5 * 60 * 1000;

#[derive(Default)]
struct Inner {
    clients: HashMap<u64, (String, mpsc::UnboundedSender<String>)>,
    next_id: u64,
    /// `sender:id` of messages accepted within the skew window, so none is accepted twice
    seen: HashMap<String, u64>,
}

pub struct Chat {
    auth: Arc<Auth>,
    inner: Mutex<Inner>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

impl Chat {
    /// `import` is a JSON-lines history file from before frames lived in the database: imported once (when the
    /// database has no frames yet) and renamed to `<name>.imported`.
    pub fn new(auth: Arc<Auth>, import: Option<PathBuf>) -> Arc<Chat> {
        if let Some(path) = import.filter(|p| p.exists()) {
            if auth.db.frame_count() == 0 {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                for frame in text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()) {
                    auth.db.push_frame(&frame, KEEP_FRAMES);
                }
            }
            let mut done = path.clone().into_os_string();
            done.push(".imported");
            let _ = std::fs::rename(&path, done);
        }
        Arc::new(Chat {
            auth,
            inner: Mutex::new(Inner::default()),
        })
    }

    fn users(inner: &Inner) -> Vec<String> {
        let mut v: Vec<String> = inner.clients.values().map(|(n, _)| n.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Send to everyone allowed to see the frame (see `visible_to`) except connection `skip`.
    fn broadcast(&self, payload: &Value, skip: Option<u64>) {
        let txt = payload.to_string();
        for (id, (name, tx)) in &self.inner.lock().unwrap().clients {
            if Some(*id) != skip && visible_to(payload, name) {
                let _ = tx.send(txt.clone());
            }
        }
    }

    fn broadcast_users(&self) {
        let users = Self::users(&self.inner.lock().unwrap());
        self.broadcast(&json!({ "type": "users", "users": users }), None);
    }

    /// Persist a frame and give it its sequence number (clients page back by it).
    fn push_history(&self, frame: &mut Value) {
        frame["seq"] = self.auth.db.push_frame(frame, KEEP_FRAMES).into();
    }

    /// Records `sender:id`; false if it was already accepted. Entries older than the skew window can go, because
    /// a message that old is refused for its time anyway.
    fn first_time(&self, sender: &str, id: &str, now: u64) -> bool {
        let mut i = self.inner.lock().unwrap();
        i.seen.retain(|_, at| now.saturating_sub(*at) <= 2 * MAX_SKEW_MS);
        i.seen.insert(format!("{}:{id}", sender.to_lowercase()), now).is_none()
    }

    /// The frames `user` may see before `before` (all rooms, or one).
    fn page(&self, user: &str, before: Option<i64>, room: Option<&str>, limit: usize) -> Vec<Value> {
        self.auth.db.frames_before(before, limit, |f| {
            visible_to(f, user) && room.is_none_or(|r| f["room"].as_str().unwrap_or(identity::LOBBY) == r)
        })
    }
}

/// Frames without a room (rotations, system notices, old messages) are public.
fn visible_to(frame: &Value, user: &str) -> bool {
    frame["room"].as_str().is_none_or(|r| identity::in_room(r, user))
}

pub fn router(chat: Arc<Chat>) -> Router {
    Router::new().route("/ws", get(ws_handler)).route("/stats", get(stats)).with_state(chat)
}

async fn stats(State(chat): State<Arc<Chat>>, headers: HeaderMap) -> Response {
    if authenticate(&chat.auth, &headers).is_none() {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "not signed in" }))).into_response();
    }
    let frames = chat.auth.db.frame_count();
    let i = chat.inner.lock().unwrap();
    Json(json!({ "connections": i.clients.len(), "online_users": Chat::users(&i), "messages": frames })).into_response()
}

async fn ws_handler(ws: WebSocketUpgrade, State(chat): State<Arc<Chat>>, headers: HeaderMap) -> Response {
    if !origin_ok(&chat.auth, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some((acc, _)) = authenticate(&chat.auth, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    ws.max_message_size(MAX_FRAME_BYTES).on_upgrade(move |socket| client(socket, chat, acc))
}

/// Checks a chat message against the account and the current keys of its active devices (`heads`); returns the frame
/// to store and broadcast, naming the device whose key signed it. `message` is the JSON of a `pq::Envelope`; both
/// signatures cover exactly that string.
fn validate(data: &Value, username: &str, heads: &[(String, ChainLink)], now: u64, exists: impl Fn(&str) -> bool) -> Result<Value, &'static str> {
    if data["sender"].as_str() != Some(username) {
        return Err("sender does not match the signed-in account");
    }
    let Some((device, head)) = heads.iter().find(|(_, h)| data["commitment"].as_str() == Some(h.root.as_str())) else {
        return Err("commitment is not the account's current key");
    };
    let Some(slh) = head.slh.as_deref() else {
        return Err("account keys need an upgrade: reload LiveChat");
    };
    let text = data["message"].as_str().ok_or("message must be text")?;
    let room = data["room"].as_str().ok_or("room is required")?;
    let sealed = serde_json::from_str::<pq::Envelope>(text).is_ok_and(|e| !e.to.is_empty()) || serde_json::from_str::<ratchet::Envelope>(text).is_ok_and(|e| !e.to.is_empty());
    let group = room == identity::LOBBY && data["type"] == "message" && serde_json::from_str::<pq::GroupCt>(text).is_ok();
    if !sealed && !group {
        return Err("message must be an encrypted envelope");
    }
    if data["type"] == "senderkey" && room != identity::LOBBY {
        return Err("sender keys belong to the lobby");
    }
    if room != identity::LOBBY {
        let (a, b) = identity::dm_members(room).ok_or("unknown room")?;
        let other = if username.eq_ignore_ascii_case(a) { b } else { a };
        if !identity::in_room(room, username) || !exists(other) {
            return Err("unknown room");
        }
    }
    let id = data["id"]
        .as_str()
        .filter(|i| identity::valid_message_id(i))
        .ok_or("message id must be 1-64 letters, digits, _ or -")?;
    let sent_at = data["sentAt"].as_u64().ok_or("sentAt is required")?;
    if sent_at.abs_diff(now) > MAX_SKEW_MS {
        return Err("message time is too far from the server's clock");
    }
    let payload = identity::message_payload(room, id, sent_at, text);
    let sig: Signature = serde_json::from_value(data["signature"].clone()).map_err(|_| "malformed signature")?;
    let pk = PublicKey {
        commitment_root: head.root.clone(),
        commitments: vec![],
        version: hbss::KEY_VERSION,
    };
    if !hbss::verify(&payload, &sig, &pk) {
        return Err("signature does not verify");
    }
    let cosig = data["slhSignature"].as_str().unwrap_or_default();
    if !pq::slh_verify(slh, &payload, cosig) {
        return Err("SLH-DSA co-signature does not verify");
    }
    Ok(json!({
        "type": data["type"], "room": room, "id": id, "sentAt": sent_at, "sender": username, "senderAvatar": "",
        "message": text, "signature": sig, "slhSignature": cosig, "commitment": head.root, "device": device, "timestamp": now,
    }))
}

fn rate_ok(recent: &mut VecDeque<Instant>) -> bool {
    let now = Instant::now();
    while recent.front().is_some_and(|t| now.duration_since(*t).as_secs() >= RATE_WINDOW_SECS) {
        recent.pop_front();
    }
    if recent.len() >= RATE_BURST {
        return false;
    }
    recent.push_back(now);
    true
}

async fn client(socket: WebSocket, chat: Arc<Chat>, acc: Account) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let (id, first_connection) = {
        let mut i = chat.inner.lock().unwrap();
        i.next_id += 1;
        let id = i.next_id;
        let first = !i.clients.values().any(|(n, _)| n == &acc.username);
        i.clients.insert(id, (acc.username.clone(), tx.clone()));
        (id, first)
    };
    let _ = tx.send(json!({ "type": "system", "message": "Welcome to HAST LiveChat", "timestamp": now_ms() }).to_string());
    // `commitment` and `slh`: the primary device's (the identity); `heads`: every active device's current root
    let head = chat.auth.db.head_link(acc.id).unwrap_or_default();
    let heads: Vec<String> = chat.auth.db.active_heads(acc.id).into_iter().map(|(_, l)| l.root).collect();
    let _ = tx.send(json!({ "type": "welcome", "username": acc.username, "commitment": head.root, "slh": head.slh, "heads": heads }).to_string());
    let _ = tx.send(json!({ "type": "senderkeys", "frames": chat.auth.db.sender_key_frames() }).to_string());
    let _ = tx.send(json!({ "type": "history", "messages": chat.page(&acc.username, None, None, HISTORY_ON_CONNECT) }).to_string());
    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if sink.send(Message::Text(m)).await.is_err() {
                break;
            }
        }
    });
    let reject = |reason: &str| {
        let _ = tx.send(json!({ "type": "error", "reason": reason }).to_string());
    };
    chat.broadcast_users();
    if first_connection {
        chat.broadcast(
            &json!({ "type": "system", "message": format!("{} joined the chat", acc.username), "timestamp": now_ms() }),
            Some(id),
        );
    }

    // messages and protocol frames (rotations, sender keys) have separate budgets, so a send that also needs a
    // handover and a new group key does not use up the message allowance
    let (mut recent, mut recent_ctl): (VecDeque<Instant>, VecDeque<Instant>) = Default::default();
    while let Some(Ok(msg)) = stream.next().await {
        let Message::Text(txt) = msg else { continue };
        let Ok(data) = serde_json::from_str::<Value>(&txt) else {
            reject("malformed JSON");
            continue;
        };
        // a removed device's key is no longer among these, so it can neither send nor rotate
        let heads = chat.auth.db.active_heads(acc.id);
        if heads.is_empty() {
            break;
        }
        match data["type"].as_str() {
            Some(kind @ ("message" | "senderkey")) => {
                if !rate_ok(if kind == "message" { &mut recent } else { &mut recent_ctl }) {
                    reject("rate limited");
                    continue;
                }
                let now = now_ms();
                match validate(&data, &acc.username, &heads, now, |n| chat.auth.db.find(n).is_some()) {
                    Ok(mut m) if chat.first_time(&acc.username, m["id"].as_str().unwrap_or_default(), now) => {
                        chat.push_history(&mut m);
                        chat.broadcast(&m, Some(id));
                    }
                    Ok(_) => reject("duplicate message id"),
                    Err(reason) => reject(reason),
                }
            }
            // The current keys of one device vouch for its successor (`identity::rotate_link`); `old_root` says which.
            Some("rotate") => {
                if !rate_ok(&mut recent_ctl) {
                    reject("rate limited");
                    continue;
                }
                let Ok(link) = serde_json::from_value::<ChainLink>(data["link"].clone()) else {
                    reject("malformed rotation");
                    continue;
                };
                let Some((device, head)) = heads.iter().find(|(_, h)| link.old_root.as_deref() == Some(h.root.as_str())) else {
                    reject("link does not continue from the current key");
                    continue;
                };
                if link.kind != LinkKind::Rotate || link.slh.is_none() || identity::verify_next(head, &link).is_err() {
                    reject("rotation does not verify");
                    continue;
                }
                if let Err(e) = chat.auth.db.append_link(acc.id, device, &link) {
                    reject(&e);
                    continue;
                }
                let mut frame =
                    json!({ "type": "rotate", "sender": acc.username, "device": device, "oldCommitment": head.root, "newCommitment": link.root, "timestamp": now_ms() });
                chat.push_history(&mut frame);
                chat.broadcast(&frame, Some(id));
            }
            // page back through history: the frames this account may see before `before` (optionally one room)
            Some("older") => {
                if !rate_ok(&mut recent_ctl) {
                    reject("rate limited");
                    continue;
                }
                let room = data["room"].as_str();
                let messages = chat.page(&acc.username, data["before"].as_i64(), room, PAGE);
                let more = messages.len() == PAGE;
                let _ = tx.send(json!({ "type": "older", "room": room, "messages": messages, "more": more }).to_string());
            }
            _ => reject("unknown message type"),
        }
    }

    let last_connection = {
        let mut i = chat.inner.lock().unwrap();
        i.clients.remove(&id);
        !i.clients.values().any(|(n, _)| n == &acc.username)
    };
    writer.abort();
    if last_connection {
        chat.broadcast_users();
        chat.broadcast(
            &json!({ "type": "system", "message": format!("{} left the chat", acc.username), "timestamp": now_ms() }),
            None,
        );
    }
}
