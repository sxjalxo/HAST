//! Messaging service: REST + WebSocket, authenticated by the account session; it stores and relays only sealed,
//! SLH-DSA-signed messages (the Hamming coding happens in browsers, inside the envelope).
mod common;
use common::*;
use futures_util::{SinkExt, StreamExt};
use hast_core::{identity, mds, pq};
use hast_server::Config;
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// A fresh temporary path for this test process.
fn temp(ext: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let p = std::env::temp_dir().join(format!("hast-msg-{}-{}.{ext}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    remove(&p);
    p
}

/// A database file and its WAL companions.
fn remove(db: &std::path::Path) {
    for suffix in ["", "-wal", "-shm", ".imported"] {
        let mut p = db.as_os_str().to_owned();
        p.push(suffix);
        let _ = std::fs::remove_file(p);
    }
}

/// Everything SQLite has written for `db` so far, WAL included.
fn bytes_at_rest(db: &std::path::Path) -> String {
    ["", "-wal"]
        .iter()
        .filter_map(|suffix| {
            let mut p = db.as_os_str().to_owned();
            p.push(suffix);
            std::fs::read(p).ok()
        })
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .collect()
}

/// A server with its own database file (returned, to inspect and clean up).
async fn server() -> (String, std::path::PathBuf) {
    let db = temp("db");
    let addr = start(Config {
        db_path: Some(db.clone()),
        ..Default::default()
    })
    .await;
    (addr, db)
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

/// What a browser sends: `inner` sealed to `to`, signed with the sender's SLH-DSA key.
fn sealed(from: &Account, inner: &Value, to: &[&Account], id: &str) -> Value {
    let rcpt: Vec<(String, String)> = to.iter().map(|a| (a.name.clone(), a.lt.kem_pk.clone())).collect();
    let body = serde_json::to_string(&pq::seal(&inner.to_string(), &from.name, &rcpt)).unwrap();
    let sent_at = now();
    json!({ "id": id, "sentAt": sent_at, "body": body, "sig": from.lt.sign(&identity::messaging_payload(id, sent_at, &body)) })
}

async fn next(sock: &mut Ws) -> Value {
    tokio::time::timeout(Duration::from_secs(2), async {
        let Some(Ok(Message::Text(t))) = sock.next().await else { panic!("expected a frame") };
        serde_json::from_str::<Value>(&t).unwrap()
    })
    .await
    .unwrap()
}

fn open(me: &Account, m: &Value) -> Option<Value> {
    let env: pq::Envelope = serde_json::from_str(m["body"].as_str()?).ok()?;
    serde_json::from_str(&pq::open(&env, &me.name, &me.lt, m["senderId"].as_str()?)?).ok()
}

#[tokio::test]
async fn rest_requires_a_session_and_stores_only_signed_ciphertext() {
    let (addr, file) = server().await;
    let alice = register(&addr, "alice").await;
    let bob = register(&addr, "bob").await;
    let url = format!("http://{addr}/api/messaging/messages");
    let post = |cookie: String, body: Value| {
        let url = url.clone();
        async move { http().post(&url).header("Cookie", cookie).json(&body).send().await.unwrap() }
    };

    assert_eq!(http().get(&url).send().await.unwrap().status(), 401);
    assert_eq!(http().post(&url).json(&json!({ "text": "x" })).send().await.unwrap().status(), 401);
    assert_eq!(post(alice.cookie.clone(), json!({ "text": "plain text" })).await.status(), 400, "plaintext is refused");
    let evil = http()
        .post(&url)
        .header("Origin", "http://evil.example")
        .header("Cookie", &alice.cookie)
        .json(&sealed(&alice, &json!({ "mode": "GD", "text": "x" }), &[&alice], "e1"))
        .send()
        .await
        .unwrap();
    assert_eq!(evil.status(), 403);

    let mut forged = sealed(&alice, &json!({ "mode": "GD", "text": "x" }), &[&alice, &bob], "f1");
    forged["sig"] = json!(bob.lt.sign("something else"));
    assert_eq!(post(alice.cookie.clone(), forged).await.status(), 400, "signature must be the sender's");

    let mut msg = sealed(&alice, &json!({ "mode": "GD", "text": "hello bob" }), &[&alice, &bob], "m1");
    msg["clientId"] = json!("c1");
    let r = post(alice.cookie.clone(), msg.clone()).await;
    assert_eq!(r.status(), 200);
    let stored: Value = r.json().await.unwrap();
    assert_eq!(
        (stored["senderId"].as_str(), stored["clientId"].as_str()),
        (Some("alice"), Some("c1")),
        "the sender is the account"
    );
    assert_eq!(post(alice.cookie.clone(), msg).await.status(), 400, "an id is accepted once");

    let list: Value = http().get(&url).header("Cookie", &bob.cookie).send().await.unwrap().json().await.unwrap();
    let first = &list["messages"][0];
    assert_eq!(open(&bob, first).unwrap()["text"], "hello bob");
    let at_rest = bytes_at_rest(&file);
    assert!(at_rest.contains("\"senderId\":\"alice\""), "the message is in the database");
    assert!(!at_rest.contains("hello bob"), "no plaintext at rest");
    remove(&file);
}

#[tokio::test]
async fn hamming_coding_travels_inside_the_envelope() {
    let (addr, file) = server().await;
    let (a, b) = (register(&addr, "a-user").await, register(&addr, "b-user").await);
    let url = format!("http://{addr}/api/messaging/messages");
    let text = "a fairly long message for the noisy channel";
    // the sender's browser encodes and simulates the channel; the receiver's decodes
    let noisy = mds::simulate_noise(&mds::encode_message(text), 0.02);
    let inner = json!({ "mode": "QuantumMDS", "codewords": hex::encode(&noisy), "errorRate": 0.02 });
    let m: Value = http()
        .post(&url)
        .header("Cookie", &a.cookie)
        .json(&sealed(&a, &inner, &[&a, &b], "q1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let got = open(&b, &m).unwrap();
    let codewords = hex::decode(got["codewords"].as_str().unwrap()).unwrap();
    let d = mds::decode_message(&codewords);
    if d.uncorrectable == 0 {
        assert_eq!(d.text, text);
    }
    remove(&file);
}

#[tokio::test]
async fn websocket_gets_backlog_echoes_client_id_and_reports_errors() {
    let (addr, file) = server().await;
    let early = register(&addr, "early").await;
    let me = register(&addr, "mia").await;
    http()
        .post(format!("http://{addr}/api/messaging/messages"))
        .header("Cookie", &early.cookie)
        .json(&sealed(&early, &json!({ "mode": "GD", "text": "before you joined" }), &[&early, &me], "b1"))
        .send()
        .await
        .unwrap();

    let mut sock = ws(&addr, "/ws/messaging", Some(&me.cookie)).await.unwrap();
    let Some(Ok(Message::Text(t))) = sock.next().await else { panic!("expected backlog") };
    let backlog: Value = serde_json::from_str(&t).unwrap();
    assert_eq!(backlog["type"], "backlog");
    assert_eq!(open(&me, &backlog["messages"][0]).unwrap()["text"], "before you joined");

    let mut frame = sealed(&me, &json!({ "mode": "GD", "text": "ping" }), &[&me], "p1");
    frame["type"] = json!("chat");
    frame["clientId"] = json!("local-1");
    sock.send(Message::Text(frame.to_string())).await.unwrap();
    let m = next(&mut sock).await;
    assert_eq!(
        (m["type"].as_str(), m["message"]["clientId"].as_str(), m["message"]["senderId"].as_str()),
        (Some("message"), Some("local-1"), Some("mia"))
    );
    assert_eq!(open(&me, &m["message"]).unwrap()["text"], "ping");

    sock.send(Message::Text(json!({ "type": "chat", "text": "plain" }).to_string())).await.unwrap();
    let e = next(&mut sock).await;
    assert_eq!((e["type"].as_str(), e["reason"].as_str()), (Some("error"), Some("body is required")));
    remove(&file);
}

#[tokio::test]
async fn messages_survive_a_restart() {
    let (addr, db) = server().await;
    let alice = register(&addr, "alice").await;
    let url = |a: &str| format!("http://{a}/api/messaging/messages");
    let r = http()
        .post(url(&addr))
        .header("Cookie", &alice.cookie)
        .json(&sealed(&alice, &json!({ "mode": "GD", "text": "kept" }), &[&alice], "k1"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // a second server on the same database sees it (accounts and sessions live there too)
    let again = start(Config {
        db_path: Some(db.clone()),
        ..Default::default()
    })
    .await;
    let list: Value = http().get(url(&again)).header("Cookie", &alice.cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["messages"].as_array().map(Vec::len), Some(1));
    assert_eq!(open(&alice, &list["messages"][0]).unwrap()["text"], "kept");
    remove(&db);
}

#[tokio::test]
async fn the_old_json_store_is_imported_once_and_renamed() {
    // the shape the JSON store had: one key whose value is the whole history as a JSON string
    let old = temp("json");
    let history = json!([
        { "id": "old1", "senderId": "alice", "ts": 1000, "text": "from before encryption" },
        { "id": "old2", "senderId": "bob", "ts": 2000, "sentAt": 2000, "body": "{}", "sig": "x" },
    ]);
    std::fs::write(&old, json!({ "chat_history": history.to_string() }).to_string()).unwrap();

    let addr = start(Config {
        messaging_import: Some(old.clone()),
        ..Default::default()
    })
    .await;
    let me = register(&addr, "reader").await;
    let list: Value = http()
        .get(format!("http://{addr}/api/messaging/messages"))
        .header("Cookie", &me.cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = list["messages"].as_array().unwrap().iter().filter_map(|m| m["id"].as_str()).collect();
    assert_eq!(ids, ["old1", "old2"], "imported in order");
    assert_eq!(list["messages"][0]["text"], "from before encryption", "stored exactly as it was");

    assert!(!old.exists(), "the old file is renamed");
    let mut done = old.as_os_str().to_owned();
    done.push(".imported");
    assert!(std::path::Path::new(&done).exists());
    remove(&old);
}
