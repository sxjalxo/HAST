//! LiveChat against a real server: accounts connect with their session cookie, seal messages to their
//! recipients and sign the envelope with their HBSS key and their SLH-DSA key.
mod common;
use common::*;
use futures_util::{SinkExt, StreamExt};
use hast_core::{
    hbss::{self, KeyPair},
    identity::{self, ChainLink, LinkKind},
    pq::{self, LongTermKeys},
};
use hast_server::Config;
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

struct Chat {
    ws: Ws,
    name: String,
    keys: KeyPair,
    lt: LongTermKeys,
}

impl Chat {
    async fn connect(addr: &str, a: &Account) -> Chat {
        let mut c = Chat {
            ws: ws(addr, "/ws", Some(&a.cookie)).await.unwrap(),
            name: a.name.clone(),
            keys: a.keys.clone(),
            lt: a.lt.clone(),
        };
        let welcome = c.next_of("welcome").await.expect("welcome frame");
        assert_eq!(welcome["username"], a.name);
        assert_eq!(welcome["commitment"], a.keys.public_key.commitment_root);
        assert_eq!(welcome["slh"], a.lt.slh_pk);
        c
    }

    async fn send(&mut self, v: Value) {
        self.ws.send(Message::Text(v.to_string())).await.unwrap();
    }

    fn recipient(&self) -> (String, String) {
        (self.name.clone(), self.lt.kem_pk.clone())
    }

    /// A lobby message frame: `text` sealed to `to`, the envelope signed with both keys.
    fn signed_for(&self, text: &str, to: &[(String, String)]) -> Value {
        self.signed_in(identity::LOBBY, text, to)
    }

    fn signed_in(&self, room: &str, text: &str, to: &[(String, String)]) -> Value {
        let env = serde_json::to_string(&pq::seal(text, &self.name.to_lowercase(), to)).unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        self.frame_in(room, &env, &uuid(), now)
    }

    fn signed(&self, text: &str) -> Value {
        self.signed_for(text, &[self.recipient()])
    }

    fn frame(&self, body: &str) -> Value {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        self.frame_at(body, &uuid(), now)
    }

    fn frame_at(&self, body: &str, id: &str, sent_at: u64) -> Value {
        self.frame_in(identity::LOBBY, body, id, sent_at)
    }

    fn frame_in(&self, room: &str, body: &str, id: &str, sent_at: u64) -> Value {
        let payload = identity::message_payload(room, id, sent_at, body);
        json!({ "type": "message", "room": room, "id": id, "sentAt": sent_at, "sender": self.name, "message": body,
                "signature": hbss::sign_with_proofs(&payload, &self.keys), "slhSignature": self.lt.sign(&payload),
                "commitment": self.keys.public_key.commitment_root })
    }

    fn read(&self, frame: &Value) -> Option<String> {
        let env: pq::Envelope = serde_json::from_str(frame["message"].as_str()?).ok()?;
        pq::open(&env, &self.name, &self.lt, &frame["sender"].as_str()?.to_lowercase())
    }

    fn rotation(&self, next: &KeyPair) -> Value {
        json!({ "type": "rotate", "link": identity::rotate_link(&self.keys, &next.public_key.commitment_root, &self.lt) })
    }

    async fn next_of(&mut self, kind: &str) -> Option<Value> {
        tokio::time::timeout(Duration::from_millis(1500), async {
            loop {
                match self.ws.next().await {
                    Some(Ok(Message::Text(t))) => {
                        let v: Value = serde_json::from_str(&t).unwrap();
                        if v["type"] == kind {
                            return v;
                        }
                    }
                    _ => return Value::Null,
                }
            }
        })
        .await
        .ok()
        .filter(|v| !v.is_null())
    }

    async fn error(&mut self) -> String {
        self.next_of("error").await.map(|v| v["reason"].as_str().unwrap().to_string()).unwrap_or_default()
    }
}

fn uuid() -> String {
    format!("{:x}", rand::random::<u128>())
}

async fn trio() -> (String, Chat, Chat) {
    let addr = start(Config::default()).await;
    let alice = register(&addr, "Alice").await;
    let bob = register(&addr, "Bob").await;
    let (a, b) = (Chat::connect(&addr, &alice).await, Chat::connect(&addr, &bob).await);
    (addr, a, b)
}

#[tokio::test]
async fn sealed_message_reaches_its_recipient_and_both_signatures_verify() {
    let (_, mut alice, mut bob) = trio().await;
    let msg = alice.signed_for("hello bob", &[alice.recipient(), bob.recipient()]);
    alice.send(msg).await;
    let got = bob.next_of("message").await.expect("bob should receive the message");
    assert_eq!(got["sender"], "Alice");
    assert!(!got.to_string().contains("hello bob"), "the server only relays ciphertext");
    assert_eq!(bob.read(&got).as_deref(), Some("hello bob"));
    assert_eq!(alice.read(&got).as_deref(), Some("hello bob"), "the sender can read its own history");

    let payload = identity::message_payload(
        identity::LOBBY,
        got["id"].as_str().unwrap(),
        got["sentAt"].as_u64().unwrap(),
        got["message"].as_str().unwrap(),
    );
    let body = payload.as_str();
    let sig = serde_json::from_value(got["signature"].clone()).unwrap();
    let pk = hbss::PublicKey {
        commitment_root: got["commitment"].as_str().unwrap().into(),
        commitments: vec![],
        version: hbss::KEY_VERSION,
    };
    assert!(hbss::verify(body, &sig, &pk), "receiver can verify the HBSS signature the server relayed");
    assert!(pq::slh_verify(&alice.lt.slh_pk, body, got["slhSignature"].as_str().unwrap()), "and the SLH-DSA one");
}

#[tokio::test]
async fn messages_not_addressed_to_you_stay_sealed() {
    let (_, mut alice, mut bob) = trio().await;
    alice.send(alice.signed("for alice only")).await;
    let got = bob.next_of("message").await.unwrap();
    assert_eq!(bob.read(&got), None);
}

#[tokio::test]
async fn online_users_are_the_signed_in_accounts() {
    let (_, mut alice, _bob) = trio().await;
    let users = loop {
        let u = alice.next_of("users").await.expect("users frame");
        if u["users"].as_array().unwrap().len() == 2 {
            break u;
        }
    };
    assert_eq!(users["users"], json!(["Alice", "Bob"]));
}

#[tokio::test]
async fn rejects_tampered_forged_and_unsigned_messages() {
    let (_, mut alice, mut bob) = trio().await;
    let mut m = alice.signed("pay 5");
    m["message"] = alice.signed("pay 500")["message"].clone();
    alice.send(m).await;
    assert_eq!(alice.error().await, "signature does not verify");

    let mut m = alice.signed("hi");
    m["signature"]["revealedPreimages"][0] = json!("ab".repeat(64));
    alice.send(m).await;
    assert_eq!(alice.error().await, "signature does not verify");

    let mut m = alice.signed("hi");
    m["slhSignature"] = json!(LongTermKeys::generate().sign("anything"));
    alice.send(m).await;
    assert_eq!(alice.error().await, "SLH-DSA co-signature does not verify", "HBSS alone is not enough");

    let mut m = alice.signed("hi");
    m.as_object_mut().unwrap().remove("slhSignature");
    alice.send(m).await;
    assert_eq!(alice.error().await, "SLH-DSA co-signature does not verify");

    let mut m = alice.signed("hi");
    m.as_object_mut().unwrap().remove("signature");
    alice.send(m).await;
    assert_eq!(alice.error().await, "malformed signature");

    assert!(bob.next_of("message").await.is_none(), "nothing invalid may reach other users");
}

#[tokio::test]
async fn cannot_speak_as_someone_else_or_with_another_key() {
    let (_, mut eve, _) = trio().await;

    let mut m = eve.signed("I am Bob");
    m["sender"] = json!("Bob");
    eve.send(m).await;
    assert_eq!(eve.error().await, "sender does not match the signed-in account");

    // a perfectly valid signature, but not by the account's key
    let other = hbss::keygen(hbss::N);
    let mut m = eve.signed("other key");
    m["signature"] = json!(hbss::sign_with_proofs("other key", &other));
    m["commitment"] = json!(other.public_key.commitment_root);
    eve.send(m).await;
    assert_eq!(eve.error().await, "commitment is not the account's current key");
}

#[tokio::test]
async fn plaintext_and_unknown_frames_are_refused() {
    let (_, mut a, _) = trio().await;
    let m = a.frame("plain text, properly signed");
    a.send(m).await;
    assert_eq!(a.error().await, "message must be an encrypted envelope");
    let m = a.signed_for("sealed to nobody", &[]);
    a.send(m).await;
    assert_eq!(a.error().await, "message must be an encrypted envelope");
    a.send(json!({ "type": "nonsense" })).await;
    assert_eq!(a.error().await, "unknown message type");
    a.send(json!({ "type": "join", "sender": "Mallory" })).await;
    assert_eq!(a.error().await, "unknown message type", "identity comes from the session, there is no join");
}

#[tokio::test]
async fn replayed_and_stale_messages_are_refused() {
    let (_, mut alice, mut bob) = trio().await;
    let m = alice.signed("once only");
    alice.send(m.clone()).await;
    assert!(bob.next_of("message").await.is_some());
    alice.send(m).await;
    assert_eq!(alice.error().await, "duplicate message id", "the same frame cannot be delivered twice");

    let mut m = alice.signed("new id, same signature");
    m["id"] = json!(uuid());
    alice.send(m).await;
    assert_eq!(alice.error().await, "signature does not verify", "the id is signed");

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let old = alice.frame_at(alice.signed("x")["message"].as_str().unwrap(), &uuid(), now - 10 * 60 * 1000);
    alice.send(old).await;
    assert_eq!(alice.error().await, "message time is too far from the server's clock");

    let mut m = alice.signed("bad id");
    m["id"] = json!("has spaces");
    alice.send(m).await;
    assert_eq!(alice.error().await, "message id must be 1-64 letters, digits, _ or -");
    assert!(bob.next_of("message").await.is_none());
}

#[tokio::test]
async fn private_rooms_reach_only_their_members() {
    let addr = start(Config::default()).await;
    let (a, b, c) = (register(&addr, "Alice").await, register(&addr, "Bob").await, register(&addr, "Carol").await);
    let (mut alice, mut bob, mut carol) = (Chat::connect(&addr, &a).await, Chat::connect(&addr, &b).await, Chat::connect(&addr, &c).await);
    let room = identity::dm_room("alice", "bob");
    alice.send(alice.signed_in(&room, "just for bob", &[alice.recipient(), bob.recipient()])).await;
    let got = bob.next_of("message").await.expect("bob gets the private message");
    assert_eq!((got["room"].as_str(), bob.read(&got).as_deref()), (Some(room.as_str()), Some("just for bob")));
    assert!(carol.next_of("message").await.is_none(), "carol is not relayed it");

    let mut moved = alice.signed_in(&room, "private", &[alice.recipient(), bob.recipient()]);
    moved["room"] = json!(identity::LOBBY);
    alice.send(moved).await;
    assert_eq!(alice.error().await, "signature does not verify", "the room is signed");
    alice.send(alice.signed_in("dm:bob:carol", "not my room", &[alice.recipient()])).await;
    assert_eq!(alice.error().await, "unknown room");
    alice
        .send(alice.signed_in(&identity::dm_room("alice", "nobody"), "no such account", &[alice.recipient()]))
        .await;
    assert_eq!(alice.error().await, "unknown room");

    // replay on connect: carol never sees the private frame, bob does
    let mut late_carol = Chat::connect(&addr, &c).await;
    let hist = late_carol.next_of("history").await.unwrap();
    assert!(hist["messages"].as_array().unwrap().iter().all(|m| m["room"] != json!(room)));
    let mut late_bob = Chat::connect(&addr, &b).await;
    let hist = late_bob.next_of("history").await.unwrap();
    assert!(hist["messages"].as_array().unwrap().iter().any(|m| m["room"] == json!(room)));
}

#[tokio::test]
async fn group_keys_reach_members_once_and_newcomers_on_connect() {
    let (addr, mut alice, mut bob) = trio().await;
    let (key, key_id) = pq::new_group_key();
    let dist = json!({ "id": key_id, "key": hex::encode(key) }).to_string();
    let env = serde_json::to_string(&pq::seal(&dist, "alice", &[alice.recipient(), bob.recipient()])).unwrap();
    let mut frame = alice.frame(&env);
    frame["type"] = json!("senderkey");
    let payload = identity::message_payload(identity::LOBBY, frame["id"].as_str().unwrap(), frame["sentAt"].as_u64().unwrap(), &env);
    frame["signature"] = json!(hbss::sign_with_proofs(&payload, &alice.keys));
    frame["slhSignature"] = json!(alice.lt.sign(&payload));
    alice.send(frame).await;
    let got = bob.next_of("senderkey").await.expect("members receive the sender key");
    assert_eq!(bob.read(&got).as_deref(), Some(dist.as_str()));

    let body = serde_json::to_string(&pq::group_seal(&key, &key_id, "cheap message", "alice")).unwrap();
    alice.send(alice.frame(&body)).await;
    let got = bob.next_of("message").await.expect("group-key messages are relayed");
    let ct: pq::GroupCt = serde_json::from_str(got["message"].as_str().unwrap()).unwrap();
    assert_eq!(pq::group_open(&key, &ct, "alice").as_deref(), Some("cheap message"));
    assert!(got.to_string().len() < 70_000, "no per-member cost");

    let carol = register(&addr, "Carol").await;
    let mut c = Chat::connect(&addr, &carol).await;
    let keys = c.next_of("senderkeys").await.expect("latest sender keys come before history");
    assert_eq!(keys["frames"].as_array().unwrap().len(), 1);
    let hist = c.next_of("history").await.unwrap();
    assert!(hist["messages"].as_array().unwrap().iter().all(|m| m["type"] != "senderkey"), "not shown as messages");

    let dm = identity::dm_room("alice", "bob");
    let mut wrong = alice.signed_in(&dm, "x", &[alice.recipient()]);
    wrong["message"] = json!(body);
    let payload = identity::message_payload(&dm, wrong["id"].as_str().unwrap(), wrong["sentAt"].as_u64().unwrap(), &body);
    wrong["signature"] = json!(hbss::sign_with_proofs(&payload, &alice.keys));
    wrong["slhSignature"] = json!(alice.lt.sign(&payload));
    alice.send(wrong).await;
    assert_eq!(alice.error().await, "message must be an encrypted envelope", "private rooms are sealed per message");
}

#[tokio::test]
async fn rate_limits_a_flood() {
    let (_, mut a, _) = trio().await;
    for i in 0..12 {
        let m = a.signed(&format!("m{i}"));
        a.send(m).await;
    }
    let mut limited = false;
    for _ in 0..12 {
        if a.next_of("error").await.is_some_and(|e| e["reason"] == "rate limited") {
            limited = true;
            break;
        }
    }
    assert!(limited);
}

#[tokio::test]
async fn cross_site_websocket_is_refused() {
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue};
    let addr = start(Config::default()).await;
    let alice = register(&addr, "alice").await;
    let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
    req.headers_mut().insert("Cookie", HeaderValue::from_str(&alice.cookie).unwrap());
    req.headers_mut().insert("Origin", HeaderValue::from_static("http://evil.example"));
    let err = tokio_tungstenite::connect_async(req).await.expect_err("must be refused");
    assert!(err.to_string().contains("403"), "{err}");
}

#[tokio::test]
async fn logging_out_stops_the_socket_from_being_used() {
    let addr = start(Config::default()).await;
    let alice = register(&addr, "alice").await;
    http().post(format!("http://{addr}/api/logout")).header("Cookie", &alice.cookie).send().await.unwrap();
    assert!(ws(&addr, "/ws", Some(&alice.cookie)).await.is_err(), "a dead session cannot open a socket");
}

#[tokio::test]
async fn key_rotation_extends_the_account_chain_and_the_new_key_takes_over() {
    let (addr, mut alice, mut bob) = trio().await;
    let next = hbss::keygen(hbss::N);
    let new_root = next.public_key.commitment_root.clone();
    let old_root = alice.keys.public_key.commitment_root.clone();
    let old_msg = alice.signed("signed with the old key");

    alice.send(alice.rotation(&next)).await;
    let rot = bob.next_of("rotate").await.expect("others learn about the rotation");
    assert_eq!(
        (rot["sender"].as_str(), rot["oldCommitment"].as_str(), rot["newCommitment"].as_str()),
        (Some("Alice"), Some(old_root.as_str()), Some(new_root.as_str()))
    );

    alice.send(old_msg).await;
    assert_eq!(alice.error().await, "commitment is not the account's current key");
    alice.keys = next;
    let m = alice.signed_for("signed with the new key", &[bob.recipient()]);
    alice.send(m).await;
    let got = bob.next_of("message").await.unwrap();
    assert_eq!(bob.read(&got).as_deref(), Some("signed with the new key"));

    // the directory shows the same chain, and it verifies
    let bob_cookie = cookie_of(&login(&addr, "Bob", PASSWORD).await).unwrap();
    let body: Value = http()
        .get(format!("http://{addr}/api/keys/alice"))
        .header("Cookie", &bob_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let chain: Vec<ChainLink> = serde_json::from_value(body["chain"].clone()).unwrap();
    assert_eq!(chain.iter().map(|l| l.kind).collect::<Vec<_>>(), [LinkKind::Register, LinkKind::Rotate]);
    let v = identity::verify_chain("alice", &chain).unwrap();
    assert_eq!(v.roots.last(), Some(&new_root));
    assert_eq!(v.kem.as_deref(), Some(alice.lt.kem_pk.as_str()), "the encryption key survives rotation");

    // only what is new since a root the client already verified
    let since: Value = http()
        .get(format!("http://{addr}/api/keys/alice?since={old_root}"))
        .header("Cookie", &bob_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(since["full"], false);
    let more: Vec<ChainLink> = serde_json::from_value(since["chain"].clone()).unwrap();
    assert_eq!(more, chain[1..].to_vec());
    assert_eq!(identity::extend_chain(identity::verify_chain("alice", &chain[..1]).unwrap(), &more), Ok(v.clone()));
    let unknown: Value = http()
        .get(format!("http://{addr}/api/keys/alice?since=nope"))
        .header("Cookie", &bob_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!((unknown["full"].clone(), unknown["chain"].as_array().unwrap().len()), (json!(true), 2));

    let dir: Value = http()
        .get(format!("http://{addr}/api/directory"))
        .header("Cookie", &bob_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        dir["accounts"],
        json!([
            { "username": "Alice", "head": new_root, "devices": [{ "device": "d1", "head": new_root }] },
            { "username": "Bob", "head": bob.keys.public_key.commitment_root, "devices": [{ "device": "d1", "head": bob.keys.public_key.commitment_root }] }
        ])
    );
}

#[tokio::test]
async fn a_second_connection_of_the_same_account_follows_a_rotation() {
    let addr = start(Config::default()).await;
    let alice = register(&addr, "alice").await;
    let (mut tab1, mut tab2) = (Chat::connect(&addr, &alice).await, Chat::connect(&addr, &alice).await);

    let next = hbss::keygen(hbss::N);
    tab1.send(tab1.rotation(&next)).await;
    tab2.next_of("rotate").await.expect("the other tab is told");
    tab2.keys = next;
    let m = tab2.signed("from the other tab");
    tab2.send(m).await;
    let got = tab1.next_of("message").await.unwrap();
    assert_eq!(
        tab1.read(&got).as_deref(),
        Some("from the other tab"),
        "the chain lives with the account, not the connection"
    );
}

#[tokio::test]
async fn rejects_forged_rotations() {
    let (_, mut eve, _) = trio().await;
    let (stranger, target) = (hbss::keygen(hbss::N), hbss::keygen(hbss::N));
    let t = target.public_key.commitment_root.clone();

    let mut forged = identity::rotate_link(&stranger, &t, &eve.lt);
    forged.old_root = Some(eve.keys.public_key.commitment_root.clone());
    eve.send(json!({ "type": "rotate", "link": forged })).await;
    assert_eq!(eve.error().await, "rotation does not verify", "signed by another HBSS key");

    let swapped = identity::rotate_link(&eve.keys, &t, &LongTermKeys::generate());
    eve.send(json!({ "type": "rotate", "link": swapped })).await;
    assert_eq!(eve.error().await, "rotation does not verify", "the co-signing key cannot be swapped by a rotation");

    let legacy = ChainLink {
        kind: LinkKind::Rotate,
        root: t.clone(),
        old_root: Some(eve.keys.public_key.commitment_root.clone()),
        signature: Some(hbss::sign_rotation(&eve.keys, &t)),
        ..Default::default()
    };
    eve.send(json!({ "type": "rotate", "link": legacy })).await;
    assert_eq!(eve.error().await, "rotation does not verify", "HBSS-only rotations are not accepted any more");

    eve.send(json!({ "type": "rotate", "newCommitment": t })).await;
    assert_eq!(eve.error().await, "malformed rotation");
}

#[tokio::test]
async fn history_with_rotations_survives_a_restart() {
    let db = std::env::temp_dir().join(format!("hast-history-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db);
    let cfg = Config {
        db_path: Some(db.clone()),
        ..Default::default()
    };

    let addr = start(cfg.clone()).await;
    let alice = register(&addr, "Alice").await;
    let mut chat = Chat::connect(&addr, &alice).await;
    let m = chat.signed("remember me");
    chat.send(m).await;
    let next = hbss::keygen(hbss::N);
    chat.send(chat.rotation(&next)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let addr2 = start(cfg).await; // a fresh server on the same database
    let carol = register(&addr2, "Carol").await;
    let mut c = Chat::connect(&addr2, &carol).await;
    let hist = c.next_of("history").await.unwrap();
    let kinds: Vec<_> = hist["messages"].as_array().unwrap().iter().map(|m| m["type"].as_str().unwrap().to_string()).collect();
    assert_eq!(kinds, ["message", "rotate"], "a late joiner replays the frames in order");
    assert_eq!(chat.read(&hist["messages"][0]).as_deref(), Some("remember me"));
    assert_eq!(c.read(&hist["messages"][0]), None, "but cannot read what was sealed before they joined");
    let raw = std::fs::read(&db).unwrap_or_default();
    assert!(!raw.windows(11).any(|w| w == b"remember me"), "no plaintext at rest");
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn history_pages_back_and_old_history_files_are_imported() {
    let file = std::env::temp_dir().join(format!("hast-import-{}.jsonl", std::process::id()));
    let frames: String = (0..30)
        .map(|i| format!("{}\n", json!({ "type": "message", "room": "lobby", "sender": "old", "message": format!("m{i}") })))
        .collect();
    std::fs::write(&file, frames).unwrap();
    let addr = start(Config {
        history_file: Some(file.clone()),
        ..Default::default()
    })
    .await;
    let a = register(&addr, "alice").await; // the server is up once this answers
    assert!(!file.exists(), "renamed after the import");
    let mut imported = file.clone().into_os_string();
    imported.push(".imported");
    let _ = std::fs::remove_file(&imported);

    let mut c = Chat::connect(&addr, &a).await;
    let hist = c.next_of("history").await.unwrap();
    let first = hist["messages"].as_array().unwrap();
    assert_eq!((first.len(), first[0]["message"].as_str()), (20, Some("m10")), "newest 20 on connect");
    c.send(json!({ "type": "older", "before": first[0]["seq"], "room": "lobby" })).await;
    let older = c.next_of("older").await.unwrap();
    let msgs = older["messages"].as_array().unwrap();
    assert_eq!((msgs.len(), msgs[0]["message"].as_str(), older["more"].as_bool()), (10, Some("m0"), Some(false)));
}

// ---- devices: more than one browser per account ----

async fn get_json(addr: &str, path: &str, cookie: &str) -> (u16, Value) {
    let r = http().get(format!("http://{addr}{path}")).header("Cookie", cookie).send().await.unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

async fn send_json(addr: &str, method: reqwest::Method, path: &str, cookie: &str, body: Value) -> (u16, Value) {
    let r = http()
        .request(method, format!("http://{addr}{path}"))
        .header("Cookie", cookie)
        .json(&body)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

/// A second browser of `a`: its own HBSS and ML-KEM keys, the account's identity (SLH-DSA) key.
fn second_device(a: &Account, device: &str) -> (KeyPair, LongTermKeys, ChainLink) {
    let mut lt = a.lt.clone();
    lt.rotate_kem(1.0, 1.0);
    let kp = hbss::keygen(hbss::N);
    let link = identity::device_link(&a.name, device, &kp, &lt);
    (kp, lt, link)
}

#[tokio::test]
async fn a_linked_device_sends_rotates_and_can_be_removed() {
    let addr = start(Config::default()).await;
    let alice = register(&addr, "Alice").await;
    let bob = register(&addr, "Bob").await;
    let (mut laptop, mut b) = (Chat::connect(&addr, &alice).await, Chat::connect(&addr, &bob).await);
    const PHONE: &str = "d0000000a";

    // the offer: an opaque blob the new browser fetches with the same account's session
    let offer = json!({ "salt": "00112233445566778899aabbccddeeff", "blob": "sealed identity key" });
    assert_eq!(send_json(&addr, reqwest::Method::POST, "/api/devices/offer", &alice.cookie, offer.clone()).await.0, 200);
    assert_eq!(get_json(&addr, "/api/devices/offer", &alice.cookie).await, (200, offer));
    assert_eq!(get_json(&addr, "/api/devices/offer", &bob.cookie).await.0, 404, "offers are per account");

    let (phone_kp, phone_lt, link) = second_device(&alice, PHONE);
    let add = |link: &ChainLink, device: &str, name: &str| json!({ "device": device, "name": name, "link": link });
    let stranger = identity::device_link("Alice", PHONE, &phone_kp, &LongTermKeys::generate());
    let (status, body) = send_json(&addr, reqwest::Method::POST, "/api/devices", &alice.cookie, add(&stranger, PHONE, "Phone")).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("device link does not verify")),
        "only the identity key vouches for a device"
    );
    assert_eq!(
        send_json(&addr, reqwest::Method::POST, "/api/devices", &alice.cookie, add(&link, PHONE, " ")).await.0,
        400,
        "a name is required"
    );
    assert_eq!(
        send_json(&addr, reqwest::Method::POST, "/api/devices", &alice.cookie, add(&link, "d1", "Phone")).await.0,
        400,
        "not the primary id"
    );
    assert_eq!(
        send_json(&addr, reqwest::Method::POST, "/api/devices", &bob.cookie, add(&link, PHONE, "Phone")).await.0,
        400,
        "nor for another account"
    );
    assert_eq!(
        send_json(&addr, reqwest::Method::POST, "/api/devices", &alice.cookie, add(&link, PHONE, "Phone")).await.0,
        201
    );
    assert_eq!(
        send_json(&addr, reqwest::Method::POST, "/api/devices", &alice.cookie, add(&link, PHONE, "Phone")).await.0,
        409,
        "once"
    );
    assert_eq!(get_json(&addr, "/api/devices/offer", &alice.cookie).await.0, 404, "the offer is used up");

    let (_, me) = get_json(&addr, "/api/me", &alice.cookie).await;
    assert_eq!(me["devices"].as_array().unwrap().len(), 2);
    assert_eq!(
        me["devices"][1],
        json!({ "device": PHONE, "commitment": phone_kp.public_key.commitment_root, "kem": phone_lt.kem_pk })
    );
    let (_, keys) = get_json(&addr, &format!("/api/keys/alice?device={PHONE}"), &bob.cookie).await;
    let chain: Vec<ChainLink> = serde_json::from_value(keys["chain"].clone()).unwrap();
    assert!(
        identity::verify_device("alice", PHONE, &alice.lt.slh_pk, &chain).is_ok(),
        "anyone can check the device's chain"
    );
    assert_eq!(get_json(&addr, "/api/keys/alice?device=d0000000f", &bob.cookie).await.0, 404);

    let mut phone = Chat {
        ws: ws(&addr, "/ws", Some(&alice.cookie)).await.unwrap(),
        name: alice.name.clone(),
        keys: phone_kp.clone(),
        lt: phone_lt.clone(),
    };
    let welcome = phone.next_of("welcome").await.unwrap();
    assert_eq!(welcome["heads"], json!([alice.keys.public_key.commitment_root, phone_kp.public_key.commitment_root]));

    // sealed to every device of every member, each under its own label
    let to = [
        (identity::label("Alice", identity::PRIMARY), alice.lt.kem_pk.clone()),
        (identity::label("Alice", PHONE), phone_lt.kem_pk.clone()),
        b.recipient(),
    ];
    let env = serde_json::to_string(&pq::seal("from my phone", "alice", &to)).unwrap();
    phone.send(phone.frame(&env)).await;
    let got = b.next_of("message").await.expect("a linked device can send");
    assert_eq!((got["device"].as_str(), b.read(&got).as_deref()), (Some(PHONE), Some("from my phone")));
    let mine = laptop.next_of("message").await.unwrap();
    assert_eq!(laptop.read(&mine).as_deref(), Some("from my phone"), "the other device reads it too");

    // each device rotates on its own
    let next = hbss::keygen(hbss::N);
    phone.send(phone.rotation(&next)).await;
    let rot = b.next_of("rotate").await.unwrap();
    assert_eq!(
        (rot["device"].as_str(), rot["newCommitment"].as_str()),
        (Some(PHONE), Some(next.public_key.commitment_root.as_str()))
    );
    phone.keys = next.clone();
    let (_, dir) = get_json(&addr, "/api/directory", &bob.cookie).await;
    assert_eq!(
        dir["accounts"][0]["devices"],
        json!([{ "device": "d1", "head": alice.keys.public_key.commitment_root }, { "device": PHONE, "head": next.public_key.commitment_root }])
    );
    laptop.send(laptop.signed_for("from my laptop", &to)).await;
    assert_eq!(b.next_of("message").await.unwrap()["device"], "d1", "the primary device is unaffected");

    // removed: out of the directory, and it can no longer send
    assert_eq!(
        send_json(&addr, reqwest::Method::DELETE, &format!("/api/devices/{PHONE}"), &alice.cookie, json!({}))
            .await
            .0,
        204
    );
    assert_eq!(
        send_json(&addr, reqwest::Method::DELETE, &format!("/api/devices/{PHONE}"), &alice.cookie, json!({}))
            .await
            .0,
        404
    );
    phone.send(phone.frame(&env)).await;
    assert_eq!(phone.error().await, "commitment is not the account's current key");
    let (_, dir) = get_json(&addr, "/api/directory", &bob.cookie).await;
    assert_eq!(dir["accounts"][0]["devices"].as_array().unwrap().len(), 1);
    let (_, list) = get_json(&addr, "/api/devices", &alice.cookie).await;
    assert_eq!((list["devices"][1]["name"].as_str(), list["devices"][1]["removed"].as_bool()), (Some("Phone"), Some(true)));
}

#[tokio::test]
async fn a_recovery_removes_the_devices_linked_under_the_old_identity() {
    let addr = start(Config::default()).await;
    let alice = register(&addr, "Alice").await;
    let (_, _, link) = second_device(&alice, "d0000000b");
    let body = json!({ "device": "d0000000b", "name": "Tablet", "link": link });
    assert_eq!(send_json(&addr, reqwest::Method::POST, "/api/devices", &alice.cookie, body).await.0, 201);
    let (fresh, fresh_lt) = (hbss::keygen(hbss::N), LongTermKeys::generate());
    let recover = json!({ "password": PASSWORD, "root": fresh.public_key.commitment_root, "slh": fresh_lt.slh_pk, "kem": fresh_lt.kem_pk });
    assert_eq!(send_json(&addr, reqwest::Method::POST, "/api/recover", &alice.cookie, recover).await.0, 200);
    let (_, me) = get_json(&addr, "/api/me", &alice.cookie).await;
    assert_eq!(
        me["devices"],
        json!([{ "device": "d1", "commitment": fresh.public_key.commitment_root, "kem": fresh_lt.kem_pk }])
    );
}

#[tokio::test]
async fn messages_sealed_through_ratchet_sessions_are_relayed() {
    use hast_core::ratchet;
    let (_, mut alice, mut bob) = trio().await;
    let mut session = ratchet::Session::initiate(&bob.lt.kem_pk, &bob.lt.slh_pk, 0.0).unwrap();
    let (mut env, key) = ratchet::seal("forward secret", "alice");
    assert!(ratchet::add(&mut env, &key, "bob", &mut session, 0.0));
    alice.send(alice.frame(&serde_json::to_string(&env).unwrap())).await;
    let got = bob.next_of("message").await.expect("a ratchet envelope is accepted");
    let env: ratchet::Envelope = serde_json::from_str(got["message"].as_str().unwrap()).unwrap();
    let (_, text) = ratchet::open_new(&env, "bob", &bob.lt, &alice.lt.slh_pk, "alice", 0.0).unwrap();
    assert_eq!(text, "forward secret");

    let (empty, _) = ratchet::seal("to nobody", "alice");
    alice.send(alice.frame(&serde_json::to_string(&empty).unwrap())).await;
    assert_eq!(alice.error().await, "message must be an encrypted envelope");
}
