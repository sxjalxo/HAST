//! Helpers: start a real server on an ephemeral port, register accounts over HTTP, open WebSockets with a session cookie.
#![allow(dead_code, clippy::result_large_err)]
use hast_core::{
    hbss::{self, KeyPair},
    identity,
    pq::LongTermKeys,
};
use hast_server::{serve, Config};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue},
    MaybeTlsStream, WebSocketStream,
};

pub type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
pub const PASSWORD: &str = "correct horse battery";

pub async fn start(cfg: Config) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(serve(listener, cfg));
    addr
}

pub fn http() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

pub struct Account {
    pub name: String,
    pub cookie: String,
    pub keys: KeyPair,
    pub lt: LongTermKeys,
}

/// `hast_session=<token>` from a response's Set-Cookie header.
pub fn cookie_of(resp: &reqwest::Response) -> Option<String> {
    let raw = resp.headers().get("set-cookie")?.to_str().ok()?;
    Some(raw.split(';').next()?.to_string())
}

/// A fresh HBSS key and long-term keys, as a browser creates them at signup.
pub fn keys() -> (KeyPair, LongTermKeys) {
    (hbss::keygen(hbss::N), LongTermKeys::generate())
}

pub fn register_body(name: &str, password: &str, keys: &(KeyPair, LongTermKeys)) -> Value {
    json!({ "username": name, "password": password, "link": identity::register_link(name, &keys.0, &keys.1) })
}

pub async fn register(addr: &str, name: &str) -> Account {
    let keys = keys();
    let resp = http()
        .post(format!("http://{addr}/api/register"))
        .json(&register_body(name, PASSWORD, &keys))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "register {name}");
    Account {
        name: name.into(),
        cookie: cookie_of(&resp).expect("session cookie"),
        keys: keys.0,
        lt: keys.1,
    }
}

pub async fn login(addr: &str, name: &str, password: &str) -> reqwest::Response {
    http()
        .post(format!("http://{addr}/api/login"))
        .json(&json!({ "username": name, "password": password }))
        .send()
        .await
        .unwrap()
}

pub async fn ws(addr: &str, path: &str, cookie: Option<&str>) -> Result<Ws, tokio_tungstenite::tungstenite::Error> {
    let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
    if let Some(c) = cookie {
        req.headers_mut().insert("Cookie", HeaderValue::from_str(c).unwrap());
    }
    connect_async(req).await.map(|(s, _)| s)
}
