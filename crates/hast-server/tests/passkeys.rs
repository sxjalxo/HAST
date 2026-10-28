//! Passkeys over HTTP, with a software authenticator (ES256): registering, the two-step sign-in, and removing one.
mod common;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64U, Engine};
use ciborium::Value as Cbor;
use common::*;
use hast_server::Config;
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// What a browser's authenticator does, for one credential on `127.0.0.1`.
struct Authenticator {
    kp: EcdsaKeyPair,
    rng: SystemRandom,
    id: Vec<u8>,
    count: u32,
}

impl Authenticator {
    fn new() -> Authenticator {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let mut id = vec![0u8; 16];
        ring::rand::SecureRandom::fill(&rng, &mut id).unwrap();
        Authenticator { kp, rng, id, count: 0 }
    }

    fn cbor(v: &Cbor) -> Vec<u8> {
        let mut out = vec![];
        ciborium::ser::into_writer(v, &mut out).unwrap();
        out
    }

    /// `navigator.credentials.create` for `options`, answering as if on `origin`.
    fn create(&self, options: &Value, origin: &str) -> Value {
        let rp = options["rp"]["id"].as_str().unwrap();
        let pk = self.kp.public_key().as_ref();
        let key = Cbor::Map(vec![
            (1.into(), 2.into()),
            (3.into(), (-7).into()),
            ((-1).into(), 1.into()),
            ((-2).into(), Cbor::Bytes(pk[1..33].to_vec())),
            ((-3).into(), Cbor::Bytes(pk[33..].to_vec())),
        ]);
        let mut ad = Sha256::digest(rp.as_bytes()).to_vec();
        ad.push(0x41); // user present, attested credential data
        ad.extend(0u32.to_be_bytes());
        ad.extend([0u8; 16]);
        ad.extend((self.id.len() as u16).to_be_bytes());
        ad.extend(&self.id);
        ad.extend(Self::cbor(&key));
        let att = Self::cbor(&Cbor::Map(vec![
            ("fmt".into(), "none".into()),
            ("attStmt".into(), Cbor::Map(vec![])),
            ("authData".into(), Cbor::Bytes(ad)),
        ]));
        let cd = json!({ "type": "webauthn.create", "challenge": options["challenge"], "origin": origin }).to_string();
        json!({ "id": B64U.encode(&self.id), "clientDataJSON": B64U.encode(cd), "attestationObject": B64U.encode(att) })
    }

    /// `navigator.credentials.get` for `options`.
    fn get(&mut self, options: &Value, origin: &str) -> Value {
        self.count += 1;
        let mut ad = Sha256::digest(options["rpId"].as_str().unwrap().as_bytes()).to_vec();
        ad.push(0x01);
        ad.extend(self.count.to_be_bytes());
        let cd = json!({ "type": "webauthn.get", "challenge": options["challenge"], "origin": origin }).to_string();
        let sig = self.kp.sign(&self.rng, &[&ad[..], &Sha256::digest(cd.as_bytes())[..]].concat()).unwrap();
        json!({ "id": B64U.encode(&self.id), "clientDataJSON": B64U.encode(cd), "authenticatorData": B64U.encode(ad), "signature": B64U.encode(sig.as_ref()) })
    }
}

async fn post(addr: &str, path: &str, cookie: Option<&str>, body: Value) -> reqwest::Response {
    let mut r = http().post(format!("http://{addr}{path}")).header("Origin", format!("http://{addr}")).json(&body);
    if let Some(c) = cookie {
        r = r.header("Cookie", c);
    }
    r.send().await.unwrap()
}

async fn add_passkey(addr: &str, cookie: &str, auth: &Authenticator) -> reqwest::Response {
    let options: Value = post(addr, "/api/passkeys/options", Some(cookie), json!({})).await.json().await.unwrap();
    let mut answer = auth.create(&options, &format!("http://{addr}"));
    answer["name"] = json!("laptop");
    post(addr, "/api/passkeys", Some(cookie), answer).await
}

#[tokio::test]
async fn registering_a_passkey_checks_the_challenge_origin_and_site() {
    let addr = start(Config::default()).await;
    let alice = register(&addr, "alice").await;
    let origin = format!("http://{addr}");
    assert_eq!(post(&addr, "/api/passkeys/options", None, json!({})).await.status(), 401, "signed in only");

    let auth = Authenticator::new();
    let options: Value = post(&addr, "/api/passkeys/options", Some(&alice.cookie), json!({})).await.json().await.unwrap();
    assert_eq!(options["rp"]["id"], "127.0.0.1");
    assert_eq!(options["attestation"], "none");

    // an answer from another origin, or to an old challenge, is refused (and uses up the challenge)
    let reason = |r: reqwest::Response| async move { (r.status().as_u16(), r.json::<Value>().await.unwrap()["error"].as_str().unwrap_or_default().to_string()) };
    let r = post(&addr, "/api/passkeys", Some(&alice.cookie), auth.create(&options, "http://evil.example")).await;
    assert_eq!(reason(r).await, (400, "origin does not match".to_string()));
    let r = post(&addr, "/api/passkeys", Some(&alice.cookie), auth.create(&options, &origin)).await;
    assert_eq!(
        reason(r).await,
        (400, "no passkey registration in progress (or it expired)".to_string()),
        "the challenge is single-use"
    );

    let r = add_passkey(&addr, &alice.cookie, &auth).await;
    assert_eq!(r.status(), 201);
    let list: Value = http()
        .get(format!("http://{addr}/api/passkeys"))
        .header("Cookie", &alice.cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["passkeys"][0]["name"], "laptop");
    assert_eq!(add_passkey(&addr, &alice.cookie, &auth).await.status(), 409, "the same passkey twice");
}

#[tokio::test]
async fn with_a_passkey_the_password_alone_no_longer_signs_in() {
    let addr = start(Config::default()).await;
    let bob = register(&addr, "bob").await;
    let origin = format!("http://{addr}");
    let mut auth = Authenticator::new();
    assert_eq!(add_passkey(&addr, &bob.cookie, &auth).await.status(), 201);

    // step one: the right password gives a challenge, not a session
    let r = login(&addr, "bob", PASSWORD).await;
    assert_eq!(r.status(), 200);
    assert!(cookie_of(&r).is_none(), "no session yet");
    let step: Value = r.json().await.unwrap();
    let (pending, options) = (step["passkey"]["pending"].clone(), step["passkey"]["options"].clone());
    assert_eq!(options["allowCredentials"][0]["id"], B64U.encode(&auth.id));

    // a forged answer fails, and the attempt is used up
    let mut forged = auth.get(&options, &origin);
    forged["pending"] = pending.clone();
    forged["signature"] = json!(B64U.encode([1u8; 70]));
    let r = post(&addr, "/api/login/passkey", None, forged).await;
    assert_eq!(r.status(), 401);
    assert_eq!(r.json::<Value>().await.unwrap()["error"], "the passkey's signature does not verify");
    let mut late = auth.get(&options, &origin);
    late["pending"] = pending;
    assert_eq!(post(&addr, "/api/login/passkey", None, late).await.status(), 401, "a pending sign-in is single-use");

    // step two: the passkey's answer starts the session
    let step: Value = login(&addr, "bob", PASSWORD).await.json().await.unwrap();
    let mut answer = auth.get(&step["passkey"]["options"], &origin);
    answer["pending"] = step["passkey"]["pending"].clone();
    let r = post(&addr, "/api/login/passkey", None, answer).await;
    assert_eq!(r.status(), 200);
    let cookie = cookie_of(&r).expect("session cookie");
    let me: Value = http()
        .get(format!("http://{addr}/api/me"))
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["username"], "bob");

    // a copied passkey shows up as a counter that does not go up
    let step: Value = login(&addr, "bob", PASSWORD).await.json().await.unwrap();
    auth.count -= 1;
    let mut stale = auth.get(&step["passkey"]["options"], &origin);
    stale["pending"] = step["passkey"]["pending"].clone();
    let r = post(&addr, "/api/login/passkey", None, stale).await;
    assert_eq!(r.status(), 401);
    assert_eq!(r.json::<Value>().await.unwrap()["error"], "the passkey's counter went backwards (it may have been copied)");
}

#[tokio::test]
async fn removing_a_passkey_needs_the_password() {
    let addr = start(Config::default()).await;
    let cara = register(&addr, "cara").await;
    let auth = Authenticator::new();
    assert_eq!(add_passkey(&addr, &cara.cookie, &auth).await.status(), 201);
    let url = format!("http://{addr}/api/passkeys/{}", B64U.encode(&auth.id));
    let del = |pw: &str| {
        http()
            .delete(&url)
            .header("Origin", format!("http://{addr}"))
            .header("Cookie", &cara.cookie)
            .json(&json!({ "password": pw }))
            .send()
    };
    assert_eq!(del("wrong password!").await.unwrap().status(), 401);
    assert_eq!(del(PASSWORD).await.unwrap().status(), 204);
    let r = login(&addr, "cara", PASSWORD).await;
    assert!(cookie_of(&r).is_some(), "the password signs in alone again");
}
