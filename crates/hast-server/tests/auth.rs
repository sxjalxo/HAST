//! Account API against a real server: signup, login, sessions, throttling, CSRF, recovery, key directory.
mod common;
use common::*;
use hast_core::{
    hbss,
    identity::{self, ChainLink, LinkKind},
    pq::LongTermKeys,
};
use hast_server::{
    auth::{AuthConfig, Signup},
    Config,
};
use serde_json::{json, Value};

async fn server() -> String {
    start(Config::default()).await
}

#[tokio::test]
async fn register_sets_a_locked_down_session_cookie_and_me_works() {
    let addr = server().await;
    let keys = keys();
    let resp = http()
        .post(format!("http://{addr}/api/register"))
        .json(&register_body("Alice", PASSWORD, &keys))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let raw = resp.headers().get("set-cookie").unwrap().to_str().unwrap().to_string();
    assert!(raw.contains("HttpOnly") && raw.contains("SameSite=Strict") && raw.contains("Path=/"), "{raw}");
    assert!(!raw.contains("Secure"), "Secure is opt-in for HTTPS deployments");
    let cookie = raw.split(';').next().unwrap().to_string();

    let me: Value = http()
        .get(format!("http://{addr}/api/me"))
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["username"], "Alice");
    assert_eq!(me["commitment"], keys.0.public_key.commitment_root);
    assert_eq!(
        (&me["slh"], &me["kem"]),
        (&json!(keys.1.slh_pk), &json!(keys.1.kem_pk)),
        "the client learns its long-term keys"
    );
    assert_eq!(http().get(format!("http://{addr}/api/me")).send().await.unwrap().status(), 401);
    assert_eq!(
        http()
            .get(format!("http://{addr}/api/me"))
            .header("Cookie", "hast_session=forged")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
}

#[tokio::test]
async fn secure_flag_is_added_when_configured() {
    let addr = start(Config {
        auth: AuthConfig {
            cookie_secure: true,
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let keys = keys();
    let resp = http()
        .post(format!("http://{addr}/api/register"))
        .json(&register_body("alice", PASSWORD, &keys))
        .send()
        .await
        .unwrap();
    assert!(resp.headers().get("set-cookie").unwrap().to_str().unwrap().contains("; Secure"));
}

#[tokio::test]
async fn register_validates_everything() {
    let addr = server().await;
    let post = |body: Value| {
        let addr = addr.clone();
        async move { http().post(format!("http://{addr}/api/register")).json(&body).send().await.unwrap() }
    };
    let keys = keys();

    assert_eq!(post(register_body("al", PASSWORD, &keys)).await.status(), 400, "short name");
    assert_eq!(post(register_body("a b c", PASSWORD, &keys)).await.status(), 400, "bad characters");
    assert_eq!(post(register_body("alice", "short", &keys)).await.status(), 400, "short password");

    // proof for another name, from another key, or without long-term keys
    let mut b = register_body("alice", PASSWORD, &keys);
    b["link"] = json!(identity::register_link("bob", &keys.0, &keys.1));
    assert_eq!(post(b).await.status(), 400, "proof for a different name");
    let mut b = register_body("alice", PASSWORD, &keys);
    b["link"]["root"] = json!(hbss::keygen(hbss::N).public_key.commitment_root);
    assert_eq!(post(b).await.status(), 400, "root without a matching proof");
    let mut b = register_body("alice", PASSWORD, &keys);
    b["link"]["cosig"] = json!(LongTermKeys::generate().sign("x"));
    assert_eq!(post(b).await.status(), 400, "SLH-DSA proof missing");
    let root = keys.0.public_key.commitment_root.clone();
    let legacy = ChainLink {
        signature: Some(hbss::sign_with_proofs(&identity::legacy_registration_payload("alice", &root), &keys.0)),
        root,
        ..Default::default()
    };
    let mut b = register_body("alice", PASSWORD, &keys);
    b["link"] = json!(legacy);
    assert_eq!(post(b).await.status(), 400, "a valid HBSS-only registration is no longer enough for a new account");

    assert_eq!(post(register_body("Alice", PASSWORD, &keys)).await.status(), 201);
    assert_eq!(post(register_body("ALICE", PASSWORD, &common::keys())).await.status(), 409, "names are case-insensitive");
    assert_eq!(post(register_body("carol", PASSWORD, &keys)).await.status(), 409, "a key belongs to one account");
}

#[tokio::test]
async fn login_logout_and_identical_failures() {
    let addr = server().await;
    register(&addr, "alice").await;

    let ok = login(&addr, "ALICE", PASSWORD).await;
    assert_eq!(ok.status(), 200);
    let cookie = cookie_of(&ok).unwrap();
    assert_eq!(http().get(format!("http://{addr}/api/me")).header("Cookie", &cookie).send().await.unwrap().status(), 200);

    let (wrong, unknown) = (login(&addr, "alice", "not the password").await, login(&addr, "nobody", PASSWORD).await);
    assert_eq!((wrong.status().as_u16(), unknown.status().as_u16()), (401, 401));
    assert_eq!(wrong.text().await.unwrap(), unknown.text().await.unwrap(), "no way to tell which usernames exist");

    let out = http().post(format!("http://{addr}/api/logout")).header("Cookie", &cookie).send().await.unwrap();
    assert_eq!(out.status(), 204);
    assert!(out.headers().get("set-cookie").unwrap().to_str().unwrap().contains("Max-Age=0"));
    assert_eq!(
        http().get(format!("http://{addr}/api/me")).header("Cookie", &cookie).send().await.unwrap().status(),
        401,
        "the session is dead server-side"
    );
}

#[tokio::test]
async fn repeated_failures_lock_the_name_even_for_the_right_password() {
    let addr = server().await;
    register(&addr, "alice").await;
    for _ in 0..4 {
        assert_eq!(login(&addr, "alice", "wrong password!").await.status(), 401);
    }
    assert_eq!(login(&addr, "alice", "wrong password!").await.status(), 401, "5th failure triggers the lock");
    let locked = login(&addr, "alice", PASSWORD).await;
    assert_eq!(locked.status(), 429);
    assert!(locked.headers().get("retry-after").is_some());
    assert_eq!(login(&addr, "bob", "irrelevant password").await.status(), 401, "other names are not affected");
}

#[tokio::test]
async fn cross_site_posts_are_refused() {
    let addr = server().await;
    register(&addr, "alice").await;
    let evil = http()
        .post(format!("http://{addr}/api/login"))
        .header("Origin", "http://evil.example")
        .json(&json!({ "username": "alice", "password": PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(evil.status(), 403);
    let same = http()
        .post(format!("http://{addr}/api/login"))
        .header("Origin", format!("http://{addr}"))
        .json(&json!({ "username": "alice", "password": PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(same.status(), 200);
}

#[tokio::test]
async fn signup_modes() {
    let closed = start(Config {
        auth: AuthConfig {
            signup: Signup::Closed,
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    assert_eq!(
        http()
            .post(format!("http://{closed}/api/register"))
            .json(&register_body("alice", PASSWORD, &keys()))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    let invite = start(Config {
        auth: AuthConfig {
            signup: Signup::Invite,
            invite_code: Some("let-me-in".into()),
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let url = format!("http://{invite}/api/register");
    assert_eq!(http().post(&url).json(&register_body("alice", PASSWORD, &keys())).send().await.unwrap().status(), 403);
    let mut wrong = register_body("alice", PASSWORD, &keys());
    wrong["invite"] = json!("guess");
    assert_eq!(http().post(&url).json(&wrong).send().await.unwrap().status(), 403);
    let mut right = register_body("alice", PASSWORD, &keys());
    right["invite"] = json!("let-me-in");
    assert_eq!(http().post(&url).json(&right).send().await.unwrap().status(), 201);
}

#[tokio::test]
async fn key_directory_needs_a_session_and_returns_a_verifiable_chain() {
    let addr = server().await;
    let alice = register(&addr, "Alice").await;
    let bob = register(&addr, "bob").await;
    let url = format!("http://{addr}/api/keys/alice");
    assert_eq!(http().get(&url).send().await.unwrap().status(), 401);
    assert_eq!(http().get(format!("http://{addr}/api/directory")).send().await.unwrap().status(), 401);
    assert_eq!(
        http()
            .get(format!("http://{addr}/api/keys/nobody"))
            .header("Cookie", &bob.cookie)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let body: Value = http().get(&url).header("Cookie", &bob.cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["username"], "Alice");
    let chain: Vec<ChainLink> = serde_json::from_value(body["chain"].clone()).unwrap();
    let verified = identity::verify_chain("alice", &chain).expect("a stranger can verify the chain from the name alone");
    assert_eq!(verified.roots, vec![alice.keys.public_key.commitment_root.clone()]);
    assert_eq!(verified.kem, Some(alice.lt.kem_pk.clone()), "and learn whom to encrypt to");
}

#[tokio::test]
async fn recovery_appends_a_flagged_link_and_needs_the_password() {
    let addr = server().await;
    let alice = register(&addr, "alice").await;
    // a second device logs in with the password but has no key
    let device2 = cookie_of(&login(&addr, "alice", PASSWORD).await).unwrap();
    let (fresh, fresh_lt) = keys();
    let recover = |cookie: String, password: &str, root: String| {
        let (addr, password) = (addr.clone(), password.to_string());
        let (slh, kem) = (fresh_lt.slh_pk.clone(), fresh_lt.kem_pk.clone());
        async move {
            http()
                .post(format!("http://{addr}/api/recover"))
                .header("Cookie", cookie)
                .json(&json!({ "password": password, "root": root, "slh": slh, "kem": kem }))
                .send()
                .await
                .unwrap()
        }
    };

    assert_eq!(recover(device2.clone(), "the wrong password", fresh.public_key.commitment_root.clone()).await.status(), 401);
    assert_eq!(
        recover(String::new(), PASSWORD, fresh.public_key.commitment_root.clone()).await.status(),
        401,
        "needs a session"
    );
    assert_eq!(
        recover(device2.clone(), PASSWORD, alice.keys.public_key.commitment_root.clone()).await.status(),
        409,
        "the key is already current / in use"
    );
    assert_eq!(recover(device2.clone(), PASSWORD, "nothex".into()).await.status(), 400);
    let bad_kem = http()
        .post(format!("http://{addr}/api/recover"))
        .header("Cookie", &device2)
        .json(&json!({ "password": PASSWORD, "root": fresh.public_key.commitment_root, "slh": fresh_lt.slh_pk, "kem": "00" }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_kem.status(), 400, "malformed encryption key");
    assert_eq!(recover(device2.clone(), PASSWORD, fresh.public_key.commitment_root.clone()).await.status(), 200);

    let body: Value = http()
        .get(format!("http://{addr}/api/keys/alice"))
        .header("Cookie", &device2)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let chain: Vec<ChainLink> = serde_json::from_value(body["chain"].clone()).unwrap();
    assert_eq!(chain.last().unwrap().kind, LinkKind::Recovery);
    let v = identity::verify_chain("alice", &chain).unwrap();
    assert_eq!((v.roots.len(), v.recoveries), (2, vec![1]));
    let me: Value = http()
        .get(format!("http://{addr}/api/me"))
        .header("Cookie", &device2)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["commitment"], fresh.public_key.commitment_root, "the recovered key is now the account's key");
    assert_eq!(me["kem"], json!(fresh_lt.kem_pk), "with the new encryption key");
    assert_eq!(v.kem, Some(fresh_lt.kem_pk.clone()));
}

#[tokio::test]
async fn changing_the_password_ends_other_sessions() {
    let addr = server().await;
    let alice = register(&addr, "alice").await;
    let other = cookie_of(&login(&addr, "alice", PASSWORD).await).unwrap();
    let change = |old: &str, new: &str| {
        let (addr, cookie, old, new) = (addr.clone(), alice.cookie.clone(), old.to_string(), new.to_string());
        async move {
            http()
                .post(format!("http://{addr}/api/password"))
                .header("Cookie", cookie)
                .json(&json!({ "old": old, "new": new }))
                .send()
                .await
                .unwrap()
        }
    };
    assert_eq!(change("wrong old password", "a brand new password").await.status(), 401);
    assert_eq!(change(PASSWORD, "short").await.status(), 400);
    assert_eq!(change(PASSWORD, "a brand new password").await.status(), 204);

    assert_eq!(
        http().get(format!("http://{addr}/api/me")).header("Cookie", &alice.cookie).send().await.unwrap().status(),
        200,
        "this device stays signed in"
    );
    assert_eq!(
        http().get(format!("http://{addr}/api/me")).header("Cookie", &other).send().await.unwrap().status(),
        401,
        "others are signed out"
    );
    assert_eq!(login(&addr, "alice", PASSWORD).await.status(), 401);
    assert_eq!(login(&addr, "alice", "a brand new password").await.status(), 200);
}

#[tokio::test]
async fn health_is_public_and_sockets_need_a_session() {
    let addr = server().await;
    let health = http().get(format!("http://{addr}/health")).send().await.unwrap();
    assert_eq!(health.status(), 200);
    let csp = health.headers().get("content-security-policy").expect("CSP on every response").to_str().unwrap();
    assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"), "{csp}");
    assert_eq!(health.headers().get("x-content-type-options").unwrap(), "nosniff");
    for path in ["/ws", "/ws/messaging"] {
        let err = ws(&addr, path, None).await.expect_err("handshake must fail without a session");
        assert!(err.to_string().contains("401"), "{path}: {err}");
    }
}
