//! The expensive operations behind one JSON entry point, so the browser can run them in a Web Worker (and fall
//! back to running them in the page): password key derivation, SLH-DSA signing and verification, building
//! signed chain links, and whole-chain verification.
use crate::{hbss::KeyPair, identity, pq};
use serde_json::{json, Value};

fn s<'a>(req: &'a Value, k: &str) -> &'a str {
    req[k].as_str().unwrap_or_default()
}

fn field<T: serde::de::DeserializeOwned + Default>(req: &Value, k: &str) -> T {
    serde_json::from_value(req[k].clone()).unwrap_or_default()
}

/// `req["op"]` names the operation; the result is JSON (`null` when the request is malformed or a check fails).
pub fn run(req: &Value) -> Value {
    match s(req, "op") {
        "derive_key" => json!(hex::encode(pq::derive_key(s(req, "password"), &hex::decode(s(req, "salt")).unwrap_or_default()))),
        "slh_sign" => json!(field::<pq::LongTermKeys>(req, "keys").sign(s(req, "message"))),
        "slh_verify" => json!(pq::slh_verify(s(req, "pk"), s(req, "message"), s(req, "sig"))),
        "register_link" => json!(identity::register_link(s(req, "username"), &field::<KeyPair>(req, "kp"), &field(req, "keys"))),
        "rotate_link" => json!(identity::rotate_link(&field::<KeyPair>(req, "kp"), s(req, "newRoot"), &field(req, "keys"))),
        "verify_chain" => match identity::verify_chain(s(req, "username"), &field::<Vec<identity::ChainLink>>(req, "links")) {
            Ok(v) => json!(v),
            Err(_) => Value::Null,
        },
        "extend_chain" => match identity::extend_chain(field(req, "verified"), &field::<Vec<identity::ChainLink>>(req, "links")) {
            Ok(v) => json!(v),
            Err(_) => Value::Null,
        },
        "device_link" => json!(identity::device_link(
            s(req, "username"),
            s(req, "device"),
            &field::<KeyPair>(req, "kp"),
            &field(req, "keys")
        )),
        "verify_device" => match identity::verify_device(s(req, "username"), s(req, "device"), s(req, "identity"), &field::<Vec<identity::ChainLink>>(req, "links")) {
            Ok(v) => json!(v),
            Err(_) => Value::Null,
        },
        "extend_device" => match identity::extend_device(field(req, "verified"), &field::<Vec<identity::ChainLink>>(req, "links")) {
            Ok(v) => json!(v),
            Err(_) => Value::Null,
        },
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hbss;

    #[test]
    fn jobs_match_the_direct_calls() {
        let (kp, lt) = (hbss::keygen(hbss::N), pq::LongTermKeys::generate());
        let sig = run(&json!({ "op": "slh_sign", "keys": lt, "message": "m" }));
        assert_eq!(run(&json!({ "op": "slh_verify", "pk": lt.slh_pk, "message": "m", "sig": sig })), json!(true));
        assert_eq!(run(&json!({ "op": "slh_verify", "pk": lt.slh_pk, "message": "x", "sig": sig })), json!(false));

        let link: identity::ChainLink = serde_json::from_value(run(&json!({ "op": "register_link", "username": "alice", "kp": kp, "keys": lt }))).unwrap();
        let chain = run(&json!({ "op": "verify_chain", "username": "alice", "links": [link] }));
        let v: identity::VerifiedChain = serde_json::from_value(chain).unwrap();
        assert_eq!(v.roots, vec![kp.public_key.commitment_root.clone()]);
        assert_eq!(run(&json!({ "op": "verify_chain", "username": "bob", "links": [] })), Value::Null);

        let dk = hbss::keygen(hbss::N);
        let dlink = run(&json!({ "op": "device_link", "username": "alice", "device": "d0123abcd", "kp": dk, "keys": lt }));
        let dv = run(&json!({ "op": "verify_device", "username": "alice", "device": "d0123abcd", "identity": lt.slh_pk, "links": [dlink] }));
        assert_eq!(dv["roots"], json!([dk.public_key.commitment_root]));
        assert_eq!(run(&json!({ "op": "extend_device", "verified": dv, "links": [] }))["roots"], dv["roots"]);

        let key = run(&json!({ "op": "derive_key", "password": "pw", "salt": "00112233445566778899aabbccddeeff" }));
        assert_eq!(key, json!(hex::encode(pq::derive_key("pw", &hex::decode("00112233445566778899aabbccddeeff").unwrap()))));
        assert_eq!(run(&json!({ "op": "nope" })), Value::Null);
    }
}
