//! Test helper for the browser tests: creates an account the way HAST did before long-term keys existed (an
//! HBSS-only `hast-register-v1` link) in the given database, and prints the browser's stored key (the plain
//! `hast_keys:<name>` localStorage value of that era) on stdout.
//!
//! `cargo run -p hast-server --example seed_legacy -- <db file> <username> <password>`
use hast_core::{
    hbss,
    identity::{self, ChainLink},
};
use hast_server::{auth, db::Db};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [db, name, password] = &args[..] else {
        eprintln!("usage: seed_legacy <db file> <username> <password>");
        std::process::exit(2);
    };
    let db = Db::open(std::path::Path::new(db)).expect("open database");
    let kp = hbss::keygen(hbss::N);
    let root = kp.public_key.commitment_root.clone();
    let link = ChainLink {
        signature: Some(hbss::sign_with_proofs(&identity::legacy_registration_payload(name, &root), &kp)),
        root,
        ..Default::default()
    };
    db.create_account(name, &auth::hash_password(password), &link).expect("create account");
    println!("{}", serde_json::to_string(&kp).unwrap());
}
