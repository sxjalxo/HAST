//! HAST server.
//!
//! * `hast-server`: serve everything on one port (`PORT`, default 8000).
//! * `hast-server user list`: accounts in the database.
//! * `hast-server user reset <name>`: set a new password read from stdin (ends the account's sessions).
//! * `hast-server user passkeys-off <name>`: remove the account's passkeys (lost authenticator), so the password signs
//!   in alone again.
//!
//! Configuration is read from `HAST_*` environment variables, see `Config::from_env`.
use hast_server::{auth, db::Db, serve, Config};

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("user") {
        return user_command(&cfg, &args[1..]);
    }
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8000);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await.expect("bind");
    println!("HAST: http://localhost:{port}  (LiveChat ws://localhost:{port}/ws, signup: {:?})", cfg.auth.signup);
    serve(listener, cfg).await.expect("server failed");
}

fn user_command(cfg: &Config, args: &[String]) {
    let db: Db = cfg.open_db().expect("open database");
    match args.first().map(String::as_str) {
        Some("list") => {
            for (name, created) in db.list_accounts() {
                println!("{name}\tcreated {created}");
            }
        }
        Some("reset") if args.len() == 2 => {
            let mut pw = String::new();
            eprintln!("New password for {} (one line on stdin):", args[1]);
            std::io::stdin().read_line(&mut pw).expect("read password");
            match auth::admin_reset_password(&db, &args[1], pw.trim_end_matches(['\r', '\n'])) {
                Ok(()) => println!("password changed; all sessions for {} ended", args[1]),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("passkeys-off") if args.len() == 2 => match auth::admin_remove_passkeys(&db, &args[1]) {
            Ok(n) => println!("removed {n} passkey(s) from {}; the password alone signs in again", args[1]),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
        _ => {
            eprintln!("usage: hast-server user list | hast-server user reset <name> | hast-server user passkeys-off <name>");
            std::process::exit(2);
        }
    }
}
