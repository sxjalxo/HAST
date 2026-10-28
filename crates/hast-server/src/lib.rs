//! One origin serves everything: the built UI, the account API, LiveChat (`/ws`) and messaging
//! (`/api/messaging/*`, `/ws/messaging`). `main.rs` runs it; the integration tests start it on an ephemeral port.
pub mod auth;
pub mod chat;
pub mod db;
pub mod devices;
pub mod messaging;
pub mod passkey;

use auth::{Auth, AuthConfig, Signup};
use axum::{
    extract::{Request, State},
    http::{header, HeaderValue},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{io, net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

#[derive(Clone, Default)]
pub struct Config {
    /// SQLite file for accounts and sessions; `None` keeps everything in memory (tests).
    pub db_path: Option<PathBuf>,
    /// JSON-lines chat history from before history lived in the database; imported once, then renamed.
    pub history_file: Option<PathBuf>,
    /// JSON messaging store from before messages lived in the database; imported once, then renamed.
    pub messaging_import: Option<PathBuf>,
    /// Built UI to serve at `/`.
    pub static_dir: Option<String>,
    pub auth: AuthConfig,
}

impl Config {
    /// Defaults for a real deployment, overridable with `HAST_*` environment variables.
    pub fn from_env() -> Config {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let mut auth = AuthConfig {
            signup: match var("HAST_SIGNUP").as_deref() {
                Some("invite") => Signup::Invite,
                Some("closed") => Signup::Closed,
                _ => Signup::Open,
            },
            invite_code: var("HAST_INVITE_CODE"),
            cookie_secure: matches!(var("HAST_COOKIE_SECURE").as_deref(), Some("1" | "true")),
            extra_origins: var("HAST_ALLOWED_ORIGINS")
                .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            trusted_proxies: var("HAST_TRUSTED_PROXIES")
                .map(|v| v.split(',').filter_map(|s| s.trim().parse().ok()).collect())
                .unwrap_or_default(),
            rp_id: var("HAST_RP_ID"),
            ..AuthConfig::default()
        };
        if let Some(days) = var("HAST_SESSION_DAYS").and_then(|d| d.parse::<u64>().ok()) {
            auth.session_ttl_secs = days * 24 * 3600;
        }
        Config {
            db_path: Some(var("HAST_DB").unwrap_or_else(|| "hast.db".into()).into()),
            history_file: Some(var("HAST_HISTORY_FILE").unwrap_or_else(|| "_chat_history.jsonl".into()).into()),
            messaging_import: Some(var("HAST_MESSAGING_STORE").unwrap_or_else(|| "_gd_fallback_storage.json".into()).into()),
            static_dir: var("HAST_STATIC_DIR"),
            auth,
        }
    }

    pub fn open_db(&self) -> io::Result<db::Db> {
        match &self.db_path {
            Some(p) => db::Db::open(p),
            None => db::Db::memory(),
        }
        .map_err(|e| io::Error::other(e.to_string()))
    }
}

/// Content-Security-Policy for the UI. Keys live in the page, so injected script is the main threat: only our own
/// files may run, plus trunk's inline loader, allowed by its hash (taken from the built `index.html`).
pub fn content_security_policy(index_html: Option<&str>) -> String {
    let mut hashes = String::new();
    let mut rest = index_html.unwrap_or_default();
    while let Some(start) = rest.find("<script") {
        let after = &rest[start..];
        let (Some(open_end), Some(close)) = (after.find('>'), after.find("</script>")) else {
            break;
        };
        if !after[..open_end].contains("src=") && open_end < close {
            let body = &after[open_end + 1..close];
            hashes.push_str(&format!(" 'sha256-{}'", hast_core::hbss::base64_bytes(&Sha256::digest(body.as_bytes()))));
        }
        rest = &after[close + "</script>".len()..];
    }
    format!(
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'{hashes}; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data: blob:; media-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; \
         form-action 'self'; frame-ancestors 'none'"
    )
}

async fn security_headers(State(csp): State<Arc<HeaderValue>>, req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, (*csp).clone());
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    r
}

pub fn build(cfg: Config) -> io::Result<Router> {
    let started = Instant::now();
    let auth = Auth::new(cfg.open_db()?, cfg.auth.clone());
    let mut router = Router::new()
        .route(
            "/health",
            get(move || async move { Json(json!({ "status": "healthy", "uptime": started.elapsed().as_secs() })) }),
        )
        .merge(auth::router(auth.clone()))
        .merge(chat::router(chat::Chat::new(auth.clone(), cfg.history_file.clone())))
        .merge(passkey::router(auth.clone()))
        .merge(devices::router(auth.clone()))
        .merge(messaging::router(messaging::Messaging::new(auth, cfg.messaging_import.clone())));
    let index = cfg.static_dir.as_ref().and_then(|d| std::fs::read_to_string(format!("{d}/index.html")).ok());
    let csp = Arc::new(HeaderValue::from_str(&content_security_policy(index.as_deref())).map_err(io::Error::other)?);
    router = match cfg.static_dir {
        Some(dir) => router.fallback_service(ServeDir::new(&dir).fallback(ServeFile::new(format!("{dir}/index.html")))),
        None => router.route("/", get(|| async { Json(json!({ "name": "HAST", "ws": "/ws" })) })),
    };
    Ok(router.layer(middleware::from_fn_with_state(csp, security_headers)))
}

pub async fn serve(listener: TcpListener, cfg: Config) -> io::Result<()> {
    axum::serve(listener, build(cfg)?.into_make_service_with_connect_info::<SocketAddr>()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_allows_only_our_inline_loader() {
        let html = r#"<head><script type="module">import init from '/a.js';</script><script src="/x.js"></script></head>"#;
        let csp = content_security_policy(Some(html));
        let want = hast_core::hbss::base64_bytes(&Sha256::digest(b"import init from '/a.js';"));
        assert!(csp.contains(&format!("'sha256-{want}'")), "{csp}");
        assert_eq!(csp.matches("'sha256-").count(), 1, "external scripts need no hash");
        assert!(!csp.contains("'unsafe-inline';") || csp.contains("style-src 'self' 'unsafe-inline'"));
        assert!(content_security_policy(None).contains("script-src 'self' 'wasm-unsafe-eval';"));
    }
}
