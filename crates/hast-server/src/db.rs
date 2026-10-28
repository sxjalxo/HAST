//! SQLite store: accounts, key chains (one per device), sessions, LiveChat frames and messaging messages.
use hast_core::identity::{ChainLink, LinkKind, PRIMARY};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::{path::Path, sync::Mutex};

#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub id: i64,
    pub username: String,
}

#[derive(Debug, PartialEq)]
pub enum CreateError {
    UsernameTaken,
    KeyTaken,
    Other(String),
}

pub struct Db(Mutex<Connection>);

/// A registered passkey: its credential id (base64url), public key (`passkey::CoseKey` as JSON) and counter.
pub struct StoredPasskey {
    pub cred_id: String,
    pub public_key: String,
    pub sign_count: u32,
    pub name: String,
    pub created_at: u64,
}

/// One of an account's devices: its chain's current root, and whether it was removed.
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceRow {
    pub device: String,
    pub name: String,
    pub created_at: u64,
    pub removed: bool,
    pub head: String,
}

/// An account in the directory: name, primary root (the identity), and `(device, root)` of each active device.
pub type DirEntry = (String, String, Vec<(String, String)>);

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// Schema steps, applied in order; `PRAGMA user_version` records how many have run. Append new steps, never
/// edit a shipped one. Step 1 uses `IF NOT EXISTS` because databases from before versioning already have it.
const MIGRATIONS: &[&str] = &[
    "
CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL,
    username_lc   TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS key_chain (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    root       TEXT NOT NULL UNIQUE,
    old_root   TEXT,
    signature  TEXT,
    at         INTEGER NOT NULL,
    UNIQUE (account_id, seq)
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);",
    // long-term keys: SLH-DSA co-signing key, ML-KEM encryption key, SLH-DSA co-signature
    "
ALTER TABLE key_chain ADD COLUMN slh TEXT;
ALTER TABLE key_chain ADD COLUMN kem TEXT;
ALTER TABLE key_chain ADD COLUMN cosig TEXT;",
    // LiveChat frames (messages, rotations, sender keys) as relayed, ciphertext only
    "
CREATE TABLE chat_frames (
    id     INTEGER PRIMARY KEY,
    kind   TEXT NOT NULL,
    room   TEXT,
    sender TEXT,
    frame  TEXT NOT NULL
);
CREATE INDEX chat_frames_sender_keys ON chat_frames (kind, sender);",
    // messaging messages as stored and relayed (`{id, senderId, ts, sentAt, body, sig}`), ciphertext only
    "
CREATE TABLE messages (
    id  INTEGER PRIMARY KEY,
    ts  INTEGER NOT NULL,
    msg TEXT NOT NULL
);
CREATE INDEX messages_ts ON messages (ts);",
    // passkeys (WebAuthn credentials): a second sign-in factor
    "
CREATE TABLE passkeys (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    cred_id    TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL,
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX passkeys_account ON passkeys (account_id);",
    // devices: every chain link names its device (`d1` is the registration's chain); other devices have a row here
    // (name, removal), and sender keys are kept per device
    "
ALTER TABLE key_chain ADD COLUMN device TEXT NOT NULL DEFAULT 'd1';
CREATE INDEX key_chain_device ON key_chain (account_id, device, seq);
CREATE TABLE devices (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device     TEXT NOT NULL,
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    removed_at INTEGER,
    PRIMARY KEY (account_id, device)
);
UPDATE chat_frames SET sender = sender || '#d1' WHERE kind = 'senderkey';",
];

fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    let done = conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? as usize;
    for (i, step) in MIGRATIONS.iter().enumerate().skip(done) {
        let tx = conn.transaction()?;
        tx.execute_batch(step)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
    }
    Ok(())
}

const LINK_COLUMNS: &str = "kind, root, old_root, signature, at, slh, kem, cosig";

fn link_from_row(r: &rusqlite::Row) -> rusqlite::Result<ChainLink> {
    let kind: String = r.get(0)?;
    let sig: Option<String> = r.get(3)?;
    Ok(ChainLink {
        kind: LinkKind::parse(&kind).unwrap_or(LinkKind::Rotate),
        root: r.get(1)?,
        old_root: r.get(2)?,
        signature: sig.and_then(|s| serde_json::from_str(&s).ok()),
        at: r.get::<_, i64>(4)? as u64,
        slh: r.get(5)?,
        kem: r.get(6)?,
        cosig: r.get(7)?,
    })
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Db> {
        Self::from(Connection::open(path)?)
    }

    pub fn memory() -> rusqlite::Result<Db> {
        Self::from(Connection::open_in_memory()?)
    }

    fn from(mut conn: Connection) -> rusqlite::Result<Db> {
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&mut conn)?;
        Ok(Db(Mutex::new(conn)))
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// New account plus its registration link, atomically.
    pub fn create_account(&self, username: &str, password_hash: &str, first: &ChainLink) -> Result<Account, CreateError> {
        let mut c = self.conn();
        let tx = c.transaction().map_err(|e| CreateError::Other(e.to_string()))?;
        let r = tx.execute(
            "INSERT INTO accounts (username, username_lc, password_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![username, username.to_lowercase(), password_hash, now() as i64],
        );
        match r {
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => return Err(CreateError::UsernameTaken),
            Err(e) => return Err(CreateError::Other(e.to_string())),
            Ok(_) => {}
        }
        let id = tx.last_insert_rowid();
        insert_link(&tx, id, PRIMARY, first).map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => CreateError::KeyTaken,
            e => CreateError::Other(e.to_string()),
        })?;
        tx.commit().map_err(|e| CreateError::Other(e.to_string()))?;
        Ok(Account {
            id,
            username: username.to_string(),
        })
    }

    /// (account, password hash) by case-insensitive name.
    pub fn find(&self, username: &str) -> Option<(Account, String)> {
        self.conn()
            .query_row("SELECT id, username, password_hash FROM accounts WHERE username_lc = ?1", [username.to_lowercase()], |r| {
                Ok((
                    Account {
                        id: r.get(0)?,
                        username: r.get(1)?,
                    },
                    r.get(2)?,
                ))
            })
            .optional()
            .ok()
            .flatten()
    }

    /// One device's chain, oldest first.
    pub fn chain(&self, account_id: i64, device: &str) -> Vec<ChainLink> {
        let c = self.conn();
        let Ok(mut st) = c.prepare(&format!("SELECT {LINK_COLUMNS} FROM key_chain WHERE account_id = ?1 AND device = ?2 ORDER BY seq")) else {
            return vec![];
        };
        let rows = st
            .query_map(params![account_id, device], link_from_row)
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_default();
        rows
    }

    /// The primary device's current root.
    pub fn head(&self, account_id: i64) -> Option<String> {
        self.head_link(account_id).map(|l| l.root)
    }

    /// The primary device's current link: it carries the account's identity (SLH-DSA) key.
    pub fn head_link(&self, account_id: i64) -> Option<ChainLink> {
        self.device_head(account_id, PRIMARY)
    }

    pub fn device_head(&self, account_id: i64, device: &str) -> Option<ChainLink> {
        self.conn()
            .query_row(
                &format!("SELECT {LINK_COLUMNS} FROM key_chain WHERE account_id = ?1 AND device = ?2 ORDER BY seq DESC LIMIT 1"),
                params![account_id, device],
                link_from_row,
            )
            .optional()
            .ok()
            .flatten()
    }

    /// The devices that are not removed, with their current links, the primary first.
    pub fn active_heads(&self, account_id: i64) -> Vec<(String, ChainLink)> {
        self.devices(account_id)
            .into_iter()
            .filter(|d| !d.removed)
            .filter_map(|d| Some((d.device.clone(), self.device_head(account_id, &d.device)?)))
            .collect()
    }

    /// Every device that has a chain, in the order they were added.
    pub fn devices(&self, account_id: i64) -> Vec<DeviceRow> {
        let c = self.conn();
        let Ok(mut st) = c.prepare(
            "SELECT k.device, COALESCE(d.name, ''), MIN(k.at), d.removed_at IS NOT NULL,
                    (SELECT root FROM key_chain WHERE account_id = k.account_id AND device = k.device ORDER BY seq DESC LIMIT 1)
             FROM key_chain k LEFT JOIN devices d ON d.account_id = k.account_id AND d.device = k.device
             WHERE k.account_id = ?1 GROUP BY k.device ORDER BY MIN(k.seq)",
        ) else {
            return vec![];
        };
        let rows = st
            .query_map([account_id], |r| {
                Ok(DeviceRow {
                    device: r.get(0)?,
                    name: r.get(1)?,
                    created_at: r.get::<_, i64>(2)? as u64,
                    removed: r.get(3)?,
                    head: r.get(4)?,
                })
            })
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_default();
        rows
    }

    /// Every account with its primary root (the identity) and its active devices' roots: whom LiveChat messages are
    /// encrypted to.
    pub fn directory(&self) -> Vec<DirEntry> {
        let accounts: Vec<(i64, String)> = {
            let c = self.conn();
            let Ok(mut st) = c.prepare("SELECT id, username FROM accounts ORDER BY username_lc") else {
                return vec![];
            };
            let rows = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map(|r| r.filter_map(Result::ok).collect())
                .unwrap_or_default();
            rows
        };
        // ponytail: a few queries per account; one joined query if the directory gets large
        accounts
            .into_iter()
            .filter_map(|(id, name)| {
                let devices = self.active_heads(id).into_iter().map(|(d, l)| (d, l.root)).collect();
                Some((name, self.head(id)?, devices))
            })
            .collect()
    }

    /// Append to a device's chain; the link must continue from that device's head and use a root nobody has used.
    pub fn append_link(&self, account_id: i64, device: &str, link: &ChainLink) -> Result<(), String> {
        let mut c = self.conn();
        let tx = c.transaction().map_err(|e| e.to_string())?;
        let head: String = tx
            .query_row(
                "SELECT root FROM key_chain WHERE account_id = ?1 AND device = ?2 ORDER BY seq DESC LIMIT 1",
                params![account_id, device],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if link.old_root.as_deref() != Some(head.as_str()) {
            return Err("link does not continue from the current key".into());
        }
        insert_link(&tx, account_id, device, link).map_err(|_| "key already in use".to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    /// A new device and the first link of its chain (checked by the caller), atomically.
    pub fn add_device(&self, account_id: i64, device: &str, name: &str, first: &ChainLink) -> Result<(), String> {
        let mut c = self.conn();
        let tx = c.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO devices (account_id, device, name, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![account_id, device, name, now() as i64],
        )
        .map_err(|_| "that device id is taken".to_string())?;
        insert_link(&tx, account_id, device, first).map_err(|_| "key already in use".to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    /// Mark a device removed (its chain stays, so its old messages still verify). False if it has no chain or was
    /// already removed.
    pub fn remove_device(&self, account_id: i64, device: &str) -> bool {
        if self.devices(account_id).iter().all(|d| d.device != device || d.removed) {
            return false;
        }
        let t = now() as i64;
        self.conn()
            .execute(
                "INSERT INTO devices (account_id, device, name, created_at, removed_at) VALUES (?1, ?2, '', ?3, ?3)
                 ON CONFLICT (account_id, device) DO UPDATE SET removed_at = excluded.removed_at",
                params![account_id, device, t],
            )
            .is_ok()
    }

    /// After a recovery (a new identity key on the primary chain): the primary device is active again and every other
    /// device, linked under the old identity key, is removed.
    pub fn recovered(&self, account_id: i64) {
        let c = self.conn();
        let _ = c.execute("UPDATE devices SET removed_at = NULL WHERE account_id = ?1 AND device = ?2", params![account_id, PRIMARY]);
        let _ = c.execute(
            "UPDATE devices SET removed_at = ?2 WHERE account_id = ?1 AND device != ?3 AND removed_at IS NULL",
            params![account_id, now() as i64, PRIMARY],
        );
    }

    pub fn new_session(&self, account_id: i64, token_hash: &str, ttl_secs: u64) {
        let t = now();
        let _ = self.conn().execute(
            "INSERT INTO sessions (token_hash, account_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![token_hash, account_id, t as i64, (t + ttl_secs) as i64],
        );
    }

    /// Account for a live session; sliding expiry (extended when less than half the lifetime is left).
    pub fn session(&self, token_hash: &str, ttl_secs: u64) -> Option<Account> {
        let t = now();
        let c = self.conn();
        let (acc, expires): (Account, i64) = c
            .query_row(
                "SELECT a.id, a.username, s.expires_at FROM sessions s JOIN accounts a ON a.id = s.account_id WHERE s.token_hash = ?1",
                [token_hash],
                |r| {
                    Ok((
                        Account {
                            id: r.get(0)?,
                            username: r.get(1)?,
                        },
                        r.get(2)?,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten()?;
        if expires as u64 <= t {
            let _ = c.execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash]);
            return None;
        }
        if (expires as u64) < t + ttl_secs / 2 {
            let _ = c.execute("UPDATE sessions SET expires_at = ?2 WHERE token_hash = ?1", params![token_hash, (t + ttl_secs) as i64]);
        }
        Some(acc)
    }

    pub fn end_session(&self, token_hash: &str) {
        let _ = self.conn().execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash]);
    }

    /// End every session of the account except `keep` (pass "" to end all).
    pub fn end_sessions_except(&self, account_id: i64, keep: &str) {
        let _ = self
            .conn()
            .execute("DELETE FROM sessions WHERE account_id = ?1 AND token_hash != ?2", params![account_id, keep]);
    }

    pub fn set_password(&self, account_id: i64, hash: &str) {
        let _ = self.conn().execute("UPDATE accounts SET password_hash = ?2 WHERE id = ?1", params![account_id, hash]);
    }

    pub fn purge_expired_sessions(&self) {
        let _ = self.conn().execute("DELETE FROM sessions WHERE expires_at <= ?1", [now() as i64]);
    }

    /// Store a relayed frame; returns its sequence number. Only the newest `senderkey` per sender is kept, and other
    /// frames beyond the newest `keep` are dropped.
    pub fn push_frame(&self, frame: &Value, keep: usize) -> i64 {
        let c = self.conn();
        let kind = frame["type"].as_str().unwrap_or_default();
        let mut sender = frame["sender"].as_str().map(str::to_lowercase);
        if kind == "senderkey" {
            // each device has its own group key: keep the newest per device
            sender = sender.map(|s| format!("{s}#{}", frame["device"].as_str().unwrap_or(PRIMARY)));
        }
        let r = c.execute(
            "INSERT INTO chat_frames (kind, room, sender, frame) VALUES (?1, ?2, ?3, ?4)",
            params![kind, frame["room"].as_str(), sender, frame.to_string()],
        );
        if r.is_err() {
            return 0;
        }
        let id = c.last_insert_rowid();
        if kind == "senderkey" {
            let _ = c.execute("DELETE FROM chat_frames WHERE kind = 'senderkey' AND sender = ?1 AND id < ?2", params![sender, id]);
        }
        let _ = c.execute(
            "DELETE FROM chat_frames WHERE kind != 'senderkey' AND id <              (SELECT id FROM chat_frames WHERE kind != 'senderkey' ORDER BY id DESC LIMIT 1 OFFSET ?1)",
            [keep.saturating_sub(1) as i64],
        );
        id
    }

    /// Up to `limit` frames before sequence number `before` (newest first in the scan, returned oldest first) that
    /// `want` accepts, each with its `seq`. Sender-key frames are not history; see `sender_key_frames`.
    pub fn frames_before(&self, before: Option<i64>, limit: usize, want: impl Fn(&Value) -> bool) -> Vec<Value> {
        let c = self.conn();
        let Ok(mut st) = c.prepare("SELECT id, frame FROM chat_frames WHERE kind != 'senderkey' AND id < ?1 ORDER BY id DESC") else {
            return vec![];
        };
        let Ok(rows) = st.query_map([before.unwrap_or(i64::MAX)], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))) else {
            return vec![];
        };
        let mut out: Vec<Value> = rows
            .filter_map(Result::ok)
            .filter_map(|(id, f)| {
                let mut v: Value = serde_json::from_str(&f).ok()?;
                v["seq"] = id.into();
                Some(v)
            })
            .filter(|v| want(v))
            .take(limit)
            .collect();
        out.reverse();
        out
    }

    pub fn sender_key_frames(&self) -> Vec<Value> {
        let c = self.conn();
        let Ok(mut st) = c.prepare("SELECT frame FROM chat_frames WHERE kind = 'senderkey' ORDER BY id") else {
            return vec![];
        };
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map(|r| r.filter_map(Result::ok).filter_map(|f| serde_json::from_str(&f).ok()).collect())
            .unwrap_or_default();
        rows
    }

    /// Store a messaging message (kept for good).
    pub fn push_message(&self, msg: &Value) {
        let _ = self.conn().execute(
            "INSERT INTO messages (ts, msg) VALUES (?1, ?2)",
            params![msg["ts"].as_u64().unwrap_or(0) as i64, msg.to_string()],
        );
    }

    /// The newest `limit` messaging messages stored after `since` (ms; 0 for all), oldest first.
    pub fn messages_since(&self, since: u64, limit: usize) -> Vec<Value> {
        let c = self.conn();
        let Ok(mut st) = c.prepare("SELECT msg FROM messages WHERE ?1 = 0 OR ts > ?1 ORDER BY id DESC LIMIT ?2") else {
            return vec![];
        };
        let mut out: Vec<Value> = st
            .query_map(params![since as i64, limit as i64], |r| r.get::<_, String>(0))
            .map(|r| r.filter_map(Result::ok).filter_map(|m| serde_json::from_str(&m).ok()).collect())
            .unwrap_or_default();
        out.reverse();
        out
    }

    pub fn message_count(&self) -> usize {
        self.conn().query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0)).unwrap_or(0) as usize
    }

    pub fn account(&self, id: i64) -> Option<Account> {
        self.conn()
            .query_row("SELECT id, username FROM accounts WHERE id = ?1", [id], |r| {
                Ok(Account {
                    id: r.get(0)?,
                    username: r.get(1)?,
                })
            })
            .optional()
            .ok()
            .flatten()
    }

    pub fn add_passkey(&self, account_id: i64, cred_id: &str, public_key: &str, sign_count: u32, name: &str) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT INTO passkeys (account_id, cred_id, public_key, sign_count, name, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![account_id, cred_id, public_key, sign_count, name, now() as i64],
            )
            .map(|_| ())
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => "that passkey is already registered".to_string(),
                e => e.to_string(),
            })
    }

    pub fn passkeys(&self, account_id: i64) -> Vec<StoredPasskey> {
        let c = self.conn();
        let Ok(mut st) = c.prepare("SELECT cred_id, public_key, sign_count, name, created_at FROM passkeys WHERE account_id = ?1 ORDER BY id") else {
            return vec![];
        };
        st.query_map([account_id], |r| {
            Ok(StoredPasskey {
                cred_id: r.get(0)?,
                public_key: r.get(1)?,
                sign_count: r.get(2)?,
                name: r.get(3)?,
                created_at: r.get::<_, i64>(4)? as u64,
            })
        })
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    pub fn set_passkey_count(&self, cred_id: &str, sign_count: u32) {
        let _ = self.conn().execute("UPDATE passkeys SET sign_count = ?1 WHERE cred_id = ?2", params![sign_count, cred_id]);
    }

    /// True if `account_id` had that passkey.
    pub fn remove_passkey(&self, account_id: i64, cred_id: &str) -> bool {
        self.conn()
            .execute("DELETE FROM passkeys WHERE account_id = ?1 AND cred_id = ?2", params![account_id, cred_id])
            .unwrap_or(0)
            > 0
    }

    pub fn remove_passkeys(&self, account_id: i64) -> usize {
        self.conn().execute("DELETE FROM passkeys WHERE account_id = ?1", [account_id]).unwrap_or(0)
    }

    pub fn frame_count(&self) -> usize {
        self.conn().query_row("SELECT COUNT(*) FROM chat_frames", [], |r| r.get::<_, i64>(0)).unwrap_or(0) as usize
    }

    pub fn list_accounts(&self) -> Vec<(String, u64)> {
        let c = self.conn();
        let Ok(mut st) = c.prepare("SELECT username, created_at FROM accounts ORDER BY id") else {
            return vec![];
        };
        let rows = st
            .query_map([], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)))
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_default();
        rows
    }
}

/// `seq` orders links across all of an account's devices (and is unique per account).
fn insert_link(tx: &rusqlite::Transaction, account_id: i64, device: &str, l: &ChainLink) -> rusqlite::Result<()> {
    let sig = l.signature.as_ref().and_then(|s| serde_json::to_string(s).ok());
    let seq: i64 = tx.query_row("SELECT COALESCE(MAX(seq) + 1, 0) FROM key_chain WHERE account_id = ?1", [account_id], |r| r.get(0))?;
    tx.execute(
        "INSERT INTO key_chain (account_id, seq, kind, root, old_root, signature, at, slh, kem, cosig, device) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![account_id, seq, l.kind.as_str(), l.root, l.old_root, sig, now() as i64, l.slh, l.kem, l.cosig, device],
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hast_core::hbss;

    fn link(kind: LinkKind, root: &str, old: Option<&str>) -> ChainLink {
        ChainLink {
            kind,
            root: root.into(),
            old_root: old.map(String::from),
            ..Default::default()
        }
    }

    fn root(c: char) -> String {
        c.to_string().repeat(128)
    }

    #[test]
    fn accounts_are_unique_case_insensitively_and_keys_are_not_shared() {
        let db = Db::memory().unwrap();
        let a = db.create_account("Alice", "h", &link(LinkKind::Register, &root('a'), None)).unwrap();
        assert_eq!(
            db.create_account("ALICE", "h", &link(LinkKind::Register, &root('b'), None)),
            Err(CreateError::UsernameTaken)
        );
        assert_eq!(db.create_account("bob", "h", &link(LinkKind::Register, &root('a'), None)), Err(CreateError::KeyTaken));
        assert!(db.find("bob").is_none(), "failed signup leaves nothing behind");
        let (found, hash) = db.find("aLiCe").unwrap();
        assert_eq!((found, hash.as_str()), (a, "h"));
    }

    #[test]
    fn chain_appends_only_from_the_head() {
        let db = Db::memory().unwrap();
        let a = db.create_account("alice", "h", &link(LinkKind::Register, &root('a'), None)).unwrap();
        assert_eq!(db.head(a.id), Some(root('a')));
        assert!(db.append_link(a.id, PRIMARY, &link(LinkKind::Rotate, &root('b'), Some(&root('a')))).is_ok());
        assert!(
            db.append_link(a.id, PRIMARY, &link(LinkKind::Rotate, &root('c'), Some(&root('a')))).is_err(),
            "stale old_root"
        );
        assert!(
            db.append_link(a.id, PRIMARY, &link(LinkKind::Rotate, &root('a'), Some(&root('b')))).is_err(),
            "keys cannot be reused"
        );
        let chain = db.chain(a.id, PRIMARY);
        assert_eq!(chain.iter().map(|l| l.root.clone()).collect::<Vec<_>>(), vec![root('a'), root('b')]);
        assert_eq!(db.head(a.id), Some(root('b')));
    }

    #[test]
    fn devices_have_their_own_chains_and_can_be_removed() {
        let db = Db::memory().unwrap();
        let a = db.create_account("alice", "h", &link(LinkKind::Register, &root('a'), None)).unwrap();
        db.add_device(a.id, "d0000000a", "Phone", &link(LinkKind::Device, &root('p'), None)).unwrap();
        assert!(
            db.add_device(a.id, "d0000000a", "Again", &link(LinkKind::Device, &root('q'), None)).is_err(),
            "ids are unique"
        );
        assert!(
            db.add_device(a.id, "d0000000b", "Copy", &link(LinkKind::Device, &root('a'), None)).is_err(),
            "and so are keys"
        );
        db.append_link(a.id, "d0000000a", &link(LinkKind::Rotate, &root('r'), Some(&root('p')))).unwrap();
        db.append_link(a.id, PRIMARY, &link(LinkKind::Rotate, &root('b'), Some(&root('a')))).unwrap();
        assert!(
            db.append_link(a.id, PRIMARY, &link(LinkKind::Rotate, &root('c'), Some(&root('r')))).is_err(),
            "each chain has its own head"
        );
        assert_eq!(db.chain(a.id, "d0000000a").iter().map(|l| l.root.clone()).collect::<Vec<_>>(), vec![root('p'), root('r')]);
        assert_eq!(db.head(a.id), Some(root('b')), "the primary chain is the account's identity");
        let heads = |db: &Db| db.active_heads(a.id).into_iter().map(|(d, l)| (d, l.root)).collect::<Vec<_>>();
        assert_eq!(heads(&db), vec![(PRIMARY.to_string(), root('b')), ("d0000000a".to_string(), root('r'))]);
        assert_eq!(db.directory(), vec![("alice".to_string(), root('b'), heads(&db))]);

        assert!(db.remove_device(a.id, "d0000000a"));
        assert!(!db.remove_device(a.id, "d0000000a") && !db.remove_device(a.id, "d0000000f"), "removed already, or unknown");
        assert_eq!(heads(&db), vec![(PRIMARY.to_string(), root('b'))]);
        assert_eq!(db.chain(a.id, "d0000000a").len(), 2, "its chain stays, for its old messages");
        assert!(db.remove_device(a.id, PRIMARY), "the primary device can be removed too");
        assert!(heads(&db).is_empty());

        db.recovered(a.id);
        assert_eq!(heads(&db), vec![(PRIMARY.to_string(), root('b'))], "a recovery brings back only the primary device");
        let rows = db.devices(a.id);
        assert_eq!((rows[1].name.as_str(), rows[1].removed), ("Phone", true));
    }

    #[test]
    fn signatures_round_trip_through_the_database() {
        let db = Db::memory().unwrap();
        let (kp, lt) = (hbss::keygen(hbss::N), hast_core::pq::LongTermKeys::generate());
        let first = hast_core::identity::register_link("alice", &kp, &lt);
        let a = db.create_account("alice", "h", &first).unwrap();
        let chain = db.chain(a.id, PRIMARY);
        assert_eq!(chain[0].cosig, first.cosig);
        assert_eq!(db.head_link(a.id).unwrap().kem, Some(lt.kem_pk));
        assert!(hast_core::identity::verify_chain("alice", &chain).is_ok());
    }

    #[test]
    fn sessions_expire_slide_and_end() {
        let db = Db::memory().unwrap();
        let a = db.create_account("alice", "h", &link(LinkKind::Register, &root('a'), None)).unwrap();
        db.new_session(a.id, "tok", 1000);
        assert_eq!(db.session("tok", 1000), Some(a.clone()));
        assert_eq!(db.session("nope", 1000), None);

        // an expired session is refused and removed
        db.new_session(a.id, "old", 0);
        assert_eq!(db.session("old", 1000), None);

        // sliding: a session with little time left is extended
        db.new_session(a.id, "short", 10);
        assert!(db.session("short", 1000).is_some());
        let expires: i64 = db.conn().query_row("SELECT expires_at FROM sessions WHERE token_hash = 'short'", [], |r| r.get(0)).unwrap();
        assert!(expires as u64 > now() + 900);

        db.end_session("tok");
        assert_eq!(db.session("tok", 1000), None);
        db.new_session(a.id, "x", 1000);
        db.new_session(a.id, "y", 1000);
        db.end_sessions_except(a.id, "x");
        assert!(db.session("x", 1000).is_some() && db.session("y", 1000).is_none());
    }

    #[test]
    fn databases_from_before_versioning_are_migrated_in_place() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(MIGRATIONS[0]).unwrap();
        c.execute(
            "INSERT INTO accounts (username, username_lc, password_hash, created_at) VALUES ('alice', 'alice', 'h', 0)",
            [],
        )
        .unwrap();
        c.execute("INSERT INTO key_chain (account_id, seq, kind, root, at) VALUES (1, 0, 'register', 'r', 0)", [])
            .unwrap();
        let db = Db::from(c).unwrap();
        let version: i64 = db.conn().pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(version as usize, MIGRATIONS.len());
        let head = db.head_link(1).unwrap();
        assert_eq!((head.root.as_str(), head.slh), ("r", None), "old rows survive with empty new columns");
        assert_eq!(db.directory(), vec![("alice".to_string(), "r".to_string(), vec![(PRIMARY.to_string(), "r".to_string())])]);
        drop(db);
    }

    #[test]
    fn chat_frames_page_backwards_and_keep_one_sender_key_each() {
        let db = Db::memory().unwrap();
        for i in 0..10 {
            db.push_frame(
                &serde_json::json!({ "type": "message", "room": if i % 2 == 0 { "lobby" } else { "dm:a:b" }, "sender": "A", "n": i }),
                8,
            );
        }
        db.push_frame(&serde_json::json!({ "type": "senderkey", "sender": "A", "n": "old" }), 8);
        db.push_frame(&serde_json::json!({ "type": "senderkey", "sender": "a", "n": "new" }), 8);
        db.push_frame(&serde_json::json!({ "type": "senderkey", "sender": "a", "device": "d0000000a", "n": "phone" }), 8);
        let all = db.frames_before(None, 100, |_| true);
        assert_eq!(
            all.iter().map(|f| f["n"].as_i64().unwrap()).collect::<Vec<_>>(),
            (2..10).collect::<Vec<_>>(),
            "only the newest 8 kept"
        );
        let lobby = db.frames_before(None, 2, |f| f["room"] == "lobby");
        assert_eq!(lobby.iter().map(|f| f["n"].as_i64().unwrap()).collect::<Vec<_>>(), vec![6, 8]);
        let older = db.frames_before(lobby[0]["seq"].as_i64(), 10, |f| f["room"] == "lobby");
        assert_eq!(older.iter().map(|f| f["n"].as_i64().unwrap()).collect::<Vec<_>>(), vec![2, 4]);
        let keys = db.sender_key_frames();
        assert_eq!(
            keys.iter().map(|k| k["n"].as_str().unwrap()).collect::<Vec<_>>(),
            vec!["new", "phone"],
            "the newest per device"
        );
        assert_eq!(db.frame_count(), 10);
    }

    #[test]
    fn deleting_nothing_else_survives_password_change() {
        let db = Db::memory().unwrap();
        let a = db.create_account("alice", "old", &link(LinkKind::Register, &root('a'), None)).unwrap();
        db.set_password(a.id, "new");
        assert_eq!(db.find("alice").unwrap().1, "new");
        assert_eq!(db.list_accounts().len(), 1);
    }
}
