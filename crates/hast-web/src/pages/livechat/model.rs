//! What LiveChat shows: messages as checked and opened, edits and deletes folded in, and per-message results.
use super::*;

#[derive(Clone, PartialEq)]
pub(super) struct ChatMessage {
    pub(super) id: String,
    pub(super) sender: String,
    pub(super) sender_avatar: String,
    /// decrypted text
    pub(super) message: String,
    pub(super) signature: Signature,
    pub(super) commitment: String,
    /// the sender's device that signed it (`identity::PRIMARY` unless they linked more browsers)
    pub(super) device: String,
    pub(super) timestamp: f64,
    pub(super) verified: bool,
    /// the signatures check out, but the keys came from a recovery (or the safety number changed) and the user hasn't
    /// confirmed the current safety number: shown amber, not green
    pub(super) unconfirmed: bool,
    /// why `verified` is false, or a notice when it is true
    pub(super) note: &'static str,
    pub(super) is_own: bool,
    /// carried an SLH-DSA co-signature that verified
    pub(super) cosigned: bool,
    /// how many keys the message was sealed to (0: sent in the clear, before encryption existed, or `group`)
    pub(super) recipients: usize,
    /// encrypted under the sender's lobby group key
    pub(super) group: bool,
    /// the sender's current safety number (empty for accounts without long-term keys)
    pub(super) fingerprint: String,
    /// `identity::LOBBY` or a private room (`identity::dm_room`)
    pub(super) room: String,
    /// the server's sequence number (0 for our own messages not yet echoed back), for paging back
    pub(super) seq: i64,
    /// an edit or delete of an earlier message: `shown` applies it and doesn't display it (unless it failed to verify)
    pub(super) change: Option<Content>,
    /// an attachment: (name, MIME type, base64)
    pub(super) file: Option<(String, String, String)>,
    /// set by `shown` when a verified edit or delete from the author applied
    pub(super) edited: bool,
    pub(super) deleted: bool,
}

impl ChatMessage {
    /// Fills the content fields from the decrypted plaintext.
    pub(super) fn with_content(mut self, plaintext: &str) -> ChatMessage {
        match Content::decode(plaintext) {
            Content::Text { text } => self.message = text,
            Content::File { name, mime, data } => {
                self.message = name.clone();
                self.file = Some((name, mime, data));
            }
            c @ Content::Edit { .. } => {
                if let Content::Edit { text, .. } = &c {
                    self.message = format!("Edit of an earlier message: {text}");
                }
                self.change = Some(c);
            }
            c @ Content::Delete { .. } => {
                self.message = "Request to delete an earlier message".into();
                self.change = Some(c);
            }
        }
        self
    }
}

/// The messages of `room` as they should read: verified edits and deletes from the author applied (in send order, a
/// delete winning), and not shown themselves. A change that failed to verify stays visible, marked, so tampering shows.
pub(super) fn shown(all: &[ChatMessage], room: &str) -> Vec<ChatMessage> {
    let in_room = |m: &&ChatMessage| m.room == room;
    let mut out: Vec<ChatMessage> = all.iter().filter(in_room).filter(|m| m.change.is_none() || !m.verified).cloned().collect();
    let mut changes: Vec<&ChatMessage> = all.iter().filter(in_room).filter(|m| m.verified && m.change.is_some()).collect();
    changes.sort_by(|a, b| a.timestamp.total_cmp(&b.timestamp));
    for c in changes {
        let Some(change) = &c.change else { continue };
        let Some(t) = out
            .iter_mut()
            .find(|t| Some(t.id.as_str()) == change.target() && t.change.is_none() && content::may_change(&c.sender, &c.room, &t.sender, &t.room))
        else {
            continue;
        };
        match change {
            Content::Edit { text, .. } if !t.deleted && t.file.is_none() => {
                // what is shown now is vouched for by the edit's signatures
                t.message = text.clone();
                t.edited = true;
                t.signature = c.signature.clone();
                t.commitment = c.commitment.clone();
                t.device = c.device.clone();
                (t.cosigned, t.recipients, t.group, t.note, t.unconfirmed) = (c.cosigned, c.recipients, c.group, c.note, c.unconfirmed);
            }
            Content::Delete { .. } => {
                t.deleted = true;
                t.message.clear();
                t.file = None;
            }
            _ => {}
        }
    }
    out
}

/// Outcome of checking one incoming message.
pub(super) struct Checked {
    pub(super) verified: bool,
    /// signed by keys that only the server vouched for (a recovery), or the safety number changed, and the user
    /// hasn't confirmed the current number yet
    pub(super) unconfirmed: bool,
    pub(super) note: &'static str,
    pub(super) text: String,
    pub(super) cosigned: bool,
    pub(super) recipients: usize,
    pub(super) group: bool,
    pub(super) readable: bool,
    pub(super) fingerprint: String,
    /// decrypted just now (rather than read from this browser's history): keep it, its keys are gone
    pub(super) opened: bool,
}

#[derive(Clone, Copy, Default)]
pub(super) struct Stats {
    pub(super) signed: u32,
    pub(super) verified: u32,
    pub(super) avg_sign: f64,
    pub(super) avg_verify: f64,
}

pub(super) fn parse_sig(v: &Value) -> Signature {
    serde_json::from_value(v.clone()).unwrap_or_default()
}

pub(super) fn room_label(room: &str, me: &str) -> String {
    match identity::dm_members(room) {
        Some((a, b)) => format!("private with @{}", if a.eq_ignore_ascii_case(me) { b } else { a }),
        None => "# Everyone".into(),
    }
}

pub(super) fn to_message(m: &Value, username: &str, c: Checked) -> ChatMessage {
    let s = |k: &str| m[k].as_str().unwrap_or_default().to_string();
    // an unreadable message's text is a placeholder, not content
    let plaintext = c.readable.then(|| c.text.clone());
    let msg = ChatMessage {
        id: m["id"].as_str().map(String::from).unwrap_or_else(|| (now_ms() as u64).to_string()),
        sender: s("sender"),
        sender_avatar: s("senderAvatar"),
        message: c.text,
        signature: parse_sig(&m["signature"]),
        commitment: s("commitment"),
        device: m["device"].as_str().unwrap_or(identity::PRIMARY).to_string(),
        timestamp: m["sentAt"].as_f64().or(m["timestamp"].as_f64()).unwrap_or_else(now_ms),
        verified: c.verified,
        unconfirmed: c.unconfirmed,
        note: c.note,
        is_own: m["sender"].as_str() == Some(username),
        cosigned: c.cosigned,
        recipients: c.recipients,
        group: c.group,
        fingerprint: c.fingerprint,
        room: m["room"].as_str().unwrap_or(identity::LOBBY).to_string(),
        seq: m["seq"].as_i64().unwrap_or(0),
        change: None,
        file: None,
        edited: false,
        deleted: false,
    };
    match plaintext {
        Some(p) => msg.with_content(&p),
        None => msg,
    }
}
