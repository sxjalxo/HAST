//! What travels inside a LiveChat message's encryption: plain text, or (as tagged JSON) an edit or delete of one of the
//! sender's earlier messages, or a file. The server only ever sees ciphertext, so it can't tell these apart; the
//! receiving browser decides whether a change applies (`may_change`) after the message's signatures verified.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

/// Largest attachment: it travels base64-encoded twice (in the content, then as ciphertext) inside a 1 MiB frame.
pub const MAX_FILE_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Content {
    Text {
        text: String,
    },
    /// replaces the text of the sender's message `target`
    Edit {
        target: String,
        text: String,
    },
    /// removes the sender's message `target` for everyone
    Delete {
        target: String,
    },
    /// `data` is the file, base64
    File {
        name: String,
        mime: String,
        data: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Tagged {
    hast: u8,
    #[serde(flatten)]
    content: Content,
}

impl Content {
    pub fn text(text: &str) -> Content {
        Content::Text { text: text.to_string() }
    }

    pub fn file(name: &str, mime: &str, bytes: &[u8]) -> Result<Content, String> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(format!("Files are limited to {} KB", MAX_FILE_BYTES / 1024));
        }
        Ok(Content::File {
            name: safe_name(name),
            mime: mime.to_string(),
            data: B64.encode(bytes),
        })
    }

    /// The plaintext to encrypt. Text stays plain (as before this format existed) unless it would read back as
    /// something else.
    pub fn encode(&self) -> String {
        if let Content::Text { text } = self {
            if Content::decode(text) == *self {
                return text.clone();
            }
        }
        serde_json::to_string(&Tagged { hast: 1, content: self.clone() }).unwrap_or_default()
    }

    /// Anything that isn't tagged content is plain text.
    pub fn decode(plaintext: &str) -> Content {
        serde_json::from_str::<Tagged>(plaintext)
            .ok()
            .filter(|t| t.hast == 1)
            .map(|t| t.content)
            .unwrap_or_else(|| Content::text(plaintext))
    }

    /// The message an edit or delete is about.
    pub fn target(&self) -> Option<&str> {
        match self {
            Content::Edit { target, .. } | Content::Delete { target } => Some(target),
            _ => None,
        }
    }
}

/// May a change sent by `change_sender` in `change_room` alter the message `target_sender` sent in `target_room`?
/// Only the author may change a message, and only where it was sent.
pub fn may_change(change_sender: &str, change_room: &str, target_sender: &str, target_room: &str) -> bool {
    change_sender.eq_ignore_ascii_case(target_sender) && change_room == target_room
}

/// The file's bytes, if `data` is valid base64.
pub fn file_bytes(data: &str) -> Option<Vec<u8>> {
    B64.decode(data).ok()
}

/// Image types safe to show inline. Anything else (SVG and HTML included, which can carry script) is only offered as
/// a download.
pub fn inline_image(mime: &str) -> bool {
    matches!(mime, "image/png" | "image/jpeg" | "image/gif" | "image/webp")
}

/// A file name to show and save under: no path, no control characters, no bidirectional overrides (which can make
/// `report<RLO>fdp.exe` display as `reportexe.pdf`), at most 120 characters.
pub fn safe_name(name: &str) -> String {
    let bidi = |c: &char| matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    let base = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let clean: String = base.chars().filter(|c| !c.is_control() && !bidi(c)).take(120).collect();
    if clean.trim().is_empty() || clean.trim_matches('.').is_empty() {
        "file".into()
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_stays_plain_and_old_messages_read_as_text() {
        assert_eq!(Content::text("hello").encode(), "hello");
        assert_eq!(Content::decode("hello"), Content::text("hello"));
        assert_eq!(Content::decode("{not json"), Content::text("{not json"));
        assert_eq!(
            Content::decode(r#"{"hast":2,"kind":"delete","target":"x"}"#),
            Content::text(r#"{"hast":2,"kind":"delete","target":"x"}"#)
        );
    }

    #[test]
    fn text_that_looks_like_a_change_is_still_text() {
        let tricky = Content::text(r#"{"hast":1,"kind":"delete","target":"m1"}"#);
        assert_ne!(tricky.encode(), r#"{"hast":1,"kind":"delete","target":"m1"}"#);
        assert_eq!(Content::decode(&tricky.encode()), tricky);
    }

    #[test]
    fn changes_and_files_round_trip() {
        for c in [
            Content::Edit {
                target: "m1".into(),
                text: "fixed".into(),
            },
            Content::Delete { target: "m1".into() },
            Content::file("notes.txt", "text/plain", b"abc").unwrap(),
        ] {
            assert_eq!(Content::decode(&c.encode()), c);
        }
        assert_eq!(Content::Delete { target: "m1".into() }.target(), Some("m1"));
        assert_eq!(Content::text("x").target(), None);
    }

    #[test]
    fn only_the_author_changes_a_message_and_only_in_its_room() {
        assert!(may_change("alice", "lobby", "Alice", "lobby"));
        assert!(!may_change("mallory", "lobby", "alice", "lobby"), "someone else's message");
        assert!(!may_change("alice", "dm:alice:bob", "alice", "lobby"), "from another room");
    }

    #[test]
    fn files_are_capped_named_safely_and_shown_inline_only_as_plain_images() {
        assert!(Content::file("big", "application/octet-stream", &vec![0; MAX_FILE_BYTES + 1]).is_err());
        let Content::File { name, data, .. } = Content::file("../../etc/passwd", "text/plain", b"\x00\xff").unwrap() else {
            panic!()
        };
        assert_eq!(name, "passwd");
        assert_eq!(file_bytes(&data), Some(vec![0, 255]));
        assert_eq!(safe_name("C:\\Users\\x\\report\u{202e}fdp.exe"), "reportfdp.exe", "path and right-to-left override removed");
        assert_eq!(safe_name(".."), "file");
        assert_eq!(safe_name(""), "file");
        assert!(inline_image("image/png") && inline_image("image/webp"));
        assert!(!inline_image("image/svg+xml") && !inline_image("text/html"));
    }
}
