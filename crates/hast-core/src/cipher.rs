//! Cipher Lab pipeline: a list of reversible byte-level steps, applied in order to encrypt and in reverse to decrypt.
//! Educational only: none of this is real cryptography.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Step {
    /// `b ^ key`
    #[serde(rename = "XOR")]
    Xor { key: u8 },
    /// rotate every byte left by `bits` (mod 8)
    #[serde(rename = "ROTATE")]
    Rotate { bits: u8 },
    /// XOR `mask` into every second byte (odd positions): a position-dependent mask that stays reversible
    #[serde(rename = "MASK")]
    Mask { mask: u8 },
    /// Caesar shift of ASCII letters by `shift` (13 = ROT13); other bytes unchanged
    #[serde(rename = "SUBSTITUTE")]
    Substitute { shift: u8 },
}

pub const KINDS: [(&str, &str, &str); 4] = [
    ("XOR", "⊕", "XOR with key"),
    ("ROTATE", "↻", "Rotate bits"),
    ("MASK", "▣", "Apply bit mask"),
    ("SUBSTITUTE", "⇄", "Character substitution"),
];

impl Step {
    pub fn default_for(kind: &str) -> Option<Step> {
        Some(match kind {
            "XOR" => Step::Xor { key: 0xFF },
            "ROTATE" => Step::Rotate { bits: 3 },
            "MASK" => Step::Mask { mask: 0xAA },
            "SUBSTITUTE" => Step::Substitute { shift: 13 },
            _ => return None,
        })
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Step::Xor { .. } => "XOR",
            Step::Rotate { .. } => "ROTATE",
            Step::Mask { .. } => "MASK",
            Step::Substitute { .. } => "SUBSTITUTE",
        }
    }

    pub fn description(&self) -> &'static str {
        KINDS.iter().find(|k| k.0 == self.kind()).map(|k| k.2).unwrap_or("")
    }

    pub fn apply(&self, data: &mut [u8]) {
        match *self {
            Step::Xor { key } => data.iter_mut().for_each(|b| *b ^= key),
            Step::Rotate { bits } => data.iter_mut().for_each(|b| *b = b.rotate_left(bits as u32 % 8)),
            Step::Mask { mask } => data.iter_mut().skip(1).step_by(2).for_each(|b| *b ^= mask),
            Step::Substitute { shift } => data.iter_mut().for_each(|b| *b = shift_letter(*b, shift % 26)),
        }
    }

    pub fn invert(&self, data: &mut [u8]) {
        match *self {
            Step::Xor { .. } | Step::Mask { .. } => self.apply(data),
            Step::Rotate { bits } => data.iter_mut().for_each(|b| *b = b.rotate_right(bits as u32 % 8)),
            Step::Substitute { shift } => data.iter_mut().for_each(|b| *b = shift_letter(*b, (26 - shift % 26) % 26)),
        }
    }
}

fn shift_letter(b: u8, by: u8) -> u8 {
    match b {
        b'a'..=b'z' => (b - b'a' + by) % 26 + b'a',
        b'A'..=b'Z' => (b - b'A' + by) % 26 + b'A',
        _ => b,
    }
}

pub fn encrypt(steps: &[Step], input: &[u8]) -> Vec<u8> {
    let mut data = input.to_vec();
    steps.iter().for_each(|s| s.apply(&mut data));
    data
}

pub fn decrypt(steps: &[Step], input: &[u8]) -> Vec<u8> {
    let mut data = input.to_vec();
    steps.iter().rev().for_each(|s| s.invert(&mut data));
    data
}

/// Accepts `0xFF`, `ff`, `255`.
pub fn parse_byte(s: &str) -> Option<u8> {
    let t = s.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => u8::from_str_radix(h, 16).ok(),
        None => t.parse::<u8>().ok().or_else(|| u8::from_str_radix(t, 16).ok().filter(|_| t.len() == 2)),
    }
}

#[derive(Serialize, Deserialize)]
struct Config {
    version: u32,
    steps: Vec<Step>,
}

pub fn export_config(steps: &[Step]) -> String {
    serde_json::to_string(&Config {
        version: 1,
        steps: steps.to_vec(),
    })
    .unwrap_or_default()
}

pub fn import_config(json: &str) -> Result<Vec<Step>, String> {
    let c: Config = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if c.version != 1 {
        return Err(format!("unsupported config version {}", c.version));
    }
    Ok(c.steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Step> {
        vec![Step::Xor { key: 0x5A }, Step::Rotate { bits: 3 }, Step::Mask { mask: 0xAA }, Step::Substitute { shift: 13 }]
    }

    #[test]
    fn rot13_known_answer() {
        assert_eq!(encrypt(&[Step::Substitute { shift: 13 }], b"Hello, World!"), b"Uryyb, Jbeyq!");
    }

    #[test]
    fn single_step_vectors() {
        assert_eq!(encrypt(&[Step::Xor { key: 0xFF }], &[0x00, 0x0F]), [0xFF, 0xF0]);
        assert_eq!(encrypt(&[Step::Rotate { bits: 1 }], &[0x81]), [0x03]);
        assert_eq!(encrypt(&[Step::Mask { mask: 0xFF }], &[1, 2, 3, 4]), [1, 2 ^ 0xFF, 3, 4 ^ 0xFF]);
        assert_eq!(encrypt(&[], b"same"), b"same");
    }

    #[test]
    fn every_step_round_trips_over_all_bytes() {
        let data: Vec<u8> = (0..=255).collect();
        for step in all().into_iter().chain([
            Step::Rotate { bits: 0 },
            Step::Rotate { bits: 11 },
            Step::Substitute { shift: 0 },
            Step::Substitute { shift: 25 },
            Step::Substitute { shift: 200 },
        ]) {
            assert_eq!(decrypt(std::slice::from_ref(&step), &encrypt(std::slice::from_ref(&step), &data)), data, "{step:?}");
        }
    }

    #[test]
    fn pipeline_round_trips_and_order_matters() {
        let steps = all();
        let msg = "Hello, World! héllo ✓".as_bytes();
        let enc = encrypt(&steps, msg);
        assert_ne!(enc, msg);
        assert_eq!(decrypt(&steps, &enc), msg);
        let mut swapped = steps.clone();
        swapped.swap(0, 3);
        assert_ne!(encrypt(&swapped, msg), enc);
    }

    #[test]
    fn parse_byte_formats() {
        assert_eq!(
            (parse_byte("0xFF"), parse_byte("ff"), parse_byte("255"), parse_byte("256"), parse_byte("zz"), parse_byte("")),
            (Some(255), Some(255), Some(255), None, None, None)
        );
    }

    #[test]
    fn config_round_trip_and_rejects_bad_input() {
        let steps = all();
        assert_eq!(import_config(&export_config(&steps)).unwrap(), steps);
        assert!(import_config("not json").is_err());
        assert!(import_config(r#"{"version":2,"steps":[]}"#).is_err());
        assert!(import_config(r#"{"version":1,"steps":[{"type":"NOPE"}]}"#).is_err());
    }
}
