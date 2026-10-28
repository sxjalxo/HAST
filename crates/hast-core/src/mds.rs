//! Hamming(12,8) encode/decode, noise and QBER check ("Quantum MDS" in the original).
use rand::Rng;

pub fn encode_message(text: &str) -> Vec<u8> {
    text.bytes().flat_map(|b| encode_byte(b).to_le_bytes()).collect()
}

pub fn simulate_noise(encoded: &[u8], p: f64) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    encoded
        .iter()
        .map(|&b| (0..8).fold(b, |acc, bit| if rng.gen::<f64>() < p { acc ^ (1 << bit) } else { acc }))
        .collect()
}

pub struct Decoded {
    pub text: String,
    pub corrected: usize,
    pub uncorrectable: usize,
}

pub fn decode_message(encoded: &[u8]) -> Decoded {
    let (mut bytes, mut corrected, mut uncorrectable) = (vec![], 0, 0);
    for c in encoded.as_chunks::<2>().0 {
        let (byte, fixed, bad) = decode_word((((c[1] as u16) << 8) | c[0] as u16) & CODE_MASK);
        corrected += fixed as usize;
        uncorrectable += bad as usize;
        bytes.push(byte);
    }
    Decoded {
        text: String::from_utf8_lossy(&bytes).into_owned(),
        corrected,
        uncorrectable,
    }
}

pub fn qkd_check(orig: &[u8], received: &[u8]) -> (f64, bool) {
    let len = orig.len().min(received.len());
    let errs: u32 = orig.iter().zip(received).map(|(a, b)| (a ^ b).count_ones()).sum();
    let qber = if len == 0 { 0.0 } else { errs as f64 / (len * 8) as f64 };
    (qber, qber <= 0.05)
}

const DATA_POS: [usize; 8] = [3, 5, 6, 7, 9, 10, 11, 12];
const CODE_MASK: u16 = 0x1fff;

/// Hamming(12,8) plus an overall parity bit: 13 bits, stored in the low bits of a 16-bit container.
fn encode_byte(b: u8) -> u16 {
    let mut pos = [0u16; 13];
    for (i, &p) in DATA_POS.iter().enumerate() {
        pos[p] = ((b >> i) & 1) as u16;
    }
    pos[1] = pos[3] ^ pos[5] ^ pos[7] ^ pos[9] ^ pos[11];
    pos[2] = pos[3] ^ pos[6] ^ pos[7] ^ pos[10] ^ pos[11];
    pos[4] = pos[5] ^ pos[6] ^ pos[7] ^ pos[12];
    pos[8] = pos[9] ^ pos[10] ^ pos[11] ^ pos[12];
    let code = (1..=12).fold(0, |code, i| code | (pos[i] << (i - 1)));
    code | (((code.count_ones() & 1) as u16) << 12)
}

fn syndrome(p: &[u16; 13]) -> usize {
    let s1 = p[1] ^ p[3] ^ p[5] ^ p[7] ^ p[9] ^ p[11];
    let s2 = p[2] ^ p[3] ^ p[6] ^ p[7] ^ p[10] ^ p[11];
    let s4 = p[4] ^ p[5] ^ p[6] ^ p[7] ^ p[12];
    let s8 = p[8] ^ p[9] ^ p[10] ^ p[11] ^ p[12];
    ((s8 << 3) | (s4 << 2) | (s2 << 1) | s1) as usize
}

/// returns (byte, corrected, uncorrectable). One flipped bit is corrected, two are detected, never silently miscorrected.
fn decode_word(code: u16) -> (u8, bool, bool) {
    let code = code & CODE_MASK;
    let mut pos = [0u16; 13];
    for (i, slot) in pos.iter_mut().enumerate().skip(1) {
        *slot = (code >> (i - 1)) & 1;
    }
    let s = syndrome(&pos);
    let odd = code.count_ones() & 1 == 1; // overall parity of all 13 bits should be even
    let (mut corrected, mut uncorrectable) = (false, false);
    match (s, odd) {
        (0, false) => {}
        (0, true) => corrected = true, // the overall parity bit itself flipped
        (s, true) if s <= 12 => {
            pos[s] ^= 1;
            corrected = true;
        }
        _ => uncorrectable = true, // even parity with a syndrome (two errors) or a syndrome outside the word
    }
    let byte = DATA_POS.iter().enumerate().fold(0u8, |o, (i, &p)| o | ((pos[p] as u8) << i));
    (byte, corrected, uncorrectable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let d = decode_message(&encode_message("Hello, HBSS!"));
        assert_eq!((d.text.as_str(), d.corrected, d.uncorrectable), ("Hello, HBSS!", 0, 0));
    }

    #[test]
    fn corrects_every_single_bit_flip() {
        for b in 0..=255u8 {
            let code = encode_byte(b);
            for bit in 0..13 {
                assert_eq!(decode_word(code ^ (1 << bit)), (b, true, false), "byte {b} bit {bit}");
            }
        }
    }

    #[test]
    fn detects_every_double_bit_flip() {
        for b in 0..=255u8 {
            let code = encode_byte(b);
            for i in 0..13 {
                for j in (i + 1)..13 {
                    let (_, corrected, uncorrectable) = decode_word(code ^ (1 << i) ^ (1 << j));
                    assert!(uncorrectable && !corrected, "byte {b} bits {i},{j} slipped through");
                }
            }
        }
    }

    #[test]
    fn clean_words_are_untouched_and_unused_bits_ignored() {
        for b in 0..=255u8 {
            assert_eq!(decode_word(encode_byte(b)), (b, false, false));
            assert_eq!(decode_word(encode_byte(b) | 0xE000), (b, false, false));
        }
    }

    #[test]
    fn noisy_channel_flags_what_it_cannot_fix() {
        let enc = encode_message("a message long enough to see some damage");
        let mut bad = enc.clone();
        bad[0] ^= 0b11; // two flipped bits in one word
        let d = decode_message(&bad);
        assert_eq!((d.corrected, d.uncorrectable), (0, 1));
    }

    #[test]
    fn qber() {
        let a = encode_message("abc");
        assert_eq!(qkd_check(&a, &a), (0.0, true));
    }
}

/// BB84-like simulation (src/services/quantum/QuantumMds.ts `qkdRun`). Field order matches the TS result.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QkdResult {
    pub length: usize,
    pub sifted_len: usize,
    pub qber: f64,
    pub eavesdrop_detected: bool,
    pub sample_alice: Vec<u8>,
    pub sample_bob: Vec<u8>,
}

pub fn qkd_run(length: usize, eavesdrop_prob: f64) -> QkdResult {
    let mut rng = rand::thread_rng();
    let bit = |r: &mut rand::rngs::ThreadRng| r.gen::<f64>() < 0.5;
    let alice_bits: Vec<u8> = (0..length).map(|_| bit(&mut rng) as u8).collect();
    let alice_bases: Vec<u8> = (0..length).map(|_| bit(&mut rng) as u8).collect();
    let (mut tx_bits, mut tx_bases) = (vec![], vec![]);
    for i in 0..length {
        if rng.gen::<f64>() < eavesdrop_prob {
            let eve = bit(&mut rng) as u8;
            let measured = if eve == alice_bases[i] { alice_bits[i] } else { bit(&mut rng) as u8 };
            tx_bits.push(measured);
            tx_bases.push(eve);
        } else {
            tx_bits.push(alice_bits[i]);
            tx_bases.push(alice_bases[i]);
        }
        if rng.gen::<f64>() < 0.01 {
            tx_bits[i] = 1 - tx_bits[i];
        }
    }
    let (mut sift_a, mut sift_b) = (vec![], vec![]);
    for i in 0..length {
        let b_basis = bit(&mut rng) as u8;
        let b_bit = if b_basis == tx_bases[i] { tx_bits[i] } else { bit(&mut rng) as u8 };
        if alice_bases[i] == b_basis {
            sift_a.push(alice_bits[i]);
            sift_b.push(b_bit);
        }
    }
    let mismatches = sift_a.iter().zip(&sift_b).filter(|(a, b)| a != b).count();
    let qber = if sift_a.is_empty() { 0.0 } else { mismatches as f64 / sift_a.len() as f64 };
    QkdResult {
        length,
        sifted_len: sift_a.len(),
        qber,
        eavesdrop_detected: qber > 0.05 || eavesdrop_prob > 0.05,
        sample_alice: sift_a.iter().take(16).copied().collect(),
        sample_bob: sift_b.iter().take(16).copied().collect(),
    }
}

#[cfg(test)]
mod qkd_tests {
    use super::*;

    #[test]
    fn qkd_without_eve_has_low_qber() {
        let r = qkd_run(2000, 0.0);
        assert!(r.sifted_len > 800 && r.qber < 0.05 && !r.eavesdrop_detected);
    }

    #[test]
    fn qkd_with_eve_is_detected() {
        assert!(qkd_run(2000, 1.0).eavesdrop_detected);
    }
}
