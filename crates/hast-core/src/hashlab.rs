//! Hash Playground helpers (components/HashPlayground.tsx).
use blake2::Blake2b512;
use sha2::{Digest, Sha256};
use sha3::Sha3_512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    Sha256,
    Sha512,
    Sha3_512,
    Blake2b,
}

impl Algo {
    pub const ALL: [Algo; 4] = [Algo::Sha256, Algo::Sha512, Algo::Sha3_512, Algo::Blake2b];

    pub fn name(self) -> &'static str {
        match self {
            Algo::Sha256 => "SHA-256",
            Algo::Sha512 => "SHA-512",
            Algo::Sha3_512 => "SHA3-512",
            Algo::Blake2b => "BLAKE2b",
        }
    }

    /// (bits, bytes, speed, security)
    pub fn info(self) -> (u32, u32, &'static str, &'static str) {
        match self {
            Algo::Sha256 => (256, 32, "Very Fast", "High"),
            Algo::Sha512 => (512, 64, "Fast", "Very High"),
            Algo::Sha3_512 => (512, 64, "Balanced", "Very High"),
            Algo::Blake2b => (512, 64, "Very Fast", "Very High"),
        }
    }
}

/// Real SHA-256, SHA-512, SHA3-512 (FIPS 202) and BLAKE2b-512.
pub fn hash(algo: Algo, input: &str) -> String {
    let b = input.as_bytes();
    match algo {
        Algo::Sha256 => hex::encode(Sha256::digest(b)),
        Algo::Sha512 => crate::hbss::sha512(input),
        Algo::Sha3_512 => hex::encode(Sha3_512::digest(b)),
        Algo::Blake2b => hex::encode(Blake2b512::digest(b)),
    }
}

/// Differing bits over the bytes both hex strings have (the original's NaN bytes contributed 0).
pub fn bit_difference(a: &str, b: &str) -> u32 {
    let (a, b) = (hex::decode(a).unwrap_or_default(), hex::decode(b).unwrap_or_default());
    a.iter().zip(&b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert!(hash(Algo::Sha256, "abc").starts_with("ba7816bf8f01cfea"));
        assert!(hash(Algo::Sha512, "abc").starts_with("ddaf35a193617aba"));
        assert!(hash(Algo::Sha3_512, "").starts_with("a69f73cca23a9ac5c8b567dc185a756e"));
        assert!(hash(Algo::Sha3_512, "abc").starts_with("b751850b1a57168a5693cd924b6b096e"));
        assert!(hash(Algo::Blake2b, "abc").starts_with("ba80a53f981c4d0d6a2797b69f12f6e9"));
        assert!(hash(Algo::Blake2b, "").starts_with("786a02f742015903c6c6fd852552d272"));
    }

    #[test]
    fn bit_difference_counts_bits() {
        assert_eq!(bit_difference("00ff", "0f0f"), 8);
        assert_eq!(bit_difference("abcd", "abcd"), 0);
        assert_eq!(bit_difference("ff", "ffff"), 0);
    }
}
