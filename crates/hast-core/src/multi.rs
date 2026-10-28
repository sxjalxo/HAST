//! HBSS / HBSS* / HBSS** and a simulated SPHINCS+ (comparison only, as in the original).
use crate::hbss::{self, KeyPair, PublicKey, Signature};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Hbss,
    Star,
    StarStar,
    Sphincs,
}

impl Scheme {
    pub const ALL: [Scheme; 4] = [Scheme::Hbss, Scheme::Star, Scheme::StarStar, Scheme::Sphincs];
    pub fn name(self) -> &'static str {
        match self {
            Scheme::Hbss => "HBSS",
            Scheme::Star => "HBSS*",
            Scheme::StarStar => "HBSS**",
            Scheme::Sphincs => "SPHINCS+",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Metrics {
    pub keygen_ms: f64,
    pub sign_ms: f64,
    pub verify_ms: f64,
    pub public_key_size: usize,
    pub private_key_size: usize,
    pub signature_size: usize,
    pub memory_footprint: usize,
}

pub struct Comparison {
    pub scheme: Scheme,
    pub key_size: &'static str,
    pub sig_size: &'static str,
    pub speed: &'static str,
    pub security_level: u32,
    pub description: &'static str,
}

pub fn comparisons() -> Vec<Comparison> {
    let c = |scheme, key_size, sig_size, speed, description| Comparison {
        scheme,
        key_size,
        sig_size,
        speed,
        security_level: 128,
        description,
    };
    vec![
        c(Scheme::Hbss, "64 KB", "4.3 KB", "Fast", "Hash-based stateless signatures with Bloom filters"),
        c(Scheme::Star, "32 bytes (seed)", "4.3 KB", "Fast", "Seed-based HBSS with reduced memory footprint"),
        c(Scheme::StarStar, "64 bytes (root)", "~45 KB", "Balanced", "Merkle-enhanced HBSS with compact public keys"),
        c(Scheme::Sphincs, "32 bytes", "~17 KB", "Slow", "SLH-DSA-SHAKE-128f (FIPS 205), real implementation"),
    ]
}

// ---- HBSS** ----
// Same keys as HBSS, but the public key is only the 64-byte Merkle root and every signature carries
// authentication paths (hbss::sign_with_proofs).

pub fn star_star_sign(message: &str, kp: &KeyPair) -> Signature {
    hbss::sign_with_proofs(message, kp)
}

pub fn star_star_verify(message: &str, sig: &Signature, pk: &PublicKey) -> bool {
    hbss::verify(
        message,
        sig,
        &PublicKey {
            commitments: vec![],
            ..pk.clone()
        },
    )
}

// ---- SPHINCS+ (SLH-DSA-SHAKE-128f, FIPS 205), a real implementation ----

use slh_dsa::signature::{Keypair, Signer, Verifier};
use slh_dsa::{Shake128f, Signature as SlhSignature, SigningKey};

pub struct SphincsKeyPair {
    sk: SigningKey<Shake128f>,
}

pub struct SphincsSignature {
    sig: SlhSignature<Shake128f>,
    pub size: usize,
}

pub fn sphincs_keygen() -> SphincsKeyPair {
    SphincsKeyPair {
        sk: SigningKey::<Shake128f>::new(&mut rand::thread_rng()),
    }
}

pub fn sphincs_sign(message: &str, kp: &SphincsKeyPair) -> SphincsSignature {
    let sig = kp.sk.try_sign(message.as_bytes()).expect("SLH-DSA signing");
    let size = sig.to_vec().len();
    SphincsSignature { sig, size }
}

pub fn sphincs_verify(message: &str, sig: &SphincsSignature, kp: &SphincsKeyPair) -> bool {
    kp.sk.verifying_key().verify(message.as_bytes(), &sig.sig).is_ok()
}

pub fn sphincs_public_key_size(kp: &SphincsKeyPair) -> usize {
    kp.sk.verifying_key().to_bytes().len()
}

pub fn sphincs_private_key_size(kp: &SphincsKeyPair) -> usize {
    kp.sk.to_bytes().len()
}

/// `now_ms` is a monotonic clock in ms (performance.now in the browser, Instant natively).
pub fn benchmark(scheme: Scheme, message: &str, now_ms: &dyn Fn() -> f64) -> Metrics {
    let t0 = now_ms();
    let mut m = Metrics::default();
    let (t1, t2, t3);
    match scheme {
        Scheme::Hbss | Scheme::Star => {
            let kp = if scheme == Scheme::Hbss {
                hbss::keygen(hbss::N)
            } else {
                hbss::star_keygen(&format!("random-seed-{t0}"), hbss::N)
            };
            t1 = now_ms();
            let sig = hbss::sign(message, &kp.private_key);
            t2 = now_ms();
            hbss::verify(message, &sig, &kp.public_key);
            t3 = now_ms();
            m.public_key_size = hbss::public_key_size(&kp.public_key);
            m.private_key_size = if scheme == Scheme::Hbss { hbss::N * 64 } else { 32 };
            m.signature_size = hbss::signature_size(&sig);
            m.memory_footprint = m.public_key_size + m.private_key_size;
        }
        Scheme::StarStar => {
            let kp = hbss::keygen(hbss::N);
            t1 = now_ms();
            let sig = star_star_sign(message, &kp);
            t2 = now_ms();
            star_star_verify(message, &sig, &kp.public_key);
            t3 = now_ms();
            m.public_key_size = hbss::public_key_size(&kp.root_only());
            m.private_key_size = hbss::N * 64;
            m.signature_size = hbss::signature_size(&sig);
            m.memory_footprint = m.public_key_size + m.private_key_size;
        }
        Scheme::Sphincs => {
            let kp = sphincs_keygen();
            t1 = now_ms();
            let sig = sphincs_sign(message, &kp);
            t2 = now_ms();
            sphincs_verify(message, &sig, &kp);
            t3 = now_ms();
            m.public_key_size = sphincs_public_key_size(&kp);
            m.private_key_size = sphincs_private_key_size(&kp);
            m.signature_size = sig.size;
            m.memory_footprint = m.public_key_size + m.private_key_size;
        }
    }
    m.keygen_ms = t1 - t0;
    m.sign_ms = t2 - t1;
    m.verify_ms = t3 - t2;
    m
}

pub fn format_bytes(b: usize) -> String {
    if b < 1024 {
        format!("{b} B")
    } else if b < 1024 * 1024 {
        format!("{:.2} KB", b as f64 / 1024.0)
    } else {
        format!("{:.2} MB", b as f64 / 1048576.0)
    }
}

pub fn format_time(ms: f64) -> String {
    if ms < 1.0 {
        format!("{:.2} μs", ms * 1000.0)
    } else if ms < 1000.0 {
        format!("{ms:.2} ms")
    } else {
        format!("{:.2} s", ms / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_all_schemes_run() {
        let t = std::time::Instant::now();
        let now = move || t.elapsed().as_secs_f64() * 1000.0;
        for s in Scheme::ALL {
            assert!(benchmark(s, "msg", &now).signature_size > 0, "{}", s.name());
        }
    }

    #[test]
    fn star_star_verifies_against_root_only_and_rejects_tampering() {
        let kp = hbss::keygen(hbss::N);
        let sig = star_star_sign("m", &kp);
        assert!(star_star_verify("m", &sig, &kp.public_key));
        assert!(!star_star_verify("other", &sig, &kp.public_key));
    }

    #[test]
    fn sphincs_signs_and_rejects_tampering() {
        let kp = sphincs_keygen();
        let sig = sphincs_sign("hello", &kp);
        assert!(sphincs_verify("hello", &sig, &kp));
        assert!(!sphincs_verify("hellO", &sig, &kp));
        assert!(!sphincs_verify("hello", &sig, &sphincs_keygen()));
        assert_eq!((sig.size, sphincs_public_key_size(&kp)), (17088, 32));
    }

    #[test]
    fn format_helpers() {
        assert_eq!(format_bytes(2048), "2.00 KB");
        assert_eq!(format_time(0.5), "500.00 μs");
    }
}
