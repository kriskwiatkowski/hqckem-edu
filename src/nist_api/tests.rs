#![cfg(test)]

//! Known Answer Test (KAT) validation for HQC-KEM
//!
//! This module validates the HQC-KEM implementation against official NIST PQC test vectors.
//! It is only compiled when both test and std features are enabled, as it requires file I/O
//! to read the KAT vectors from disk.

#[cfg(feature = "std")]
mod kat_tests {
    use super::super::nist_api::{nist_decaps, nist_encaps, nist_keygen};
    use crate::HqcParams;
    use rand_core::{CryptoRng, RngCore};
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    use std::boxed::Box;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::vec::Vec;

    struct HqcPrng {
        reader: Box<dyn XofReader>,
    }

    impl HqcPrng {
        /// Create a new HQC PRNG seeded with SHAKE256
        /// This reproduces the deterministic RNG used in NIST test vector generation
        fn new(seed: &[u8; 48]) -> Self {
            let mut h = Shake256::default();
            h.update(seed.as_ref());
            h.update(&[0u8]);
            HqcPrng {
                reader: Box::new(h.finalize_xof()),
            }
        }
    }

    impl RngCore for HqcPrng {
        fn next_u32(&mut self) -> u32 {
            rand_core::impls::next_u32_via_fill(self)
        }

        fn next_u64(&mut self) -> u64 {
            rand_core::impls::next_u64_via_fill(self)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.reader.read(dest);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for HqcPrng {}

    /// Parsed NIST PQC KAT vector containing seed and expected outputs
    struct KatVector {
        count: u32,
        seed: [u8; 48],
        pk: Vec<u8>,
        sk: Vec<u8>,
        ct: Vec<u8>,
        ss: Vec<u8>,
    }

    fn parse_hex(s: &str) -> Vec<u8> {
        hex::decode(s)
            .unwrap_or_else(|e| panic!("Invalid hex at '{}...': {}", &s[..s.len().min(16)], e))
    }

    /// Parse NIST PQC .rsp file format into KAT vectors
    /// Each vector contains a seed and expected outputs for keygen, encaps, and decaps
    fn parse_kat_rsp(path: &str) -> Vec<KatVector> {
        let file = File::open(path).unwrap_or_else(|e| panic!("Cannot open '{}': {}", path, e));
        let reader = BufReader::new(file);

        let mut vectors: Vec<KatVector> = Vec::new();
        let mut current: Option<KatVector> = None;

        for line in reader.lines() {
            let line = line.expect("I/O error reading KAT file");
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (key, value) = match line.split_once(" = ") {
                Some(pair) => pair,
                None => continue,
            };

            match key {
                "count" => {
                    if let Some(v) = current.take() {
                        vectors.push(v);
                    }
                    current = Some(KatVector {
                        count: value.parse().expect("count must be an integer"),
                        seed: [0u8; 48],
                        pk: Vec::new(),
                        sk: Vec::new(),
                        ct: Vec::new(),
                        ss: Vec::new(),
                    });
                }
                "seed" => {
                    if let Some(ref mut v) = current {
                        let bytes = parse_hex(value);
                        assert_eq!(bytes.len(), 48, "seed must be 48 bytes");
                        v.seed.copy_from_slice(&bytes);
                    }
                }
                "pk" => {
                    if let Some(ref mut v) = current {
                        v.pk = parse_hex(value);
                    }
                }
                "sk" => {
                    if let Some(ref mut v) = current {
                        v.sk = parse_hex(value);
                    }
                }
                "ct" => {
                    if let Some(ref mut v) = current {
                        v.ct = parse_hex(value);
                    }
                }
                "ss" => {
                    if let Some(ref mut v) = current {
                        v.ss = parse_hex(value);
                    }
                }
                _ => {}
            }
        }

        if let Some(v) = current {
            vectors.push(v);
        }

        vectors
    }

    /// Validate key generation against KAT vector
    /// Checks that generated public and secret keys match expected values
    fn check_keygen(param: &HqcParams, kat: &KatVector) {
        let mut prng = HqcPrng::new(&kat.seed);
        let mut ek: [u8; 7237] = [0u8; 7237];
        let mut dk: [u8; 7333] = [0u8; 7333];
        let (ek_len, dk_len) = nist_keygen(param, &mut ek, &mut dk, &mut prng);

        assert_eq!(ek_len, kat.pk.len(), "count={}", kat.count);
        assert_eq!(dk_len, kat.sk.len(), "count={}", kat.count);
        assert_eq!(&ek[..ek_len], kat.pk.as_slice(), "count={}", kat.count);
        assert_eq!(&dk[..dk_len], kat.sk.as_slice(), "count={}", kat.count);
    }

    /// Validate encapsulation against KAT vector
    /// Checks that generated ciphertext and shared secret match expected values
    fn check_encaps(param: &HqcParams, kat: &KatVector) {
        let mut prng = HqcPrng::new(&kat.seed);
        let mut discard = [0u8; 32];
        prng.fill_bytes(&mut discard);

        let mut shared_secret = [0u8; 32];
        let mut ciphertext = Vec::new();
        ciphertext.resize(kat.ct.len(), 0u8);
        nist_encaps(param, &kat.pk, &mut shared_secret, &mut ciphertext, &mut prng);

        assert_eq!(&ciphertext[..], &kat.ct[..], "count={}", kat.count);
        assert_eq!(shared_secret.as_slice(), kat.ss.as_slice(), "count={}", kat.count);
    }

    /// Validate decapsulation against KAT vector
    /// Checks that recovered shared secret matches expected value
    fn check_decaps(param: &HqcParams, kat: &KatVector) {
        let mut ss = [0u8; 32];
        nist_decaps(param, kat.sk.as_slice(), kat.ct.as_slice(), &mut ss);
        assert_eq!(ss.as_slice(), kat.ss.as_slice(), "count={}", kat.count);
    }

    /// Run complete KAT validation for a parameter set
    /// Tests all three operations (keygen, encaps, decaps) for all vectors
    fn run_kat(path: &str, name: &str) {
        let vectors = parse_kat_rsp(path);
        let p = HqcParams::new(name).expect("Invalid parameter set");

        for kat in &vectors {
            check_keygen(&p, kat);
            check_encaps(&p, kat);
            check_decaps(&p, kat);
        }
    }

    /// KAT test for HQC-128 (128-bit security level)
    /// Validates against 100+ official NIST PQC test vectors
    #[test]
    fn kat_vectors_hqc_128() {
        run_kat("KAT/hqc-1/PQCkemKAT_2321.rsp", "HQC-128");
    }

    /// KAT test for HQC-192 (192-bit security level)
    /// Validates against 100+ official NIST PQC test vectors
    #[test]
    fn kat_vectors_hqc_192() {
        run_kat("KAT/hqc-3/PQCkemKAT_4602.rsp", "HQC-192");
    }

    /// KAT test for HQC-256 (256-bit security level)
    /// Validates against 100+ official NIST PQC test vectors
    #[test]
    fn kat_vectors_hqc_256() {
        run_kat("KAT/hqc-5/PQCkemKAT_7333.rsp", "HQC-256");
    }
}


