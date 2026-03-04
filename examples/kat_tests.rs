// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

//! HQC KAT (Known Answer Test) checker
//!
//! Parses NIST PQC KEM KAT response files (.rsp) and verifies the output
//! of the HQC implementation against the reference vectors.
//!
//! The NIST KAT procedure uses an AES-256 CTR-DRBG seeded deterministically
//! from the per-vector seed field. This DRBG drives key generation and
//! encapsulation, making the outputs reproducible.
//!
//! ```text
//! cargo run --example kat_tests
//! ```

use hqc::{HqcParams, nist_encaps, nist_generate_key, nist_decaps};
use rand_core::{CryptoRng, RngCore};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};

struct HqcPrng {
    reader: Box<dyn XofReader>,
}

impl HqcPrng {
    fn new(seed: &[u8; 48]) -> Self {
        let mut h = Shake256::default();
        h.update(seed.as_ref());
        h.update(&[0u8]); // HQC_PRNG_DOMAIN = 0
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

// ---------------------------------------------------------------------------
// KAT file parsing
// ---------------------------------------------------------------------------

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

/// Parse a NIST PQC KAT .rsp file into a list of test vectors.
fn parse_kat_rsp(path: &str) -> Vec<KatVector> {
    let file = File::open(path).unwrap_or_else(|e| panic!("Cannot open '{}': {}", path, e));
    let reader = BufReader::new(file);

    let mut vectors: Vec<KatVector> = Vec::new();
    let mut current: Option<KatVector> = None;

    for line in reader.lines() {
        let line = line.expect("I/O error reading KAT file");
        let line = line.trim();

        // Comments and blank lines — flush the current vector on blank
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

// ---------------------------------------------------------------------------
// Per-check helpers
// ---------------------------------------------------------------------------

fn check_keygen(param: &HqcParams, kat: &KatVector) -> (bool, bool) {
    let mut prng: HqcPrng = HqcPrng::new(&kat.seed);
    let mut ek: [u8; 7237] = [0u8; 7237];
    let mut dk: [u8; 7333] = [0u8; 7333];
    let (ek_len, dk_len) = nist_generate_key(param, &mut ek, &mut dk, &mut prng);
    let pk_len_ok = ek_len == kat.pk.len();
    let sk_len_ok = dk_len == kat.sk.len();
    let pk_ok = pk_len_ok && kat.pk == &ek[..ek_len];
    let sk_ok = sk_len_ok && kat.sk == &dk[..dk_len];
    (pk_ok, sk_ok)
}

fn check_encaps(param: &HqcParams, kat: &KatVector) -> Option<bool> {
    // The PRNG after keygen: encaps reads security_bytes (m) then 16 (salt) from prng.
    // We advance the shared PRNG: keygen consumed 32 bytes (seed_kem).
    let mut prng = HqcPrng::new(&kat.seed);
    let mut discard = vec![0u8; 32]; // skip seed_kem consumed by keygen
    prng.fill_bytes(&mut discard);
    let mut shared_secret = vec![0u8; 32];
    let mut ciphertext = vec![0u8; kat.ct.len()];

    nist_encaps(param, &kat.pk, &mut shared_secret, &mut ciphertext, &mut prng);
    let ct_ok = ciphertext.as_slice() == kat.ct.as_slice();
    let ss_ok = shared_secret.as_slice() == kat.ss.as_slice();
    if !ss_ok {
        println!(
            "  [FAIL] encaps: shared secret mismatch (expected \n{} got\n{})",
            hex::encode(&kat.ss),
            hex::encode(&shared_secret)
        );
    }
    Some(ct_ok && ss_ok)
}

fn check_decaps(param: &HqcParams, kat: &KatVector) -> Option<bool> {
    let mut ss: [u8; 32] = [0u8; 32];
    nist_decaps(&param, kat.sk.as_slice(), kat.ct.as_slice(), &mut ss);
    Some(ss.as_slice() == kat.ss.as_slice())
}

// ---------------------------------------------------------------------------
// Main runner
// ---------------------------------------------------------------------------

fn run_kat(path: &str, name: &str) {
    println!("=== {} KAT ===", name);
    println!("File : {}", path);
    println!();

    let vectors = parse_kat_rsp(path);
    println!("Loaded {} test vectors", vectors.len());
    println!();

    let mut kg_pass = 0usize;
    let mut kg_fail = 0usize;
    let mut enc_pass = 0usize;
    let mut enc_fail = 0usize;
    let mut enc_skip = 0usize;
    let mut dec_pass = 0usize;
    let mut dec_fail = 0usize;
    let mut dec_skip = 0usize;

    let p = HqcParams::new(name).expect(&format!("Invalid parameter set '{}'", name));

    for kat in &vectors {
        // --- keygen ---
        let (pk_ok, sk_ok) = check_keygen(&p, kat);
        if pk_ok && sk_ok {
            kg_pass += 1;
        } else {
            kg_fail += 1;
        }

        // --- encaps ---
        match check_encaps(&p, kat) {
            Some(true) => enc_pass += 1,
            Some(false) => {
                enc_fail += 1;
                println!("[FAIL] count={:3}  encaps: ct or ss mismatch", kat.count);
            }
            None => {
                enc_skip += 1;
                if enc_skip == 1 {
                    println!(
                        "[SKIP] encaps: KAT pk={} bytes vs EK_BYTES=",
                        kat.pk.len(),
                    );
                }
            }
        }

        // --- decaps ---
        match check_decaps(&p, kat) {
            Some(true) => dec_pass += 1,
            Some(false) => {
                dec_fail += 1;
                println!(
                    "[FAIL] count={:3}  decaps: ss mismatch (expected {})",
                    kat.count,
                    hex::encode(&kat.ss),
                );
            }
            None => {
                dec_skip += 1;
                if dec_skip == 1 {
                    println!(
                        "[SKIP] decaps: KAT ct={} bytes, sk={} bytes",
                        kat.ct.len(),
                        kat.sk.len()
                    );
                }
            }
        }
    }

    let total = vectors.len();
    println!();
    println!("Keygen : {}/{} passed", kg_pass, total);
    println!(
        "Encaps : {}/{} passed{}",
        enc_pass,
        total - enc_skip,
        if enc_skip > 0 {
            format!(", {} skipped", enc_skip)
        } else {
            String::new()
        }
    );
    println!(
        "Decaps : {}/{} passed{}",
        dec_pass,
        total - dec_skip,
        if dec_skip > 0 {
            format!(", {} skipped (size mismatch)", dec_skip)
        } else {
            String::new()
        }
    );

    let all_ok = kg_fail == 0 && enc_fail == 0 && enc_skip == 0 && dec_fail == 0 && dec_skip == 0;
    if all_ok {
        println!("\nAll {} vectors PASSED", total);
    } else {
        println!(
            "\n{} keygen failure(s), {} encaps failure(s), {} decaps failure(s), {} skipped",
            kg_fail, enc_fail, dec_fail, dec_skip
        );
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let kat_path_1 = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "KAT/hqc-1/PQCkemKAT_2321.rsp".to_string());
    let kat_path_3 = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "KAT/hqc-3/PQCkemKAT_4602.rsp".to_string());
    let kat_path_5 = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "KAT/hqc-5/PQCkemKAT_7333.rsp".to_string());

    run_kat(&kat_path_1, "HQC-128");
    println!();
    run_kat(&kat_path_3, "HQC-192");
    println!();
    run_kat(&kat_path_5, "HQC-256");
}
