// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

//! HQC (Hamming Quasi-Cyclic) - Rust Implementation
//!
//! This is an educational implementation of the HQC post-quantum key encapsulation mechanism (KEM)
//! based on the HQC specification from https://pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf
//!
//! HQC is a code-based cryptosystem that uses quasi-cyclic codes and is a candidate for
//! NIST post-quantum standardization. It provides three security levels: HQC-128, HQC-192, and HQC-256.
//!
//! The implementation includes:
//! - Key generation (PKE and KEM)
//! - Encryption/Encapsulation
//! - Decryption/Decapsulation
//! - Reed-Solomon and Reed-Muller error correction codes
//! - Galois field arithmetic (GF(256))
//! - Vector operations over GF(2)[X]/(X^n - 1)

#![no_std]
//#![no_main]

use sha3::{
    digest::{ExtendableOutput, FixedOutput, XofReader},
    Digest, Sha3_256, Sha3_512, Shake256,
};

// ============================================================================
// Galois Field GF(256) Tables
// ============================================================================
// GF(256) with primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
// Used for Reed-Solomon encoding/decoding

/// Alpha powers: gf_exp[i] = alpha^i where alpha is a primitive element
/// GF_EXP[255] = 1 (since alpha^255 = 1), last two entries extend for gf_mul optimization
pub const GF_EXP: [u16; 258] = [
    1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76, 152, 45, 90, 180, 117,
    234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181,
    119, 238, 193, 159, 35, 70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161,
    95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240, 253, 231, 211, 187,
    107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217, 175, 67, 134, 17, 34, 68, 136,
    13, 26, 52, 104, 208, 189, 103, 206, 129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197,
    151, 51, 102, 204, 133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168,
    77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230, 209, 191, 99, 198,
    145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227, 219, 171, 75, 150, 49, 98, 196, 149,
    55, 110, 220, 165, 87, 174, 65, 130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167,
    83, 166, 81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18, 36, 72,
    144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44, 88, 176, 125, 250, 233, 207,
    131, 27, 54, 108, 216, 173, 71, 142, 1, 2, 4,
];

/// Discrete logarithm table: gf_log[a] = i such that alpha^i = a
/// gf_log[0] = 0 by convention (though log(0) is undefined)
pub const GF_LOG: [u16; 256] = [
    0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75, 4, 100, 224, 14, 52, 141, 239,
    129, 28, 193, 105, 248, 200, 8, 76, 113, 5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218,
    240, 18, 130, 69, 29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166, 6,
    191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136, 54, 208, 148, 206, 143,
    150, 219, 189, 241, 210, 19, 92, 131, 56, 70, 64, 30, 66, 182, 163, 195, 72, 126, 110, 107, 58,
    40, 84, 250, 133, 186, 61, 202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243,
    167, 87, 7, 112, 192, 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24, 227, 165,
    153, 119, 38, 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46, 55, 63, 209, 91, 149, 188, 207,
    205, 144, 135, 151, 178, 220, 252, 190, 97, 242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57,
    83, 71, 109, 65, 162, 31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246,
    108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204, 62, 90, 203, 89, 95, 176, 156,
    169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215, 79, 174, 213, 233, 230, 231, 173, 232, 116,
    214, 244, 234, 168, 80, 88, 175,
];

// ============================================================================
// Reed-Solomon Generator Polynomials
// ============================================================================
// Generator polynomials g(x) for RS codes used in the concatenated encoding scheme
// Each polynomial has degree 2*delta (where delta is the error correction capability)

/// Generator polynomial for HQC-128: degree 30, RS(46,16)
const G_POLY_128: &[u8] = &[
    89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118,
    105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
];

/// Generator polynomial for HQC-192: degree 32, RS(56,24)
const G_POLY_192: &[u8] = &[
    45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1,
    238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1,
];

/// Generator polynomial for HQC-256: degree 58, RS(90,32)
const G_POLY_256: &[u8] = &[
    49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201,
    115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191,
    144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1,
];

// ============================================================================
// Maximum Parameter Bounds
// ============================================================================
// These define buffer sizes for the most demanding parameter set (HQC-256)

/// Maximum n in 64-bit words (HQC-256: n=57637 → ⌈57637/64⌉ = 901)
const MAX_N64: usize = 901;
/// Maximum n1 (HQC-256: n1=90)
const MAX_N1: usize = 90;
/// Maximum n1*n2 in 64-bit words (HQC-256: n1*n2=57600 → ⌈57600/64⌉ = 900)
const MAX_N1N2_64: usize = 900;
/// Maximum n1*n2 in bytes (HQC-256: n1*n2=57600 → ⌈57600/8⌉ = 7200)
const MAX_N1N2_BYTES: usize = 7200;
/// Maximum Hamming weight omega_r or omega_e (HQC-256: 149)
const MAX_OMEGA: usize = 149;
/// Maximum n in bytes (HQC-256: n=57637 → ⌈57637/8⌉ = 7205)
const MAX_N_BYTES: usize = 7205;
/// Maximum delta (Reed-Solomon error correction capability) (HQC-256: 29)
const MAX_DELTA: usize = 29;
/// Maximum k (message size in bytes) (HQC-256: 32)
const MAX_K: usize = 32;

// ============================================================================
// Domain Separators for Hash Functions
// ============================================================================
// Per HQC spec, different hash function calls are separated by domain bytes

/// Domain separator for XOF (SHAKE256): seed || 0x01
const XOF_DOMAIN: u8 = 1;
/// Domain separator for Hash_I (SHA3-512): seed || 0x02
const HASH_I_DOMAIN: u8 = 2;
/// Domain separator for Hash_H (SHA3-256): ek || 0x01
const HASH_H_DOMAIN: u8 = 1;
/// Domain separator for Hash_G (SHA3-512): hash_ek || m || salt || 0x00
const HASH_G_DOMAIN: u8 = 0;
/// Domain separator for Hash_J (SHA3-256): hash_ek || sigma || u || v || salt || 0x03
const HASH_J_DOMAIN: u8 = 3;
/// Salt size for KEM encapsulation/decapsulation (16 bytes)
const SALT_SIZE : usize = 16usize;
/// Shared secret size for all parameter sets (32 bytes)
const SHARED_SECRET_SIZE: usize = 32;

// ============================================================================
// HQC Parameter Set Structure
// ============================================================================

/// Runtime parameters for an HQC parameter set (HQC-128, HQC-192, or HQC-256).
/// These define the security level and operational characteristics of the scheme.
pub struct HqcParams {
    /// Parameter set name (e.g., "HQC-128", "HQC-192", "HQC-256")
    pub name: &'static str,
    /// Code length: n (dimension of the quasi-cyclic code)
    /// Code length: n (dimension of the quasi-cyclic code)
    pub n: usize,
    /// Reed-Solomon code parameter: n1 (codeword length in GF(256) symbols)
    pub n1: usize,
    /// Reed-Muller multiplicity: n2 (RM codeword length in bits)
    pub n2: usize,
    /// Message length: k (in bytes)
    pub k: usize,
    /// Reed-Solomon error correction capability: delta (can correct up to delta errors)
    pub delta: usize,
    /// Hamming weight of secret key vectors x, y
    pub omega: usize,
    /// Hamming weight of random vectors r1, r2 during encryption
    pub omega_r: usize,
    /// Hamming weight of error vector e during encryption
    pub omega_e: usize,
    /// Security level in bits (128, 192, or 256)
    pub security_bits: usize,
    /// Precomputed Barrett reduction parameter: μ = ⌊2^32 / n⌋
    pub n_mu: u64,
    /// Rejection threshold for fixed-weight sampling: ⌊2^24 / n⌋ * n
    pub threshold: u32,
    /// Reed-Solomon generator polynomial for this parameter set
    pub g_poly: &'static [u8],
}

impl HqcParams {
    /// Create an HQC parameter set by name.
    ///
    /// # Arguments
    /// * `name` - One of "HQC-128", "HQC-192", or "HQC-256"
    ///
    /// # Returns
    /// The corresponding parameter set, or an error if the name is invalid
    pub fn new(name: &str) -> Result<Self, &'static str> {
        match name {
            // N=17669  n_size_bytes=2209  n1n2_size_bytes=2208
            // EK = 32 + 2209 = 2241   DK = 2241+32+16+32 = 2321   CT = 2209+2208+16 = 4433
            "HQC-128" => Ok(HqcParams {
                name: "HQC-128",
                n: 17669,
                n1: 46,
                n2: 384,
                k: 16,
                delta: 15,
                omega: 66,
                omega_r: 75,
                omega_e: 75,
                security_bits: 128,
                n_mu: 243079u64,
                threshold: 16767881u32,
                g_poly: G_POLY_128,
            }),

            // N=35851  n_size_bytes=4482  n1n2_size_bytes=4480
            // EK = 32 + 4482 = 4514   DK = 4514+32+24+32 = 4602   CT = 4482+4480+16 = 8978
            "HQC-192" => Ok(HqcParams {
                name: "HQC-192",
                n: 35851,
                n1: 56,
                n2: 640,
                k: 24,
                delta: 16,
                omega: 100,
                omega_r: 114,
                omega_e: 114,
                security_bits: 192,
                n_mu: 119800u64,
                threshold: 16742417u32,
                g_poly: G_POLY_192,
            }),

            // N=57637  n_size_bytes=7205  n1n2_size_bytes=7200
            // EK = 32 + 7205 = 7237   DK = 7237+32+32+32 = 7333   CT = 7205+7200+16 = 14421
            "HQC-256" => Ok(HqcParams {
                name: "HQC-256",
                n: 57637,
                n1: 90,
                n2: 640,
                k: 32, // this can be calculated
                delta: 29,
                omega: 131,
                omega_r: 149,
                omega_e: 149,
                security_bits: 256,
                n_mu: 74517u64,
                threshold: 16772367u32,
                g_poly: G_POLY_256,
            }),
            _ => todo!(),
        }
    }

    /// Returns security level in bytes (security_bits / 8)
    /// Returns security level in bytes (security_bits / 8)
    fn security_bytes(&self) -> usize {
        self.security_bits / 8
    }

    /// Returns the size of n-bit vectors in bytes: ⌈n/8⌉
    fn n_size_bytes(&self) -> usize {
        (self.n + 7) / 8
    }

    /// Returns the size of n-bit vectors in 64-bit words: ⌈n/64⌉
    fn n_size_64(&self) -> usize {
        (self.n + 63) / 64
    }

    /// Returns the size of (n1*n2)-bit vectors in bytes: ⌈(n1*n2)/8⌉
    fn n1n2_size_bytes(&self) -> usize {
        (self.n1 * self.n2 + 7) / 8
    }

    /// Returns the size of (n1*n2)-bit vectors in 64-bit words: ⌈(n1*n2)/64⌉
    fn n1n2_size_64(&self) -> usize {
        (self.n1 * self.n2 + 63) / 64
    }

    /// Returns public key size in bytes: n_size_bytes + 32 (for seed_ek)
    fn ek_size(&self) -> usize {
        self.n_size_bytes() + 32 /* seed */
    }
}

// ============================================================================
// Galois Field GF(256) Arithmetic
// ============================================================================

/// Multiplication in GF(256) using log/antilog tables.
/// Computes a * b in GF(256) where elements are represented as bytes.
/// Uses the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1.
#[inline(always)]
pub fn gf_mul(a: u16, b: u16) -> u16 {
    if a == 0 || b == 0 {
        return 0;
    }
    let s = GF_LOG[a as usize] + GF_LOG[b as usize];
    GF_EXP[if s >= 255 {
        (s - 255) as usize
    } else {
        s as usize
    }]
}

/// Multiplicative inverse in GF(256).
/// Computes a^{-1} such that a * a^{-1} = 1 in GF(256).
/// Returns 0 for input 0 (undefined, but convenient).
#[inline(always)]
pub fn gf_inverse(a: u16) -> u16 {
    if a == 0 {
        return 0;
    }
    GF_EXP[(255 - GF_LOG[a as usize]) as usize]
}


// ============================================================================
// Cryptographic Hash and XOF Functions
// ============================================================================
// Per HQC specification, these functions are used for key derivation and
// random sampling, with domain separation to ensure independent outputs

/// XOF (Extendable Output Function): SHAKE256(seed || 0x01)
/// Used for expanding seeds into random vectors and fixed-weight samples.
pub fn xof_reader(seed: &[u8]) -> impl XofReader {
    use sha3::digest::Update;
    let mut h = Shake256::default();
    Update::update(&mut h, seed);
    Update::update(&mut h, &[XOF_DOMAIN]);
    h.finalize_xof()
}

/// Hash_I: SHA3-512(seed || 0x02) → 64 bytes
/// Used in PKE key generation to split a seed into seed_dk (32 bytes) and seed_ek (32 bytes).
pub fn hash_i(seed: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(seed);
    h.update(&[HASH_I_DOMAIN]);
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize_fixed());
    out
}

/// Hash_H: SHA3-256(ek || 0x01) → 32 bytes
/// Computes a hash of the public key for use in KEM encapsulation/decapsulation.
pub fn hash_h(ek: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ek);
    h.update(&[HASH_H_DOMAIN]);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize_fixed());
    out
}

/// Hash_G: SHA3-512(hash_ek || m || salt || 0x00) → 64 bytes
/// Derives shared secret K (first 32 bytes) and randomness theta (last 32 bytes) in KEM.
pub fn hash_g(hash_ek: &[u8], m: &[u8], salt: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(hash_ek);
    h.update(m);
    h.update(salt);
    h.update(&[HASH_G_DOMAIN]);
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize_fixed());
    out
}

/// Hash_J: SHA3-256(hash_ek || sigma || u || v || salt || 0x03) → 32 bytes
/// Computes the "implicit rejection" shared secret used when decryption fails in FO transform.
pub fn hash_j(hash_ek: &[u8], sigma: &[u8], u: &[u8], v: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(hash_ek);
    h.update(sigma);
    h.update(u);
    h.update(v);
    h.update(salt);
    h.update(&[HASH_J_DOMAIN]);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize_fixed());
    out
}

// ============================================================================
// Vector Conversion Utilities
// ============================================================================
// These functions convert between byte arrays and 64-bit word arrays,
// which are used to represent polynomial coefficients in GF(2)[X]

/// Convert a vector (array of u64 words) to bytes in little-endian order.
/// Writes the first `n` bytes from the vector into `out`.
fn vec_to_bytes(out: &mut [u8], vec: &[u64], n: usize) {
    for (dst, &w) in out[..n].chunks_mut(8).zip(vec.iter()) {
        let word = w.to_le_bytes();
        dst.copy_from_slice(&word[..dst.len()]);
    }
}

/// Helper: append bytes from `src` to `out`, returning the remaining slice.
/// Used for building serialized outputs (keys, ciphertexts).
#[inline(always)]
fn append_bytes<'a>(out: &'a mut [u8], src: &[u8]) -> &'a mut [u8] {
    let (dst, rest) = out.split_at_mut(src.len());
    dst.copy_from_slice(src);
    rest
}

/// Convert vector `v` (u64 words) to bytes, writing exactly `out.len()` bytes.
/// Used when the output buffer size is known in advance.
pub fn vec_to_bytes_into(v: &[u64], out: &mut [u8]) {
let mut written = 0;
    for &w in v {
        if written >= out.len() {
            break;
        }
        let word = w.to_le_bytes();
        let take = (out.len() - written).min(8);
        out[written..written + take].copy_from_slice(&word[..take]);
        written += take;
    }
}

/// Helper: append vector bytes to output buffer and return remaining slice.
#[inline(always)]
fn append_vec_bytes<'a>(out: &'a mut [u8], v: &[u64], n_bytes: usize) -> &'a mut [u8] {
    let (dst, rest) = out.split_at_mut(n_bytes);
    vec_to_bytes_into(v, dst);
    rest
}

/// Convert bytes to a vector of u64 words in little-endian order.
/// Each 8 bytes become one u64 word; zero-padded if bytes.len() < out.len() * 8.
pub fn bytes_to_vec(out: &mut [u64], bytes: &[u8]) {
    for i in 0..out.len() {
        let start = i * 8;
        let end = (start + 8).min(bytes.len());
        if start < bytes.len() {
            let mut word = [0u8; 8];
            word[..end - start].copy_from_slice(&bytes[start..end]);
            out[i] = u64::from_le_bytes(word);
        }
    }
}

// ============================================================================
// Barrett Reduction and Constant-Time Utilities
// ============================================================================

/// Barrett reduction: compute x mod n using precomputed μ = ⌊2^32 / n⌋.
/// More efficient than division for repeated modular reductions with fixed n.
fn barrett_reduce(x: u32, n: u32, n_mu: u64) -> u32 {
    let q = ((x as u64 * n_mu) >> 32) as u32;
    let mut r = x.wrapping_sub(q.wrapping_mul(n));
    let flag = ((r.wrapping_sub(n) >> 31) ^ 1) as u32;
    r = r.wrapping_sub(0u32.wrapping_sub(flag) & n);
    r
}

/// Constant-time equality comparison: returns 1 if v1 == v2, else 0.
/// Avoids branching to prevent timing side-channels.
fn compare_u32(v1: u32, v2: u32) -> u32 {
    1 ^ (((v1.wrapping_sub(v2)) | (v2.wrapping_sub(v1))) >> 31)
}

// ============================================================================
// Fixed-Weight Vector Sampling
// ============================================================================
// HQC requires sampling sparse binary vectors with fixed Hamming weight.
// Two algorithms are used:
// - vect_sample_fixed_weight1: rejection sampling (for key generation)
// - vect_sample_fixed_weight2: Fisher-Yates shuffle (for encryption)

/// Sample a random binary vector of length n with exact Hamming weight omega.
/// Uses rejection sampling to ensure uniform distribution over all valid vectors.
/// Used in key generation (sampling x, y with weight omega).
pub fn vect_sample_fixed_weight1(
    out: &mut [u64],
    xof: &mut dyn XofReader,
    n: usize,
    omega: usize,
    n_mu: u64,
    threshold: u32) {
    let mut support: [u32; MAX_OMEGA] = [0u32; MAX_OMEGA];
    let mut buf = [0u8; 3];
    let mut i = 0;

    while i < omega {
        xof.read(&mut buf);
        let c = buf[0] as u32 | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16);
        if c >= threshold {
            continue;
        }
        let c = barrett_reduce(c, n as u32, n_mu);
        let mut ok = true;
        for j in 0..i {
            if c == support[j] {
                ok = false;
                break;
            }
        }
        if ok {
            support[i] = c;
            i += 1;
        }
    }

    for &pos in &support[..omega] {
        out[(pos >> 6) as usize] |= 1u64 << (pos & 0x3f);
    }
}

/// Sample a random binary vector of length n with exact Hamming weight.
/// Uses a Fisher-Yates-like permutation algorithm that's faster than rejection sampling.
/// Used in encryption (sampling r1, r2, e with weights omega_r, omega_e).
pub fn vect_sample_fixed_weight2(
    out: &mut [u64],
    xof: &mut dyn XofReader,
    n: usize,
    weight: usize) {

    let w4 = 4*weight;
    let mut rand_bytes: [u8; 4 * MAX_OMEGA] = [0u8; 4 * MAX_OMEGA];
    let mut rand_u32: [u32; MAX_OMEGA] = [0u32; MAX_OMEGA];

    xof.read(&mut rand_bytes[..w4]);
    for (i, c) in rand_bytes[..w4].chunks_exact(4).enumerate() {
        rand_u32[i] =
            u32::from_le_bytes(
                [c[0], c[1], c[2], c[3]]);
    }

    let mut support: [u32; MAX_OMEGA] = [0u32; MAX_OMEGA];
    for i in 0..weight {
        let buff = rand_u32[i] as u64;
        support[i] = (i as u32) + ((buff * (n as u64 - i as u64)) >> 32) as u32;
    }

    // Deduplicate in constant-time (backward pass).
    for i in (0..weight.saturating_sub(1)).rev() {
        let mut found: u32 = 0;
        for j in (i + 1)..weight {
            found |= compare_u32(support[j], support[i]);
        }
        let mask = 0u32.wrapping_sub(found);
        support[i] = (mask & i as u32) | (!mask & support[i]);
    }

    for &pos in &support[0..weight] {
        out[(pos >> 6) as usize] |= 1u64 << (pos & 0x3f);
    }
}

// ============================================================================
// Vector Operations Over GF(2)[X]
// ============================================================================
// Vectors represent polynomials in GF(2)[X] / (X^n - 1), the quasi-cyclic ring.
// Operations are performed on bit vectors stored as arrays of u64 words.

/// Fill a vector with n uniformly random bits from XOF.
/// The vector is stored as u64 words; the last word is masked to exactly n bits.
pub fn vect_set_random(
    out: &mut [u64],
    xof: &mut dyn XofReader,
    n: usize,
    n_size_bytes: usize,
    n_size_64: usize) {

    let mut bytes: [u8; MAX_N_BYTES] = [0u8; MAX_N_BYTES];
    xof.read(&mut bytes[..n_size_bytes]);
    bytes_to_vec(out, &bytes);
    let n_mod = n & 63;
    if n_mod != 0 {
        out[n_size_64 - 1] &= (1u64 << n_mod) - 1;
    }
}

/// Vector addition in GF(2): out = a XOR b.
/// Addition in GF(2) is simply XOR at the bit level.
pub fn vect_add(out: &mut [u64], a: &[u64], b: &[u64], size: usize) {
    for i in 0..size {
        out[i] = a[i] ^ b[i];
    }
}

/// Polynomial multiplication in GF(2)[X] / (X^n - 1).
/// Computes out = a * b mod (X^n - 1) using schoolbook multiplication with carry-less arithmetic.
/// This is the core operation in the HQC cryptosystem (computing s = yh + x and v = r2*s + e).
pub fn vect_mul(out: &mut [u64], a: &[u64], b: &[u64], n: usize) {
    let mut full: [u64; 2 * MAX_N64 + 1] = [0; 2 * MAX_N64 + 1];
    let n_size_64 = (n + 63) / 64;
    for i in 0..n_size_64 {
        let ai = a[i];
        for bit in 0..64u32 {
            if (ai >> bit) & 1 == 0 {
                continue;
            }
            let sh = bit as usize;
            let inv = 64 - sh;
            if sh == 0 {
                for j in 0..n_size_64 {
                    full[i + j] ^= b[j];
                }
            } else {
                for j in 0..n_size_64 {
                    full[i + j] ^= b[j] << sh;
                    full[i + j + 1] ^= b[j] >> inv;
                }
            }
        }
    }
    // Reduce mod X^n − 1
    let n_mod = n % 64;
    for i in 0..n_size_64 {
        let r = full[i + n_size_64 - 1] >> n_mod;
        let carry = full[i + n_size_64] << (64 - n_mod);
        out[i] = full[i] ^ r ^ carry;
    }
    out[n_size_64 - 1] &= (1u64 << n_mod) - 1;
}

/// Truncate a vector: zero out all bits beyond n1n2.
/// Used to reduce an n-bit result to n1*n2 bits (the code dimension).
pub fn vect_truncate(v: &mut [u64], n_bits: usize, n1n2: usize) {
    let new_full = n1n2 / 64;
    let rem = n1n2 % 64;
    let orig = (n_bits + 63) / 64;
    let mut idx = new_full;
    if rem > 0 {
        v[idx] &= (1u64 << rem) - 1;
        idx += 1;
    }
    for i in idx..orig {
        v[i] = 0;
    }
}

/// Constant-time byte-wise comparison: returns 0 if equal, 1 if not equal.
/// Used in decapsulation to check if re-encryption matches the received ciphertext.
pub fn vect_compare(v1: &[u8], v2: &[u8]) -> u8 {
    let mut r: u16 = 0x0100;
    for (a, b) in v1.iter().zip(v2.iter()) {
        r |= (*a ^ *b) as u16;
    }
    ((r - 1) >> 8) as u8
}

// ============================================================================
// Reed-Muller Code RM(1,7)
// ============================================================================
// The Reed-Muller code RM(1,7) encodes 8 bits into a 128-bit codeword.
// It can correct up to 32 bit errors. Multiple copies are concatenated for longer messages.

/// Encode a single byte into a 128-bit RM(1,7) codeword (returned as 4 u32 words).
/// Uses a fast bitwise implementation of first-order Reed-Muller encoding.
fn rm_encode_byte(m: u8) -> [u32; 4] {
    let m = m as u32;
    let bit = |n: u32| -> u32 { 0u32.wrapping_sub((m >> n) & 1) };
    let mut fw = bit(7);
    fw ^= bit(0) & 0xaaaaaaaa;
    fw ^= bit(1) & 0xcccccccc;
    fw ^= bit(2) & 0xf0f0f0f0;
    fw ^= bit(3) & 0xff00ff00;
    fw ^= bit(4) & 0xffff0000;
    let mut w = [0u32; 4];
    w[0] = fw;
    fw ^= bit(5);
    w[1] = fw;
    fw ^= bit(6);
    w[3] = fw;
    fw ^= bit(5);
    w[2] = fw;
    w
}

/// Encode n1 bytes (message) into n1*n2 bits using RM(1,7).
/// Each byte is encoded into a 128-bit RM codeword, repeated `mult` times
/// where mult = ⌈n2/128⌉ to fill the n2-bit space allocated per byte.
pub fn rm_encode(out: &mut [u64], msg: &[u8], n1: usize, n2: usize, _n1n2_size_64: usize) {
    let mult = (n2 + 127) / 128;
    for i in 0..n1 {
        let cw = rm_encode_byte(msg[i]);
        for copy in 0..mult {
            let cw_idx = i * mult + copy;
            let wi = cw_idx * 2; // each 128-bit codeword = 2 u64 words
            out[wi] = (cw[0] as u64) | ((cw[1] as u64) << 32);
            out[wi + 1] = (cw[2] as u64) | ((cw[3] as u64) << 32);
        }
    }
}

/// Fast Hadamard Transform on 128 elements.
/// Used in Reed-Muller decoding for majority-logic decision.
fn hadamard(data: &mut [i16; 128]) {
    let mut tmp = [0i16; 128];
    for _ in 0..7 {
        for i in 0..64 {
            let a = data[2 * i];
            let b = data[2 * i + 1];
            tmp[i] = a + b;
            tmp[i + 64] = a - b;
        }
        *data = tmp;
    }
}

/// Find the peak (maximum absolute value) in Hadamard-transformed data.
/// Returns an 8-bit value encoding position and sign (used to decode one byte).
fn find_peaks(t: &[i16; 128]) -> u8 {
    let mut best_abs: i32 = 0;
    let mut best_val: i32 = 0;
    let mut best_pos: i32 = 0;
    for i in 0..128 {
        let v = t[i] as i32;
        let abs = if v >= 0 { v } else { -v };
        if abs > best_abs {
            best_abs = abs;
            best_val = v;
            best_pos = i as i32;
        }
    }
    (best_pos | (128 * (best_val > 0) as i32)) as u8
}

/// Decode n1*n2 bits back to n1 bytes using RM(1,7).
/// Sums multiple copies of each codeword, applies Hadamard transform, and finds peaks.
pub fn rm_decode(msg: &mut [u8], cdw: &[u64], n1: usize, n2: usize)  {
    let mult = (n2 + 127) / 128;
    for i in 0..n1 {
        let mut expanded = [0i16; 128];
        for copy in 0..mult {
            let cw_idx = i * mult + copy;
            let wi = cw_idx * 2;
            let w0 = cdw[wi];
            let w1 = cdw[wi + 1];
            let parts = [
                (w0 & 0xffffffff) as u32,
                (w0 >> 32) as u32,
                (w1 & 0xffffffff) as u32,
                (w1 >> 32) as u32,
            ];
            for part in 0..4 {
                for bit in 0..32 {
                    expanded[part * 32 + bit] += ((parts[part] >> bit) & 1) as i16;
                }
            }
        }
        hadamard(&mut expanded);
        expanded[0] -= 64 * mult as i16;
        msg[i] = find_peaks(&expanded);
    }
}

// ============================================================================
// Reed-Solomon Code RS(n1, k, 2*delta)
// ============================================================================
// Systematic Reed-Solomon code over GF(256) used as the outer code.
// Can correct up to delta symbol errors.

/// Encode a k-byte message into an n1-symbol RS codeword in systematic form.
/// Output format: [parity symbols (n1-k)] || [message symbols (k)].
pub fn rs_encode(cdw: &mut [u8], msg: &[u8], n1: usize, k: usize, g_poly: &[u8]) {
    let nm_k: usize = n1 - k; // = 2*delta = PARAM_G - 1
    for i in 0..k {
        let gate = (msg[k - 1 - i] ^ cdw[nm_k - 1]) as u16;
        let mut tmp = [0u8; MAX_N1];
        for (j, &c) in g_poly.iter().enumerate() {
            tmp[j] = gf_mul(gate, c as u16) as u8;
        }
        for kk in (1..nm_k).rev() {
            cdw[kk] = cdw[kk - 1] ^ tmp[kk];
        }
        cdw[0] = tmp[0];
    }
    cdw[nm_k..n1].copy_from_slice(msg);
}

/// Compute syndromes for RS decoding.
/// Syndrome s_i = sum_j cdw[j] * alpha^{(i+1)*j} for i=0..2*delta-1.
fn compute_syndromes(out: &mut [u16], cdw: &[u8], n1: usize, delta: usize)  {
    for i in 0..(2 * delta) {
        let mut si = cdw[0] as u16;
        for j in 1..n1 {
            let exp = ((i + 1) * j) % 255;
            si ^= gf_mul(cdw[j] as u16, GF_EXP[exp]);
        }
        out[i] = si;
    }
}

/// Berlekamp-Massey algorithm: compute the error-locator polynomial sigma(X).
/// Returns the degree of sigma. Uses constant-time operations to avoid timing leaks.
fn compute_elp(sigma: &mut [u16], syndromes: &[u16], delta: usize) -> u16 {
    let mut deg_sigma: u16 = 0;
    let mut deg_sigma_p: u16 = 0;
    let mut deg_sigma_copy: u16;
    let mut pp: u16 = u16::MAX; // represents -1
    let mut d_p: u16 = 1;
    let mut d: u16 = syndromes[0];
    let mut sigma_copy: [u16; MAX_DELTA + 1] = [0u16; MAX_DELTA + 1];
    let mut x_sigma_p: [u16; MAX_DELTA + 1] = [0u16; MAX_DELTA + 1];

    sigma[0] = 1;
    x_sigma_p[1] = 1;

    for mu in 0u16..(2 * delta as u16) {
        sigma_copy[..delta].copy_from_slice(&sigma[..delta]);
        deg_sigma_copy = deg_sigma;

        let dd = gf_mul(d, gf_inverse(d_p));
        let upper = (mu + 1).min(delta as u16);
        for i in 1..=upper {
            sigma[i as usize] ^= gf_mul(dd, x_sigma_p[i as usize]);
        }

        let deg_x = mu.wrapping_sub(pp);
        let deg_x_sig_p = deg_x.wrapping_add(deg_sigma_p);

        // mask1 = 0xffff if d != 0
        let mask1 = 0u16.wrapping_sub(0u16.wrapping_sub(d) >> 15);
        // mask2 = 0xffff if deg_x_sig_p > deg_sigma
        let mask2 = 0u16.wrapping_sub(deg_sigma.wrapping_sub(deg_x_sig_p) >> 15);
        let mask12 = mask1 & mask2;

        deg_sigma ^= mask12 & (deg_x_sig_p ^ deg_sigma);

        if mu == (2 * delta as u16 - 1) {
            break;
        }

        pp ^= mask12 & (mu ^ pp);
        d_p ^= mask12 & (d ^ d_p);
        for i in (1..=(delta as u16)).rev() {
            x_sigma_p[i as usize] =
                (mask12 & sigma_copy[(i - 1) as usize]) ^ (!mask12 & x_sigma_p[(i - 1) as usize]);
        }
        deg_sigma_p ^= mask12 & (deg_sigma_copy ^ deg_sigma_p);
        d = syndromes[(mu + 1) as usize];
        for i in 1..=upper {
            d ^= gf_mul(sigma[i as usize], syndromes[(mu + 1 - i) as usize]);
        }
    }
    deg_sigma
}

/// Chien search: find error positions by evaluating sigma at all field elements.
/// Sets error[i]=1 if alpha^i is a root of sigma(X) (i.e., position i has an error).
fn compute_roots(error: &mut [u8], sigma: &[u16], n1: usize) {
    for i in 0..n1 {
        // Evaluate sigma at alpha^{-i} (the root for error at position i).
        // alpha^{-0} = 1 = GF_EXP[0], alpha^{-i} = alpha^{255-i} = GF_EXP[255-i] for i>0.
        let eval = if i == 0 { GF_EXP[0] } else { GF_EXP[255 - i] };
        let mut val = sigma[0];
        let mut xp: u16 = 1;
        for &s in &sigma[1..] {
            xp = gf_mul(xp, eval);
            val ^= gf_mul(s, xp);
        }
        if val == 0 {
            error[i] = 1;
        }
    }
}

/// Compute the error-evaluator polynomial z(X) used in Forney's algorithm.
fn compute_z_poly(z: &mut [u16], sigma: &[u16], degree: u16, syndromes: &[u16], delta: usize) {
    z[0] = 1;
    for i in 1..=(delta) {
        let mask = 0u16.wrapping_sub((i as u16).wrapping_sub(degree).wrapping_sub(1) >> 15);
        z[i] = mask & sigma[i];
    }
    z[1] ^= syndromes[0];
    for i in 2..=(delta) {
        let mask = 0u16.wrapping_sub((i as u16).wrapping_sub(degree).wrapping_sub(1) >> 15);
        z[i] ^= mask & syndromes[i - 1];
        for j in 1..i {
            z[i] ^= mask & gf_mul(sigma[j], syndromes[i - j - 1]);
        }
    }
}

/// Forney algorithm: compute error values at known error positions.
/// Given error-locator and error-evaluator polynomials, compute the magnitude
/// of the error at each position.
fn compute_error_values(ev: &mut [u16], z: &[u16], error: &[u8], n1: usize, delta: usize) {
    let mut delta_counter: u16 = 0;
    let mut beta_j: [u16; MAX_DELTA] = [0u16; MAX_DELTA];
    let mut e_j: [u16; MAX_DELTA] = [0u16; MAX_DELTA];

    // Collect beta_j = alpha^i for each error position i.
    for i in 0..n1 {
        let mask1 = 0u16.wrapping_sub(0u16.wrapping_sub(error[i] as u16) >> 15);
        let mut found: u16 = 0;
        for j in 0..delta {
            let diff = (j as i32) ^ (delta_counter as i32);
            let mask2 = !(((-diff) >> 31) as u16);
            beta_j[j] = beta_j[j].wrapping_add(mask1 & mask2 & GF_EXP[i]);
            found = found.wrapping_add(mask1 & mask2 & 1);
        }
        delta_counter = delta_counter.wrapping_add(found);
    }
    let delta_real = delta_counter;

    // Compute error values via Forney algorithm.
    for i in 0..delta {
        let mut tmp1: u16 = 1;
        let mut tmp2: u16 = 1;
        let inv = gf_inverse(beta_j[i]);
        let mut inv_pow: u16 = 1;
        for j in 1..=delta {
            inv_pow = gf_mul(inv_pow, inv);
            tmp1 ^= gf_mul(inv_pow, z[j]);
        }
        for k in 1..delta {
            tmp2 = gf_mul(tmp2, 1 ^ gf_mul(inv, beta_j[(i + k) % delta]));
        }
        let mask1 = ((i as i32 - delta_real as i32) >> 15) as u16;
        e_j[i] = mask1 & gf_mul(tmp1, gf_inverse(tmp2));
    }

    // Place e_j values at error positions.
    let mut delta_counter: u16 = 0;
    for i in 0..n1 {
        let mask1 = 0u16.wrapping_sub(0u16.wrapping_sub(error[i] as u16) >> 15);
        let mut found: u16 = 0;
        for j in 0..delta {
            let diff = (j as i32) ^ (delta_counter as i32);
            let mask2 = !(((-diff) >> 31) as u16);
            ev[i] = ev[i].wrapping_add(mask1 & mask2 & e_j[j]);
            found = found.wrapping_add(mask1 & mask2 & 1);
        }
        delta_counter = delta_counter.wrapping_add(found);
    }
}

/// RS decoding: decode an n1-symbol codeword to extract the k-byte message.
/// Uses syndrome computation, Berlekamp-Massey, Chien search, and Forney algorithm.
pub fn rs_decode(cdw_k: &mut [u8], cdw_in: &[u8], n1: usize, k: usize, delta: usize) {
    let mut syndromes = [0u16; 2 * MAX_DELTA];
    let mut z: [u16; MAX_DELTA + 1] = [0u16; MAX_DELTA + 1];
    let mut ev: [u16; MAX_N1] = [0u16; MAX_N1];
    let mut sigma: [u16; 32] = [0u16; 32];
    let mut error: [u8; 256] = [0u8; 256];

    compute_syndromes(&mut syndromes, &cdw_in, n1, delta);
    let deg = compute_elp(&mut sigma, &syndromes, delta);
    compute_roots(&mut error, &sigma, n1);
    compute_z_poly(&mut z, &sigma, deg, &syndromes, delta);
    compute_error_values(&mut ev, &z, &error, n1, delta);

    let nm_k: usize = n1 - k;
    for i in nm_k..nm_k + k {
        cdw_k[i - nm_k] = cdw_in[i] ^ (ev[i] as u8);
    }
}

// ============================================================================
// Concatenated Code (Reed-Solomon + Reed-Muller)
// ============================================================================
// HQC uses a concatenated code: outer RS code followed by inner RM code.
// This provides both good distance properties and efficient decoding.

/// Encode k-byte message to n1*n2-bit codeword using concatenated code.
/// First applies RS(n1, k) encoding, then RM(1,7) encoding.
fn code_encode(
    out: &mut [u64],
    m: &[u8],
    n1: usize,
    n2: usize,
    k: usize,
    n1n2_size_64: usize,
    g_poly: &[u8]) {
    let mut cdw: [u8; MAX_N1] = [0u8; MAX_N1];
    rs_encode(&mut cdw, m, n1, k, g_poly);
    rm_encode(out, &cdw, n1, n2, n1n2_size_64);
}

/// Decode n1*n2-bit codeword to k-byte message using concatenated code.
/// First applies RM decoding, then RS decoding.
fn code_decode(out: &mut [u8], em: &[u64], n1: usize, n2: usize, k: usize, delta: usize) {
    let mut rs_cdw: [u8; MAX_N1] = [0u8; MAX_N1];
    rm_decode(&mut rs_cdw, em, n1, n2);
    rs_decode(out, &rs_cdw, n1, k, delta);
}

// ============================================================================
// HQC Public-Key Encryption (PKE) Scheme
// ============================================================================
// The PKE is the core cryptographic primitive. The KEM is built on top using FO transform.

/// Parse a PKE public key: extract h (random vector) and s (secret syndrome).
/// Public key format: [seed_ek (32 bytes)] || [s (n bits)].
/// h is derived from seed_ek via XOF.
fn ek_pke_parse(
    h: &mut [u64],
    s: &mut [u64],
    ek_pke: &[u8],
    n: usize,
    n_size_bytes: usize,
    n_size_64: usize,
) {
    let seed_ek = &ek_pke[..32];
    let mut ek_xof = xof_reader(seed_ek);
    vect_set_random(h, &mut ek_xof, n, n_size_bytes, n_size_64);
    bytes_to_vec(s, &ek_pke[32..32 + n_size_bytes]);
}

/// PKE key generation.
/// Generates secret key (x, y) and public key (h, s = yh + x).
/// x, y are sparse vectors with Hamming weight omega.
/// h is a random vector, s is the syndrome.
fn pke_keygen(
    seed_dk: &mut [u8],
    ek_pke: &mut [u8],
    seed_pke: &[u8],
    n: usize,
    n_size_bytes: usize,
    n_size_64: usize,
    omega: usize,
    n_mu: u64,
    threshold: u32,
)  {
    let kp = hash_i(seed_pke);
    let seed_ek = &kp[32..];
    let mut x: [u64; MAX_N64] = [0u64; MAX_N64];
    let mut y: [u64; MAX_N64] = [0u64; MAX_N64];

    seed_dk.copy_from_slice(&kp[..32]);

    let mut dk_xof = xof_reader(seed_dk);
    vect_sample_fixed_weight1(&mut y, &mut dk_xof, n, omega, n_mu, threshold);
    vect_sample_fixed_weight1(&mut x, &mut dk_xof, n, omega, n_mu, threshold);

    let mut ek_xof = xof_reader(seed_ek);
    let mut h: [u64; MAX_N64] = [0u64; MAX_N64];
    vect_set_random(&mut h, &mut ek_xof, n, n_size_bytes, n_size_64);

    let mut yh: [u64; MAX_N64] = [0u64; MAX_N64];
    vect_mul(&mut yh, &y, &h, n);

    let mut s: [u64; MAX_N64] = [0u64; MAX_N64];
    vect_add(&mut s, &yh, &x, n_size_64);

    let mut s_bytes: [u8; MAX_N_BYTES] = [0u8; MAX_N_BYTES];
    vec_to_bytes(&mut s_bytes, &s, n_size_bytes);

    append_bytes(&mut ek_pke[..32], seed_ek);
    append_bytes(&mut ek_pke[32..32 + n_size_bytes], &s_bytes[..n_size_bytes]);
}

/// PKE encryption: encrypt k-byte message m using public key (h, s).
/// Generates ciphertext (u, v) where:
///   u = r1 + r2*h  (masked ephemeral key)
///   v = Encode(m) + r2*s + e  (masked encoded message)
/// r1, r2, e are sparse random vectors with specified weights.
fn pke_encrypt(
    u: &mut [u64],
    v: &mut [u64],
    ek_pke: &[u8],
    m: &[u8],
    theta: &[u8],
    n: usize,
    n_size_bytes: usize,
    n_size_64: usize,
    n1: usize,
    n2: usize,
    k: usize,
    omega_r: usize,
    omega_e: usize,
    n1n2_size_64: usize,
    g_poly: &[u8],
) {
    assert!(omega_e == omega_r);

    let mut xof = xof_reader(theta);

    let mut h: [u64; MAX_N64] = [0u64; MAX_N64];
    let mut s: [u64; MAX_N64] = [0u64; MAX_N64];
    ek_pke_parse(&mut h, &mut s,ek_pke, n, n_size_bytes, n_size_64);

    let mut r1: [u64; MAX_N64] = [0u64; MAX_N64];
    let mut r2: [u64; MAX_N64] = [0u64; MAX_N64];
    let mut e: [u64; MAX_N64] = [0u64; MAX_N64];
    vect_sample_fixed_weight2(&mut r2, &mut xof, n,  omega_r);
    vect_sample_fixed_weight2(&mut e, &mut xof, n,  omega_r);
    vect_sample_fixed_weight2(&mut r1, &mut xof, n,  omega_r);

    let mut r2h = [0u64; MAX_N64];
    vect_mul(&mut r2h, &r2, &h, n);

    vect_add(u, &r1, &r2h, n_size_64);

    let mut em: [u64; MAX_N1N2_64] = [0u64; MAX_N1N2_64];
    code_encode(&mut em, m, n1, n2, k, n1n2_size_64, g_poly);

    let mut r2s = [0u64; MAX_N64];
    vect_mul(&mut r2s, &r2, &s, n);

    let mut tmp = [0u64; MAX_N64];
    vect_add(&mut tmp, &r2s, &e, n_size_64);
    vect_truncate(&mut tmp, n, n1 * n2);

    vect_add(v, &em, &tmp[..n1n2_size_64], n1n2_size_64);

}

/// PKE decryption: decrypt ciphertext (u, v) using secret key y.
/// Computes v - u*y and decodes to recover the message m.
/// Works because: v - u*y = Encode(m) + r2*s + e - (r1 + r2*h)*y
///                        = Encode(m) + r2*(s - h*y) + e - r1*y
///                        = Encode(m) + r2*x + e - r1*y  (since s = yh + x)
/// With small error, the decoder can recover m.
fn pke_decrypt(
    out: &mut [u8; 32],
    u: &[u64],
    v: &[u64],
    dk_pke: &[u8],
    n: usize,
    n1: usize,
    n2: usize,
    k: usize,
    delta: usize,
    omega: usize,
    n_mu: u64,
    threshold: u32,
    n1n2_size_64: usize
) {
    let mut dk_xof = xof_reader(dk_pke);

    let mut y = [0u64; MAX_N64];
    vect_sample_fixed_weight1(&mut y, &mut dk_xof, n, omega, n_mu, threshold);

    let mut uy = [0u64; MAX_N64];
    vect_mul(&mut uy, &y, u, n);

    let mut tmp = uy;
    vect_truncate(&mut tmp, n, n1 * n2);

    let mut tmp2 = [0u64; MAX_N1N2_64];
    vect_add(&mut tmp2, v, &tmp[..n1n2_size_64], n1n2_size_64);

    code_decode(out, &mut tmp2, n1, n2, k, delta);
}

// ============================================================================
// HQC Key Encapsulation Mechanism (KEM)
// ============================================================================
// The KEM uses the Fujisaki-Okamoto (FO) transform to convert the PKE into an IND-CCA2 secure KEM.

/// Generate HQC key pair from a seed.
///
/// # Arguments
/// * `p` - Parameter set (HQC-128, HQC-192, or HQC-256)
/// * `seed` - 32-byte random seed
/// * `pk_out` - Buffer for public key
/// * `sk_out` - Buffer for secret key
///
/// # Returns
/// Tuple of (public_key_size, secret_key_size)
pub fn generate_key(
    p: &HqcParams,
    seed: &[u8],
    pk_out: &mut [u8],
    sk_out: &mut [u8],
) -> (usize, usize) {
    let mut ctx = xof_reader(&seed);
    let mut seed_pke: [u8; 32] = [0u8; 32];
    let mut sigma: [u8; 32] = [0u8; 32];
    ctx.read(&mut seed_pke);
    ctx.read(&mut sigma[..p.security_bytes()]);

    let mut dk: [u8; 32] = [0u8; 32];

    pke_keygen(
        &mut dk,
        pk_out,
        &seed_pke,
        p.n,
        p.n_size_bytes(),
        p.n_size_64(),
        p.omega,
        p.n_mu,
        p.threshold,
    );

    // Copy out secret key: [ek_pke | dk_pke | sigma | seed]
    let mut t =&mut sk_out[..];
    t = append_bytes(t, &pk_out[..p.ek_size()]);
    t = append_bytes(t, &dk);
    t = append_bytes(t, &sigma[..p.security_bytes()]);
    _ = append_bytes(t, &seed);

    (p.ek_size(), p.ek_size() + 32 /*dk_pke*/ + p.security_bytes() + seed.len())
}

/// NIST-compatible key generation using an RNG.
pub fn nist_generate_key<R: rand_core::RngCore>(
    param: &HqcParams,
    pk_out: &mut [u8],
    sk_out: &mut [u8],
    rng: &mut R,
) -> (usize, usize) {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    generate_key(param, &seed, pk_out, sk_out)
}

/// KEM encapsulation: generate a shared secret and ciphertext.
///
/// Uses the FO transform:
/// 1. Hash public key: hash_ek = H(pk)
/// 2. Derive K, theta from seed: (K || theta) = G(hash_ek || m || salt)
/// 3. Encrypt m: ct = PKE.Encrypt(pk, m; theta)
/// 4. Output (K, ct)
///
/// # Arguments
/// * `p` - Parameter set
/// * `seed` - Random seed: [m (security_bytes)] || [salt (16 bytes)]
/// * `public_key` - Recipient's public key
/// * `shared_secret` - Output buffer for 32-byte shared secret
/// * `ciphertext` - Output buffer for ciphertext
///
/// # Returns
/// Tuple of (shared_secret_size, ciphertext_size)
pub fn encaps(
    p: &HqcParams, seed: &[u8], public_key: &[u8], shared_secret: &mut [u8], ciphertext: &mut [u8]
) -> (usize, usize) {
    let (m, r) = seed.split_at(p.security_bytes());
    let (salt, _) = r.split_at(SALT_SIZE);

    let hash_ek = hash_h(public_key);
    let k_theta = hash_g(&hash_ek, &m, &salt);

    let mut u : [u64; MAX_N64] = [0u64; MAX_N64];
    let mut v : [u64; MAX_N1N2_64] = [0u64; MAX_N1N2_64];

    pke_encrypt(
        &mut u, &mut v,
        public_key,
        &m,
        &k_theta[SHARED_SECRET_SIZE..],
        p.n,
        p.n_size_bytes(),
        p.n_size_64(),
        p.n1,
        p.n2,
        p.k,
        p.omega_r,
        p.omega_e,
        p.n1n2_size_64(),
        p.g_poly,
    );

    let mut out = &mut ciphertext[..];
    out = append_vec_bytes(out, &u, p.n_size_bytes());
    out = append_vec_bytes(out, &v, p.n1n2_size_bytes());
    append_bytes(out, salt);

    let mut u_bytes: [u8; MAX_N64] = [0u8; MAX_N64];
    let mut v_bytes: [u8; MAX_N1N2_64] = [0u8; MAX_N1N2_64];
    vec_to_bytes_into(&u, &mut u_bytes);
    vec_to_bytes_into(&v, &mut v_bytes);

    shared_secret.copy_from_slice(&k_theta[..SHARED_SECRET_SIZE]);
    (shared_secret.len(), p.n_size_bytes() + p.n1n2_size_bytes() + SALT_SIZE)
}

/// NIST-compatible encapsulation using an RNG.
pub fn nist_encaps<R: rand_core::RngCore>(
    param: &HqcParams,
    public_key: &[u8],
    shared_secret: &mut [u8],
    ciphertext: &mut [u8],
    rng: &mut R,
) {
    let mut seed = [0u8; SALT_SIZE + 32]; // salt + m
    rng.fill_bytes(&mut seed[..param.security_bytes()]);
    rng.fill_bytes(&mut seed[param.security_bytes()..param.security_bytes() + SALT_SIZE]);
    encaps(param, &seed, public_key, shared_secret, ciphertext);
}

/// KEM decapsulation: recover shared secret from ciphertext.
///
/// Uses FO transform with implicit rejection:
/// 1. Decrypt ciphertext: m' = PKE.Decrypt(sk, ct)
/// 2. Derive K', theta': (K' || theta') = G(H(pk) || m' || salt)
/// 3. Re-encrypt: ct' = PKE.Encrypt(pk, m'; theta')
/// 4. If ct == ct': return K' (success)
///    Else: return K_bar = J(H(pk) || sigma || ct || salt) (implicit rejection)
///
/// Constant-time: both paths are computed, result selected via masking.
pub fn decaps(p: &HqcParams, dk_kem: &[u8], ct: &[u8], shared_secret: &mut [u8]) {
    let ek_pke = &dk_kem[..p.ek_size()];
    let dk_pke = &dk_kem[p.ek_size()..p.ek_size() + 32];
    let sigma = &dk_kem[p.ek_size() + 32..p.ek_size() + 32 + 16];

    let u_bytes = &ct[..p.n_size_bytes()];
    let v_bytes = &ct[p.n_size_bytes()..p.n_size_bytes() + p.n1n2_size_bytes()];
    let salt = &ct[p.n_size_bytes() + p.n1n2_size_bytes()..p.n_size_bytes() + p.n1n2_size_bytes() + SALT_SIZE];

    let mut u: [u64; MAX_N64] = [0u64; MAX_N64];
    let mut v: [u64; MAX_N1N2_64] = [0u64; MAX_N1N2_64];

    bytes_to_vec(&mut u, u_bytes);
    bytes_to_vec(&mut v, v_bytes);

    let mut m_prime = [0u8; MAX_K];
    pke_decrypt(
        &mut m_prime,
        &u,
        &v,
        dk_pke,
        p.n,
        p.n1,
        p.n2,
        p.k,
        p.delta,
        p.omega,
        p.n_mu,
        p.threshold,
        p.n1n2_size_64(),
    );
    // Shadow m_prime, so that it's used correctly
    let m_prime = &m_prime[..p.k];

    let hash_ek = hash_h(ek_pke);
    let k_theta_prime = hash_g(&hash_ek, m_prime, salt);
    let k_prime = &k_theta_prime[..32];
    let theta_prime = &k_theta_prime[32..];
    let mut u : [u64; MAX_N64] = [0u64; MAX_N64];
    let mut v : [u64; MAX_N1N2_64] = [0u64; MAX_N1N2_64];

    pke_encrypt(
        &mut u, &mut v,
        ek_pke,
        m_prime,
        theta_prime,
        p.n,
        p.n_size_bytes(),
        p.n_size_64(),
        p.n1,
        p.n2,
        p.k,
        p.omega_r,
        p.omega_e,
        p.n1n2_size_64(),
        p.g_poly,
    );

    let mut u_prime_bytes: [u8; MAX_N_BYTES] = [0u8; MAX_N_BYTES];
    vec_to_bytes(&mut u_prime_bytes, &u, p.n_size_bytes());
    let mut v_prime_bytes: [u8; MAX_N1N2_BYTES] = [0u8; MAX_N1N2_BYTES];
    vec_to_bytes(&mut v_prime_bytes, &v, p.n1n2_size_bytes());
    let k_bar = hash_j(&hash_ek, sigma, u_bytes, v_bytes, salt);

    let mut result: u8 = 0;
    result |= vect_compare(u_bytes, &u_prime_bytes);
    result |= vect_compare(v_bytes, &v_prime_bytes);
    result = result.wrapping_sub(1); // 0xFF on match, 0x00 on mismatch

    for i in 0..SHARED_SECRET_SIZE {
        shared_secret[i] = (k_prime[i] & result) ^ (k_bar[i] & !result);
    }
}

/// NIST-compatible decapsulation.
pub fn nist_decaps(p: &HqcParams, dk_kem: &[u8], ct: &[u8], shared_secret: &mut [u8]) {
    let mut ss = [0u8; SHARED_SECRET_SIZE];
    decaps(p, dk_kem, ct, &mut ss);
    shared_secret.copy_from_slice(&ss);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hqc128_kem() {
        let p: HqcParams = HqcParams::new("HQC-128").expect("Invalid parameter set name");
        let seed_keygen: [u8; 32] = [0u8; 32];
        let seed_encaps: [u8; 16+16] = [0u8; 16+16];
        let mut ek: [u8; 2241] = [0u8; 2241];
        let mut dk: [u8; 2321] = [0u8; 2321];
        let mut ct: [u8; 4433] = [0u8; 4433];
        let mut ss1: [u8; 32] = [0u8; 32];
        let mut ss2: [u8; 32] = [0u8; 32];
        // Key generation
        generate_key(&p, &seed_keygen, &mut ek, &mut dk);
        // Encapsulation
        encaps(&p, &seed_encaps, &ek, &mut ss1, &mut ct);
        // Decapsulation
        decaps(&p, &dk, &ct, &mut ss2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_hqc192_kem() {
        let p: HqcParams = HqcParams::new("HQC-192").expect("Invalid parameter set name");
        let seed_keygen: [u8; 32] = [0u8; 32];
        let seed_encaps: [u8; 24+16] = [0u8; 24+16];
        let mut ek: [u8; 4514] = [0u8; 4514];
        let mut dk: [u8; 4602] = [0u8; 4602];
        let mut ct: [u8; 8978] = [0u8; 8978];
        let mut ss1: [u8; 32] = [0u8; 32];
        let mut ss2: [u8; 32] = [0u8; 32];

        // Key generation
        generate_key(&p, &seed_keygen, &mut ek, &mut dk);
        // Encapsulation
        encaps(&p, &seed_encaps, &ek, &mut ss1, &mut ct);
        // Decapsulation
        decaps(&p, &dk, &ct, &mut ss2);
        assert_eq!(ss1, ss2);
    }
    #[test]
    fn test_hqc256_kem() {
        let p: HqcParams = HqcParams::new("HQC-256").expect("Invalid parameter set name");
        let seed_keygen: [u8; 32] = [0u8; 32];
        let seed_encaps: [u8; 32+16] = [0u8; 32+16];
        let mut ek: [u8; 7237] = [0u8; 7237];
        let mut dk: [u8; 7333] = [0u8; 7333];
        let mut ct: [u8; 14_421] = [0u8; 14_421];
        let mut ss1: [u8; 32] = [0u8; 32];
        let mut ss2: [u8; 32] = [0u8; 32];

        // Key generation
        generate_key(&p, &seed_keygen, &mut ek, &mut dk);
        // Encapsulation
        encaps(&p, &seed_encaps, &ek, &mut ss1, &mut ct);
        // Decapsulation
        decaps(&p, &dk, &ct, &mut ss2);
        assert_eq!(ss1, ss2);
    }
}
