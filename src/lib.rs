// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

//! HQC (Hamming Quasi-Cyclic) - Rust Implementation

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use sha3::{
    digest::{ExtendableOutput, FixedOutput, XofReader},
    Digest, Sha3_256, Sha3_512, Shake256,
};
/// Alpha powers: gf_exp[i] = alpha^i  (alpha^255 = 1, last two entries extend for gf_mul)
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

/// Discrete log: gf_log[a] = i such that alpha^i = a (gf_log[0] = 0 by convention)
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

const G_POLY_128: &[u8] = &[
    89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118,
    105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
];

const G_POLY_192: &[u8] = &[
    45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1,
    238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1,
];

const G_POLY_256: &[u8] = &[
    49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201,
    115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191,
    144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1,
];

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

#[inline(always)]
pub fn gf_inverse(a: u16) -> u16 {
    if a == 0 {
        return 0;
    }
    GF_EXP[(255 - GF_LOG[a as usize]) as usize]
}

const XOF_DOMAIN: u8 = 1;
const HASH_I_DOMAIN: u8 = 2;
const HASH_H_DOMAIN: u8 = 1;
const HASH_G_DOMAIN: u8 = 0;
const HASH_J_DOMAIN: u8 = 3;
// Salt size used for encaps/decaps
const SALT_SIZE : usize = 16usize;
// Shared secret size (32 bytes for all param sets)
const SHARED_SECRET_SIZE: usize = 32;

/// SHAKE256(seed || 0x01) – used for XOF-based key derivation.
pub fn xof_reader(seed: &[u8]) -> impl XofReader {
    use sha3::digest::Update;
    let mut h = Shake256::default();
    Update::update(&mut h, seed);
    Update::update(&mut h, &[XOF_DOMAIN]);
    h.finalize_xof()
}

/// SHA3-512(seed || 0x02) → 64 bytes (used in PKE keygen to split seed).
pub fn hash_i(seed: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(seed);
    h.update(&[HASH_I_DOMAIN]);
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize_fixed());
    out
}

/// SHA3-256(ek || 0x01) → 32 bytes.
pub fn hash_h(ek: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ek);
    h.update(&[HASH_H_DOMAIN]);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize_fixed());
    out
}

/// SHA3-512(hash_ek || m || salt || 0x00) → 64 bytes.
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

/// SHA3-256(hash_ek || sigma || u || v || salt || 0x03) → 32 bytes.
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

/// First `n_bytes` bytes of `v` (little-endian u64 words).
pub fn vec_to_bytes(v: &[u64], n_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n_bytes);
    for &w in v {
        out.extend_from_slice(&w.to_le_bytes());
        if out.len() >= n_bytes {
            break;
        }
    }
    out.truncate(n_bytes);
    out
}

#[inline(always)]
fn append_bytes<'a>(out: &'a mut [u8], src: &[u8]) -> &'a mut [u8] {
    let (dst, rest) = out.split_at_mut(src.len());
    dst.copy_from_slice(src);
    rest
}

/// Write first `out.len()` bytes of `v` (little-endian u64 words) into `out`.
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

#[inline(always)]
fn append_vec_bytes<'a>(out: &'a mut [u8], v: &[u64], n_bytes: usize) -> &'a mut [u8] {
    let (dst, rest) = out.split_at_mut(n_bytes);
    vec_to_bytes_into(v, dst);
    rest
}

/// Convert `bytes` to `n_size_64` little-endian u64 words (zero-padded).
pub fn bytes_to_vec(bytes: &[u8], n_size_64: usize) -> Vec<u64> {
    let mut v = vec![0u64; n_size_64];
    for i in 0..n_size_64 {
        let start = i * 8;
        let end = (start + 8).min(bytes.len());
        if start < bytes.len() {
            let mut word = [0u8; 8];
            word[..end - start].copy_from_slice(&bytes[start..end]);
            v[i] = u64::from_le_bytes(word);
        }
    }
    v
}

/// Barrett reduction of x mod n using precomputed mu = floor(2^32 / n).
fn barrett_reduce(x: u32, n: u32, n_mu: u64) -> u32 {
    let q = ((x as u64 * n_mu) >> 32) as u32;
    let mut r = x.wrapping_sub(q.wrapping_mul(n));
    let flag = ((r.wrapping_sub(n) >> 31) ^ 1) as u32;
    r = r.wrapping_sub(0u32.wrapping_sub(flag) & n);
    r
}

/// Constant-time comparison: 1 if v1 == v2, 0 otherwise.
fn compare_u32(v1: u32, v2: u32) -> u32 {
    1 ^ (((v1.wrapping_sub(v2)) | (v2.wrapping_sub(v1))) >> 31)
}

/// Fixed-weight sampling via rejection (keygen only).
pub fn vect_sample_fixed_weight1(
    xof: &mut dyn XofReader,
    n: usize,
    n_size_64: usize,
    omega: usize,
    n_mu: u64,
    threshold: u32,
) -> Vec<u64> {
    let mut support = vec![0u32; omega];
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
    let mut v = vec![0u64; n_size_64];
    for &pos in &support {
        v[(pos >> 6) as usize] |= 1u64 << (pos & 0x3f);
    }
    v
}

/// Fixed-weight sampling via permutation (encrypt only).
pub fn vect_sample_fixed_weight2(
    xof: &mut dyn XofReader,
    n: usize,
    n_size_64: usize,
    weight: usize,
) -> Vec<u64> {
    let mut rand_bytes = vec![0u8; 4 * weight];
    xof.read(&mut rand_bytes);
    let rand_u32: Vec<u32> = rand_bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();

    let mut support = vec![0u32; weight];
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

    let mut v = vec![0u64; n_size_64];
    for &pos in &support {
        v[(pos >> 6) as usize] |= 1u64 << (pos & 0x3f);
    }
    v
}

/// Fill a random n-bit vector from XOF (reads exactly n_size_bytes, masks last word).
pub fn vect_set_random(
    xof: &mut dyn XofReader,
    n: usize,
    n_size_bytes: usize,
    n_size_64: usize,
) -> Vec<u64> {
    let mut bytes = vec![0u8; n_size_bytes];
    xof.read(&mut bytes);
    let mut v = bytes_to_vec(&bytes, n_size_64);
    let n_mod = n % 64;
    if n_mod != 0 {
        v[n_size_64 - 1] &= (1u64 << n_mod) - 1;
    }
    v
}

/// XOR two vectors of `size` words.
pub fn vect_add(a: &[u64], b: &[u64], size: usize) -> Vec<u64> {
    (0..size).map(|i| a[i] ^ b[i]).collect()
}

/// Carry-less polynomial multiplication mod X^n − 1, schoolbook over GF(2).
pub fn vect_mul(a: &[u64], b: &[u64], n: usize, n_size_64: usize) -> Vec<u64> {
    let mut full = vec![0u64; 2 * n_size_64 + 1]; // +1 guard word
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
    let mut o = vec![0u64; n_size_64];
    for i in 0..n_size_64 {
        let r = full[i + n_size_64 - 1] >> n_mod;
        let carry = full[i + n_size_64] << (64 - n_mod);
        o[i] = full[i] ^ r ^ carry;
    }
    o[n_size_64 - 1] &= (1u64 << n_mod) - 1;
    o
}

/// Zero out bits beyond n1n2 in a vector of n_bits.
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

/// 0 if equal, 1 if not equal (constant-time byte comparison).
pub fn vect_compare(v1: &[u8], v2: &[u8]) -> u8 {
    let mut r: u16 = 0x0100;
    for (a, b) in v1.iter().zip(v2.iter()) {
        r |= (*a ^ *b) as u16;
    }
    ((r - 1) >> 8) as u8
}

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

/// Encode N1 bytes into N1*N2 bits via RM(1,7) with MULTIPLICITY=ceil(N2/128) copies.
pub fn rm_encode(msg: &[u8], n1: usize, n2: usize, n1n2_size_64: usize) -> Vec<u64> {
    let mult = (n2 + 127) / 128;
    let mut result = vec![0u64; n1n2_size_64];
    for i in 0..n1 {
        let cw = rm_encode_byte(msg[i]);
        for copy in 0..mult {
            let cw_idx = i * mult + copy;
            let wi = cw_idx * 2; // each 128-bit codeword = 2 u64 words
            result[wi] = (cw[0] as u64) | ((cw[1] as u64) << 32);
            result[wi + 1] = (cw[2] as u64) | ((cw[3] as u64) << 32);
        }
    }
    result
}

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

/// Decode N1*N2 bits back to N1 bytes via RM(1,7) with MULTIPLICITY copies.
pub fn rm_decode(cdw: &[u64], n1: usize, n2: usize) -> Vec<u8> {
    let mult = (n2 + 127) / 128;
    let mut msg = vec![0u8; n1];
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
    msg
}

/// Systematic RS encoding: output is [parity(n1-k) | msg(k)].
pub fn rs_encode(msg: &[u8], n1: usize, k: usize, g_poly: &[u8]) -> Vec<u8> {
    let nm_k = n1 - k; // = 2*delta = PARAM_G - 1
    let mut cdw = vec![0u8; n1];
    for i in 0..k {
        let gate = (msg[k - 1 - i] ^ cdw[nm_k - 1]) as u16;
        let tmp: Vec<u8> = g_poly
            .iter()
            .map(|&c| gf_mul(gate, c as u16) as u8)
            .collect();
        for kk in (1..nm_k).rev() {
            cdw[kk] = cdw[kk - 1] ^ tmp[kk];
        }
        cdw[0] = tmp[0];
    }
    cdw[nm_k..].copy_from_slice(msg);
    cdw
}

fn compute_syndromes(cdw: &[u8], n1: usize, delta: usize) -> Vec<u16> {
    let mut s = vec![0u16; 2 * delta];
    for i in 0..(2 * delta) {
        let mut si = cdw[0] as u16;
        for j in 1..n1 {
            let exp = ((i + 1) * j) % 255;
            si ^= gf_mul(cdw[j] as u16, GF_EXP[exp]);
        }
        s[i] = si;
    }
    s
}

/// Berlekamp-Massey; returns degree of error-locator polynomial.
fn compute_elp(sigma: &mut [u16], syndromes: &[u16], delta: usize) -> u16 {
    let mut deg_sigma: u16 = 0;
    let mut deg_sigma_p: u16 = 0;
    let mut deg_sigma_copy: u16;
    let mut sigma_copy = vec![0u16; delta + 1];
    let mut x_sigma_p = vec![0u16; delta + 1];
    x_sigma_p[1] = 1;
    let mut pp: u16 = u16::MAX; // represents -1
    let mut d_p: u16 = 1;
    let mut d: u16 = syndromes[0];

    sigma[0] = 1;

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

/// Chien search: set error[i]=1 if alpha^i is a root of sigma, for i in 0..n1.
fn compute_roots(error: &mut Vec<u8>, sigma: &[u16], n1: usize) {
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

fn compute_z_poly(sigma: &[u16], degree: u16, syndromes: &[u16], delta: usize) -> Vec<u16> {
    let mut z = vec![0u16; delta + 1];
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
    z
}

fn compute_error_values(z: &[u16], error: &[u8], n1: usize, delta: usize) -> Vec<u16> {
    let mut beta_j = vec![0u16; delta];
    let mut e_j = vec![0u16; delta];
    let mut delta_counter: u16 = 0;

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
    let mut ev = vec![0u16; n1];
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
    ev
}

/// RS decode: corrects errors in `cdw` and returns the k message bytes.
pub fn rs_decode(cdw_in: &[u8], n1: usize, k: usize, delta: usize) -> Vec<u8> {
    let mut cdw = cdw_in.to_vec();
    let fft_size = if delta <= 15 { 16usize } else { 32 };

    let syndromes = compute_syndromes(&cdw, n1, delta);
    let mut sigma = vec![0u16; fft_size];
    let deg = compute_elp(&mut sigma, &syndromes, delta);
    let mut error = vec![0u8; 256];
    compute_roots(&mut error, &sigma, n1);
    let z = compute_z_poly(&sigma, deg, &syndromes, delta);
    let ev = compute_error_values(&z, &error, n1, delta);
    for i in 0..n1 {
        cdw[i] ^= ev[i] as u8;
    }
    let nm_k = n1 - k; // = 2*delta
    cdw[nm_k..nm_k + k].to_vec()
}

fn code_encode(
    m: &[u8],
    n1: usize,
    n2: usize,
    k: usize,
    n1n2_size_64: usize,
    g_poly: &[u8],
) -> Vec<u64> {
    let rs_cdw = rs_encode(m, n1, k, g_poly);
    rm_encode(&rs_cdw, n1, n2, n1n2_size_64)
}

fn code_decode(em: &[u64], n1: usize, n2: usize, k: usize, delta: usize) -> Vec<u8> {
    let rs_cdw = rm_decode(em, n1, n2);
    rs_decode(&rs_cdw, n1, k, delta)
}

fn ek_pke_parse(
    ek_pke: &[u8],
    n: usize,
    n_size_bytes: usize,
    n_size_64: usize,
) -> (Vec<u64>, Vec<u64>) {
    let seed_ek = &ek_pke[..32];
    let mut ek_xof = xof_reader(seed_ek);
    let h = vect_set_random(&mut ek_xof, n, n_size_bytes, n_size_64);
    let s = bytes_to_vec(&ek_pke[32..32 + n_size_bytes], n_size_64);
    (h, s)
}

fn pke_keygen(
    seed_pke: &[u8],
    n: usize,
    n_size_bytes: usize,
    n_size_64: usize,
    omega: usize,
    n_mu: u64,
    threshold: u32,
) -> (Vec<u8>, Vec<u8>) {
    let kp = hash_i(seed_pke);
    let seed_dk = &kp[..32];
    let seed_ek = &kp[32..];

    let mut dk_xof = xof_reader(seed_dk);
    let y = vect_sample_fixed_weight1(&mut dk_xof, n, n_size_64, omega, n_mu, threshold);
    let x = vect_sample_fixed_weight1(&mut dk_xof, n, n_size_64, omega, n_mu, threshold);

    let mut ek_xof = xof_reader(seed_ek);
    let h = vect_set_random(&mut ek_xof, n, n_size_bytes, n_size_64);

    let yh = vect_mul(&y, &h, n, n_size_64);
    let s = vect_add(&yh, &x, n_size_64);

    let mut ek_pke = Vec::new();
    ek_pke.extend_from_slice(seed_ek);
    ek_pke.extend_from_slice(&vec_to_bytes(&s, n_size_bytes));

    (ek_pke, seed_dk.to_vec())
}

fn pke_encrypt(
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
) -> (Vec<u64>, Vec<u64>) {
    let mut xof = xof_reader(theta);
    let (h, s) = ek_pke_parse(ek_pke, n, n_size_bytes, n_size_64);

    let r2 = vect_sample_fixed_weight2(&mut xof, n, n_size_64, omega_r);
    let e = vect_sample_fixed_weight2(&mut xof, n, n_size_64, omega_e);
    let r1 = vect_sample_fixed_weight2(&mut xof, n, n_size_64, omega_r);

    let r2h = vect_mul(&r2, &h, n, n_size_64);
    let u = vect_add(&r1, &r2h, n_size_64);

    let em = code_encode(m, n1, n2, k, n1n2_size_64, g_poly);
    let r2s = vect_mul(&r2, &s, n, n_size_64);
    let mut tmp = vect_add(&r2s, &e, n_size_64);
    vect_truncate(&mut tmp, n, n1 * n2);
    let v = vect_add(&em, &tmp[..n1n2_size_64], n1n2_size_64);

    (u, v)
}

fn pke_decrypt(
    u: &[u64],
    v: &[u64],
    dk_pke: &[u8],
    n: usize,
    n_size_64: usize,
    n1: usize,
    n2: usize,
    k: usize,
    delta: usize,
    omega: usize,
    n_mu: u64,
    threshold: u32,
    n1n2_size_64: usize,
) -> Vec<u8> {
    let mut dk_xof = xof_reader(dk_pke);
    let y = vect_sample_fixed_weight1(&mut dk_xof, n, n_size_64, omega, n_mu, threshold);
    let uy = vect_mul(&y, u, n, n_size_64);
    let mut tmp = uy;
    vect_truncate(&mut tmp, n, n1 * n2);
    let tmp2 = vect_add(v, &tmp[..n1n2_size_64], n1n2_size_64);
    code_decode(&tmp2, n1, n2, k, delta)
}

/// All runtime parameters for one HQC parameter set.
pub struct HqcParams {
    /// Parameter set name (e.g., "HQC-128")
    pub name: &'static str,
    pub n: usize,
    pub n1: usize,
    pub n2: usize,
    pub k: usize,
    pub delta: usize,
    pub omega: usize,
    pub omega_r: usize,
    pub omega_e: usize,
    pub security_bits: usize,
    pub n_mu: u64,
    pub threshold: u32,
    pub g_poly: &'static [u8],
}

impl HqcParams {
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
    fn security_bytes(&self) -> usize {
        self.security_bits / 8
    }
    fn n_size_bytes(&self) -> usize {
        (self.n + 7) / 8
    }
    fn n_size_64(&self) -> usize {
        (self.n + 63) / 64
    }
    fn n1n2_size_bytes(&self) -> usize {
        (self.n1 * self.n2 + 7) / 8
    }
    fn n1n2_size_64(&self) -> usize {
        (self.n1 * self.n2 + 63) / 64
    }
    fn ek_size(&self) -> usize {
        self.n_size_bytes() + 32 /* seed */
    }
}

pub fn generate_key(
    p: &HqcParams,
    seed: &[u8],
    pk_out: &mut [u8],
    sk_out: &mut [u8],
) -> (usize, usize) {
    let mut ctx = xof_reader(&seed);
    let mut seed_pke = vec![0u8; 32];
    let mut sigma = vec![0u8; p.security_bytes()];
    ctx.read(&mut seed_pke);
    ctx.read(&mut sigma);

    let (ek_pke, dk_pke) = pke_keygen(
        &seed_pke,
        p.n,
        p.n_size_bytes(),
        p.n_size_64(),
        p.omega,
        p.n_mu,
        p.threshold,
    );

    // Copy out public key
    pk_out[..ek_pke.len()].copy_from_slice(&ek_pke);

    // Copy out secret key: [ek_pke | dk_pke | sigma | seed]
    let mut t =&mut sk_out[..];
    t = append_bytes(t, &ek_pke);
    t = append_bytes(t, &dk_pke);
    t = append_bytes(t, &sigma);
    _ = append_bytes(t, &seed);

    (ek_pke.len(), ek_pke.len() + dk_pke.len() + sigma.len() + seed.len())
}

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

// Seed is m(security_bytes)|salt(32b) padded to 64bytes
pub fn encaps(
    p: &HqcParams, seed: &[u8], public_key: &[u8], shared_secret: &mut [u8], ciphertext: &mut [u8]
) -> (usize, usize) {
    let (m, r) = seed.split_at(p.security_bytes());
    let (salt, _) = r.split_at(SALT_SIZE);

    let hash_ek = hash_h(public_key);
    let k_theta = hash_g(&hash_ek, &m, &salt);

    let (u, v) = pke_encrypt(
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

    let mut u_bytes = vec![0u8; p.n_size_bytes()];
    let mut v_bytes = vec![0u8; p.n1n2_size_bytes()];
    vec_to_bytes_into(&u, &mut u_bytes);
    vec_to_bytes_into(&v, &mut v_bytes);

    shared_secret.copy_from_slice(&k_theta[..SHARED_SECRET_SIZE]);
    (shared_secret.len(), p.n_size_bytes() + p.n1n2_size_bytes() + SALT_SIZE)
}

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

/// KEM decapsulation: returns 32-byte shared secret.
pub fn decaps(p: &HqcParams, dk_kem: &[u8], ct: &[u8], shared_secret: &mut [u8]) {
    let ek_pke = &dk_kem[..p.ek_size()];
    let dk_pke = &dk_kem[p.ek_size()..p.ek_size() + 32];
    let sigma = &dk_kem[p.ek_size() + 32..p.ek_size() + 32 + 16];

    let u_bytes = &ct[..p.n_size_bytes()];
    let v_bytes = &ct[p.n_size_bytes()..p.n_size_bytes() + p.n1n2_size_bytes()];
    let salt = &ct[p.n_size_bytes() + p.n1n2_size_bytes()..p.n_size_bytes() + p.n1n2_size_bytes() + SALT_SIZE];

    let u = bytes_to_vec(u_bytes, p.n_size_64());
    let v = bytes_to_vec(v_bytes, p.n1n2_size_64());

    let m_prime = pke_decrypt(
        &u,
        &v,
        dk_pke,
        p.n,
        p.n_size_64(),
        p.n1,
        p.n2,
        p.k,
        p.delta,
        p.omega,
        p.n_mu,
        p.threshold,
        p.n1n2_size_64(),
    );

    let hash_ek = hash_h(ek_pke);
    let k_theta_prime = hash_g(&hash_ek, &m_prime, salt);
    let k_prime = k_theta_prime[..32].to_vec();
    let theta_prime = &k_theta_prime[32..];

    let (u_prime, v_prime) = pke_encrypt(
        ek_pke,
        &m_prime,
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

    let u_prime_bytes = vec_to_bytes(&u_prime, p.n_size_bytes());
    let v_prime_bytes = vec_to_bytes(&v_prime, p.n1n2_size_bytes());
    let k_bar = hash_j(&hash_ek, sigma, u_bytes, v_bytes, salt);

    let mut result: u8 = 0;
    result |= vect_compare(u_bytes, &u_prime_bytes);
    result |= vect_compare(v_bytes, &v_prime_bytes);
    result = result.wrapping_sub(1); // 0xFF on match, 0x00 on mismatch

    for i in 0..SHARED_SECRET_SIZE {
        shared_secret[i] = (k_prime[i] & result) ^ (k_bar[i] & !result);
    }
}

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
        let mut ek = vec![0u8; 2241];
        let mut dk = vec![0u8; 2321];
        let mut ct = vec![0u8; 4433];
        let mut ss1= vec![0u8; 32];
        let mut ss2= vec![0u8; 32];

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
        let mut ek = vec![0u8; 4514];
        let mut dk = vec![0u8; 4602];
        let mut ct = vec![0u8; 8978];
        let mut ss1= vec![0u8; 32];
        let mut ss2= vec![0u8; 32];

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
        let mut ek = vec![0u8; 7237];
        let mut dk = vec![0u8; 7333];
        let mut ct = vec![0u8; 14_421];
        let mut ss1= vec![0u8; 32];
        let mut ss2= vec![0u8; 32];

        // Key generation
        generate_key(&p, &seed_keygen, &mut ek, &mut dk);
        // Encapsulation
        encaps(&p, &seed_encaps, &ek, &mut ss1, &mut ct);
        // Decapsulation
        decaps(&p, &dk, &ct, &mut ss2);
        assert_eq!(ss1, ss2);
    }
}
