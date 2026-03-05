use crate::common::*;
use crate::common::consts::*;

// ============================================================================
// Vector Operations Over GF(2)[X]
// ============================================================================
// Vectors represent polynomials in GF(2)[X] / (X^n - 1), the quasi-cyclic ring.
// Operations are performed on bit vectors stored as arrays of u64 words.

/// Fill a vector with n uniformly random bits from XOF.
/// The vector is stored as u64 words; the last word is masked to exactly n bits.
pub(crate) fn vect_set_random(
    out: &mut [u64],
    xof: &mut dyn Xof,
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
pub(crate) fn add(out: &mut [u64], a: &[u64], b: &[u64], size: usize) {
    for i in 0..size {
        out[i] = a[i] ^ b[i];
    }
}

/// Polynomial multiplication in GF(2)[X] / (X^n - 1).
/// Computes out = a * b mod (X^n - 1) using schoolbook multiplication with carry-less arithmetic.
/// This is the core operation in the HQC cryptosystem (computing s = yh + x and v = r2*s + e).
pub(crate) fn mul(out: &mut [u64], a: &[u64], b: &[u64], n: usize) {
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
pub(crate) fn truncate(v: &mut [u64], n_bits: usize, n1n2: usize) {
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
pub(crate) fn compare(v1: &[u8], v2: &[u8]) -> u8 {
    let mut r: u16 = 0x0100;
    for (a, b) in v1.iter().zip(v2.iter()) {
        r |= (*a ^ *b) as u16;
    }
    ((r - 1) >> 8) as u8
}
