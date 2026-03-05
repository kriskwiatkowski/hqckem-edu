use crate::common::consts::*;
use crate::common::hash::*;
use crate::common::utils::*;
use crate::field::*;
use crate::coders::*;
use crate::samplers::*;

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
pub(super) fn pke_keygen(
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
    sample_fixed_weight1(&mut y, &mut dk_xof, n, omega, n_mu, threshold);
    sample_fixed_weight1(&mut x, &mut dk_xof, n, omega, n_mu, threshold);

    let mut ek_xof = xof_reader(seed_ek);
    let mut h: [u64; MAX_N64] = [0u64; MAX_N64];
    vect_set_random(&mut h, &mut ek_xof, n, n_size_bytes, n_size_64);

    let mut yh: [u64; MAX_N64] = [0u64; MAX_N64];
    mul(&mut yh, &y, &h, n);

    let mut s: [u64; MAX_N64] = [0u64; MAX_N64];
    add(&mut s, &yh, &x, n_size_64);

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
pub(super) fn pke_encrypt(
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
    sample_fixed_weight2(&mut r2, &mut xof, n,  omega_r);
    sample_fixed_weight2(&mut e, &mut xof, n,  omega_r);
    sample_fixed_weight2(&mut r1, &mut xof, n,  omega_r);

    let mut r2h = [0u64; MAX_N64];
    mul(&mut r2h, &r2, &h, n);

    add(u, &r1, &r2h, n_size_64);

    let mut em: [u64; MAX_N1N2_64] = [0u64; MAX_N1N2_64];
    code_encode(&mut em, m, n1, n2, k, n1n2_size_64, g_poly);

    let mut r2s = [0u64; MAX_N64];
    mul(&mut r2s, &r2, &s, n);

    let mut tmp = [0u64; MAX_N64];
    add(&mut tmp, &r2s, &e, n_size_64);
    truncate(&mut tmp, n, n1 * n2);

    add(v, &em, &tmp[..n1n2_size_64], n1n2_size_64);

}

/// PKE decryption: decrypt ciphertext (u, v) using secret key y.
/// Computes v - u*y and decodes to recover the message m.
/// Works because: v - u*y = Encode(m) + r2*s + e - (r1 + r2*h)*y
///                        = Encode(m) + r2*(s - h*y) + e - r1*y
///                        = Encode(m) + r2*x + e - r1*y  (since s = yh + x)
/// With small error, the decoder can recover m.
pub(super) fn pke_decrypt(
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
    sample_fixed_weight1(&mut y, &mut dk_xof, n, omega, n_mu, threshold);

    let mut uy = [0u64; MAX_N64];
    mul(&mut uy, &y, u, n);

    let mut tmp = uy;
    truncate(&mut tmp, n, n1 * n2);

    let mut tmp2 = [0u64; MAX_N1N2_64];
    add(&mut tmp2, v, &tmp[..n1n2_size_64], n1n2_size_64);

    code_decode(out, &mut tmp2, n1, n2, k, delta);
}
