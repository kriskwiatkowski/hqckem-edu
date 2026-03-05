use crate::common::*;
use crate::common::consts::*;

// ============================================================================
// Fixed-Weight Vector Sampling
// ============================================================================
// HQC requires sampling sparse binary vectors with fixed Hamming weight.
// Two algorithms are used:
// - sample_fixed_weight1: rejection sampling (for key generation)
// - sample_fixed_weight2: Fisher-Yates shuffle (for encryption)

/// Sample a random binary vector of length n with exact Hamming weight omega.
/// Uses rejection sampling to ensure uniform distribution over all valid vectors.
/// Used in key generation (sampling x, y with weight omega).
pub(crate) fn sample_fixed_weight1(
    out: &mut [u64],
    xof: &mut dyn Xof,
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
pub(crate) fn sample_fixed_weight2(
    out: &mut [u64],
    xof: &mut dyn Xof,
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
