// ============================================================================
// Barrett Reduction and Constant-Time Utilities
// ============================================================================

/// Barrett reduction: compute x mod n using precomputed μ = ⌊2^32 / n⌋.
/// More efficient than division for repeated modular reductions with fixed n.
pub(crate) fn barrett_reduce(x: u32, n: u32, n_mu: u64) -> u32 {
    let q = ((x as u64 * n_mu) >> 32) as u32;
    let mut r = x.wrapping_sub(q.wrapping_mul(n));
    let flag = ((r.wrapping_sub(n) >> 31) ^ 1) as u32;
    r = r.wrapping_sub(0u32.wrapping_sub(flag) & n);
    r
}
