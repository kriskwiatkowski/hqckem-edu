// ============================================================================
// Maximum Parameter Bounds
// ============================================================================
// These define buffer sizes for the most demanding parameter set (HQC-256)

/// Maximum n in 64-bit words (HQC-256: n=57637 → ⌈57637/64⌉ = 901)
pub(crate) const MAX_N64: usize = 901;
/// Maximum n1 (HQC-256: n1=90)
pub(crate) const MAX_N1: usize = 90;
/// Maximum n1*n2 in 64-bit words (HQC-256: n1*n2=57600 → ⌈57600/64⌉ = 900)
pub(crate) const MAX_N1N2_64: usize = 900;
/// Maximum n1*n2 in bytes (HQC-256: n1*n2=57600 → ⌈57600/8⌉ = 7200)
pub(crate) const MAX_N1N2_BYTES: usize = 7200;
/// Maximum Hamming weight omega_r or omega_e (HQC-256: 149)
pub(crate) const MAX_OMEGA: usize = 149;
/// Maximum n in bytes (HQC-256: n=57637 → ⌈57637/8⌉ = 7205)
pub(crate) const MAX_N_BYTES: usize = 7205;
/// Maximum delta (Reed-Solomon error correction capability) (HQC-256: 29)
pub(crate) const MAX_DELTA: usize = 29;
/// Maximum k (message size in bytes) (HQC-256: 32)
pub(crate) const MAX_K: usize = 32;
/// Salt size for KEM encapsulation/decapsulation (16 bytes)
pub(crate) const SALT_SIZE : usize = 16usize;
/// Shared secret size for all parameter sets (32 bytes)
pub(crate) const SHARED_SECRET_SIZE: usize = 32;

