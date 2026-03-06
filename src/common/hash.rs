use sha3::{
    digest::{ExtendableOutput, FixedOutput},
    Digest, Sha3_256, Sha3_512, Shake256,
};

use crate::common::Xof;

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

// ============================================================================
// Cryptographic Hash and XOF Functions
// ============================================================================
// Per HQC specification, these functions are used for key derivation and
// random sampling, with domain separation to ensure independent outputs

/// XOF (Extendable Output Function): SHAKE256(seed || 0x01)
/// Used for expanding seeds into random vectors and fixed-weight samples.
pub(crate) fn xof_reader(seed: &[u8]) -> impl Xof {
    use sha3::digest::Update;
    let mut h = Shake256::default();
    Update::update(&mut h, seed);
    Update::update(&mut h, &[XOF_DOMAIN]);
    h.finalize_xof()
}

/// Hash_I: SHA3-512(seed || 0x02) → 64 bytes
/// Used in PKE key generation to split a seed into seed_dk (32 bytes) and seed_ek (32 bytes).
pub(crate) fn hash_i(seed: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(seed);
    h.update(&[HASH_I_DOMAIN]);
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize_fixed());
    out
}

/// Hash_H: SHA3-256(ek || 0x01) → 32 bytes
/// Computes a hash of the public key for use in KEM encapsulation/decapsulation.
pub(crate) fn hash_h(ek: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ek);
    h.update(&[HASH_H_DOMAIN]);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize_fixed());
    out
}

/// Hash_G: SHA3-512(hash_ek || m || salt || 0x00) → 64 bytes
/// Derives shared secret K (first 32 bytes) and randomness theta (last 32 bytes) in KEM.
pub(crate) fn hash_g(hash_ek: &[u8], m: &[u8], salt: &[u8]) -> [u8; 64] {
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
pub(crate) fn hash_j(hash_ek: &[u8], sigma: &[u8], u: &[u8], v: &[u8], salt: &[u8]) -> [u8; 32] {
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
