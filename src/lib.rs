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

#![cfg_attr(not(feature = "std"), no_std)]

pub mod hqckem;

pub(crate) mod coders;
pub(crate) mod common;
pub(crate) mod field;
pub(crate) mod samplers;

pub use hqckem::kem::{
    HqcParams,
    keygen,
    encaps,
    decaps,
};

#[cfg(test)]
mod nist_api;
