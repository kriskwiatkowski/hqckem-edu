//! Galois Field arithmetic utilities for cryptographic operations
//!
//! This module provides low-level Galois Field GF(256) operations used internally
//! by the Reed-Solomon and Reed-Muller error correction codes.

pub(crate) mod gf;
pub(crate) mod vector;

// Re-export
pub(crate) use gf::{
    GF_EXP,
    gf_mul,
    gf_inverse
};

pub(crate) use vector::{
    add,
    mul,
    truncate,
    vect_set_random,
    compare,
};
