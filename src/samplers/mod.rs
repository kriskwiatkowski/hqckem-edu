//! Galois Field arithmetic utilities for cryptographic operations
//!
//! This module provides low-level Galois Field GF(256) operations used internally
//! by the Reed-Solomon and Reed-Muller error correction codes.

pub(crate) mod fixed_weight;

pub(crate) use fixed_weight::{
    sample_fixed_weight1,
    sample_fixed_weight2
};