//! HQC-KEM Core Implementation
//!
//! This module contains the public HQC Key Encapsulation Mechanism (KEM) implementation.
//! It provides the primary cryptographic operations: key generation, encapsulation, and decapsulation.
//!
//! The module uses `pub mod` to declare the kem submodule, then re-exports the public API
//! items using `pub use` to flatten the namespace and provide a cleaner interface at the crate root.

/// Core HQC-KEM cryptographic implementation
pub mod kem;

// Sibling modules
mod pke;

/// Re-export public HQC-KEM types and functions to simplify user imports
/// Users can write: `use hqc::{HqcParams, keygen, encaps, decaps}` instead of
/// `use hqc::hqckem::kem::{HqcParams, keygen, encaps, decaps}`
pub use kem::{
    HqcParams,
    decaps,
    encaps,
    keygen,
};
