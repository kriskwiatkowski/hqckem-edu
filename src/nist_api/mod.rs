//! NIST PQC API Wrapper and KAT Testing (Test-Only Module)
//!
//! This module provides private NIST-compatible wrapper functions and KAT validation tests.
//! It is only compiled during testing (`#[cfg(test)]`) and requires the "std" feature for file I/O.
//!
//! The module is intentionally kept private (`pub(crate)`) as these wrappers are not part of the
//! public API. They exist solely to validate the implementation against official NIST KAT vectors.

/// Private NIST API wrapper functions that add RNG seeding to public KEM operations
pub(crate) mod nist_api;

/// Known Answer Test validation against official NIST PQC test vectors
/// Only compiled when both test and std features are enabled
#[cfg(all(test, feature = "std"))]
mod tests;
