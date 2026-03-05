//! Coding and decoding functions for HQC-KEM.

pub(crate) mod common;
pub(crate) mod reed_muller;
pub(crate) mod reed_solomon;

// Re-export
pub(crate) use reed_muller::{
    rm_encode,
    rm_decode
};

pub(crate) use reed_solomon::{
    rs_encode,
    rs_decode
};

pub(crate) use common::{
    code_encode,
    code_decode
};