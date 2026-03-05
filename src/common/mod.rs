//! Utility functions

pub(crate) mod consts;
pub(crate) mod hash;
pub(crate) mod barrett;
pub(crate) use sha3::digest::XofReader as Xof;
pub(crate) mod utils;

// Re-export
pub(crate) use hash::{
    xof_reader,
    hash_h,
    hash_g,
    hash_j
};

pub(crate) use barrett::{
    barrett_reduce
};

pub(crate) use utils::{
    append_bytes,
    append_vec_bytes,
    bytes_to_vec,
    compare_u32,
    vec_to_bytes_into,
    vec_to_bytes,
};