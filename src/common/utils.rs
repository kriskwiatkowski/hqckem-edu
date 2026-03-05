// ============================================================================
// Vector Conversion Utilities
// ============================================================================
// These functions convert between byte arrays and 64-bit word arrays,
// which are used to represent polynomial coefficients in GF(2)[X]

/// Convert a vector (array of u64 words) to bytes in little-endian order.
/// Writes the first `n` bytes from the vector into `out`.
pub(crate) fn vec_to_bytes(out: &mut [u8], vec: &[u64], n: usize) {
    for (dst, &w) in out[..n].chunks_mut(8).zip(vec.iter()) {
        let word = w.to_le_bytes();
        dst.copy_from_slice(&word[..dst.len()]);
    }
}

/// Helper: append bytes from `src` to `out`, returning the remaining slice.
/// Used for building serialized outputs (keys, ciphertexts).
#[inline(always)]
pub(crate) fn append_bytes<'a>(out: &'a mut [u8], src: &[u8]) -> &'a mut [u8] {
    let (dst, rest) = out.split_at_mut(src.len());
    dst.copy_from_slice(src);
    rest
}

/// Convert vector `v` (u64 words) to bytes, writing exactly `out.len()` bytes.
/// Used when the output buffer size is known in advance.
pub(crate) fn vec_to_bytes_into(v: &[u64], out: &mut [u8]) {
let mut written = 0;
    for &w in v {
        if written >= out.len() {
            break;
        }
        let word = w.to_le_bytes();
        let take = (out.len() - written).min(8);
        out[written..written + take].copy_from_slice(&word[..take]);
        written += take;
    }
}

/// Helper: append vector bytes to output buffer and return remaining slice.
#[inline(always)]
pub(crate) fn append_vec_bytes<'a>(out: &'a mut [u8], v: &[u64], n_bytes: usize) -> &'a mut [u8] {
    let (dst, rest) = out.split_at_mut(n_bytes);
    vec_to_bytes_into(v, dst);
    rest
}

/// Convert bytes to a vector of u64 words in little-endian order.
/// Each 8 bytes become one u64 word; zero-padded if bytes.len() < out.len() * 8.
pub(crate) fn bytes_to_vec(out: &mut [u64], bytes: &[u8]) {
    for i in 0..out.len() {
        let start = i * 8;
        let end = (start + 8).min(bytes.len());
        if start < bytes.len() {
            let mut word = [0u8; 8];
            word[..end - start].copy_from_slice(&bytes[start..end]);
            out[i] = u64::from_le_bytes(word);
        }
    }
}

/// Constant-time equality comparison: returns 1 if v1 == v2, else 0.
/// Avoids branching to prevent timing side-channels.
pub(crate) fn compare_u32(v1: u32, v2: u32) -> u32 {
    1 ^ (((v1.wrapping_sub(v2)) | (v2.wrapping_sub(v1))) >> 31)
}
