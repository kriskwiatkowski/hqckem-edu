use crate::coders::*;
use crate::common::consts::*;

// ============================================================================
// Reed-Solomon Generator Polynomials
// ============================================================================
// Generator polynomials g(x) for RS codes used in the concatenated encoding scheme
// Each polynomial has degree 2*delta (where delta is the error correction capability)

/// Generator polynomial for HQC-128: degree 30, RS(46,16)
pub(crate) const G_POLY_128: &[u8] = &[
    89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118,
    105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
];

/// Generator polynomial for HQC-192: degree 32, RS(56,24)
pub(crate) const G_POLY_192: &[u8] = &[
    45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1,
    238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1,
];

/// Generator polynomial for HQC-256: degree 58, RS(90,32)
pub(crate) const G_POLY_256: &[u8] = &[
    49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201,
    115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191,
    144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1,
];

// ============================================================================
// Concatenated Code (Reed-Solomon + Reed-Muller)
// ============================================================================
// HQC uses a concatenated code: outer RS code followed by inner RM code.
// This provides both good distance properties and efficient decoding.

/// Encode k-byte message to n1*n2-bit codeword using concatenated code.
/// First applies RS(n1, k) encoding, then RM(1,7) encoding.
pub(crate) fn code_encode(
    out: &mut [u64],
    m: &[u8],
    n1: usize,
    n2: usize,
    k: usize,
    n1n2_size_64: usize,
    g_poly: &[u8]) {
    let mut cdw: [u8; MAX_N1] = [0u8; MAX_N1];
    rs_encode(&mut cdw, m, n1, k, g_poly);
    rm_encode(out, &cdw, n1, n2, n1n2_size_64);
}

/// Decode n1*n2-bit codeword to k-byte message using concatenated code.
/// First applies RM decoding, then RS decoding.
pub(crate) fn code_decode(out: &mut [u8], em: &[u64], n1: usize, n2: usize, k: usize, delta: usize) {
    let mut rs_cdw: [u8; MAX_N1] = [0u8; MAX_N1];
    rm_decode(&mut rs_cdw, em, n1, n2);
    rs_decode(out, &rs_cdw, n1, k, delta);
}
