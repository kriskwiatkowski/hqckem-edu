// ============================================================================
// Reed-Muller Code RM(1,7)
// ============================================================================
// The Reed-Muller code RM(1,7) encodes 8 bits into a 128-bit codeword.
// It can correct up to 32 bit errors. Multiple copies are concatenated for longer messages.

/// Encode a single byte into a 128-bit RM(1,7) codeword (returned as 4 u32 words).
/// Uses a fast bitwise implementation of first-order Reed-Muller encoding.
fn rm_encode_byte(m: u8) -> [u32; 4] {
    let m = m as u32;
    let bit = |n: u32| -> u32 { 0u32.wrapping_sub((m >> n) & 1) };
    let mut fw = bit(7);
    fw ^= bit(0) & 0xaaaaaaaa;
    fw ^= bit(1) & 0xcccccccc;
    fw ^= bit(2) & 0xf0f0f0f0;
    fw ^= bit(3) & 0xff00ff00;
    fw ^= bit(4) & 0xffff0000;
    let mut w = [0u32;
4];
    w[0] = fw;
    fw ^= bit(5);
    w[1] = fw;
    fw ^= bit(6);
    w[3] = fw;
    fw ^= bit(5);
    w[2] = fw;
    w
}

/// Encode n1 bytes (message) into n1*n2 bits using RM(1,7).
/// Each byte is encoded into a 128-bit RM codeword, repeated `mult` times
/// where mult = ⌈n2/128⌉ to fill the n2-bit space allocated per byte.
pub fn rm_encode(out: &mut [u64], msg: &[u8], n1: usize, n2: usize, _n1n2_size_64: usize) {
    let mult = (n2 + 127) / 128;
    for i in 0..n1 {
        let cw = rm_encode_byte(msg[i]);
        for copy in 0..mult {
            let cw_idx = i * mult + copy;
            let wi = cw_idx * 2; // each 128-bit codeword = 2 u64 words
            out[wi] = (cw[0] as u64) | ((cw[1] as u64) << 32);
            out[wi + 1] = (cw[2] as u64) | ((cw[3] as u64) << 32);
        }
    }
}


/// Find the peak (maximum absolute value) in Hadamard-transformed data.
/// Returns an 8-bit value encoding position and sign (used to decode one byte).
fn find_peaks(t: &[i16; 128]) -> u8 {
    let mut best_abs: i32 = 0;
    let mut best_val: i32 = 0;
    let mut best_pos: i32 = 0;
    for i in 0..128 {
        let v = t[i] as i32;
        let abs = if v >= 0 { v } else { -v };
        if abs > best_abs {
            best_abs = abs;
            best_val = v;
            best_pos = i as i32;
        }
    }
    (best_pos | (128 * (best_val > 0) as i32)) as u8
}

/// Fast Hadamard Transform on 128 elements.
/// Used in Reed-Muller decoding for majority-logic decision.
fn hadamard(data: &mut [i16; 128]) {
    let mut tmp = [0i16; 128];
    for _ in 0..7 {
        for i in 0..64 {
            let a = data[2 * i];
            let b = data[2 * i + 1];
            tmp[i] = a + b;
            tmp[i + 64] = a - b;
        }
        *data = tmp;
    }
}

/// Decode n1*n2 bits back to n1 bytes using RM(1,7).
/// Sums multiple copies of each codeword, applies Hadamard transform, and finds peaks.
pub fn rm_decode(msg: &mut [u8], cdw: &[u64], n1: usize, n2: usize)  {
    let mult = (n2 + 127) / 128;
    for i in 0..n1 {
        let mut expanded = [0i16; 128];
        for copy in 0..mult {
            let cw_idx = i * mult + copy;
            let wi = cw_idx * 2;
            let w0 = cdw[wi];
            let w1 = cdw[wi + 1];
            let parts = [
                (w0 & 0xffffffff) as u32,
                (w0 >> 32) as u32,
                (w1 & 0xffffffff) as u32,
                (w1 >> 32) as u32,
            ];
            for part in 0..4 {
                for bit in 0..32 {
                    expanded[part * 32 + bit] += ((parts[part] >> bit) & 1) as i16;
                }
            }
        }
        hadamard(&mut expanded);
        expanded[0] -= 64 * mult as i16;
        msg[i] = find_peaks(&expanded);
    }
}
