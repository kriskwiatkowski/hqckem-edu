use crate::common::consts::*;
use crate::field::*;

// ============================================================================
// Reed-Solomon Code RS(n1, k, 2*delta)
// ============================================================================
// Systematic Reed-Solomon code over GF(256) used as the outer code.
// Can correct up to delta symbol errors.

/// Compute syndromes for RS decoding.
/// Syndrome s_i = sum_j cdw[j] * alpha^{(i+1)*j} for i=0..2*delta-1.
fn compute_syndromes(out: &mut [u16], cdw: &[u8], n1: usize, delta: usize)  {
    for i in 0..(2 * delta) {
        let mut si = cdw[0] as u16;
        for j in 1..n1 {
            let exp = ((i + 1) * j) % 255;
            si ^= gf_mul(cdw[j] as u16, GF_EXP[exp]);
        }
        out[i] = si;
    }
}

/// Berlekamp-Massey algorithm: compute the error-locator polynomial sigma(X).
/// Returns the degree of sigma. Uses constant-time operations to avoid timing leaks.
fn compute_elp(sigma: &mut [u16], syndromes: &[u16], delta: usize) -> u16 {
    let mut deg_sigma: u16 = 0;
    let mut deg_sigma_p: u16 = 0;
    let mut deg_sigma_copy: u16;
    let mut pp: u16 = u16::MAX; // represents -1
    let mut d_p: u16 = 1;
    let mut d: u16 = syndromes[0];
    let mut sigma_copy: [u16; MAX_DELTA + 1] = [0u16; MAX_DELTA + 1];
    let mut x_sigma_p: [u16; MAX_DELTA + 1] = [0u16; MAX_DELTA + 1];

    sigma[0] = 1;
    x_sigma_p[1] = 1;

    for mu in 0u16..(2 * delta as u16) {
        sigma_copy[..delta].copy_from_slice(&sigma[..delta]);
        deg_sigma_copy = deg_sigma;

        let dd = gf_mul(d, gf_inverse(d_p));
        let upper = (mu + 1).min(delta as u16);
        for i in 1..=upper {
            sigma[i as usize] ^= gf_mul(dd, x_sigma_p[i as usize]);
        }

        let deg_x = mu.wrapping_sub(pp);
        let deg_x_sig_p = deg_x.wrapping_add(deg_sigma_p);

        // mask1 = 0xffff if d != 0
        let mask1 = 0u16.wrapping_sub(0u16.wrapping_sub(d) >> 15);
        // mask2 = 0xffff if deg_x_sig_p > deg_sigma
        let mask2 = 0u16.wrapping_sub(deg_sigma.wrapping_sub(deg_x_sig_p) >> 15);
        let mask12 = mask1 & mask2;

        deg_sigma ^= mask12 & (deg_x_sig_p ^ deg_sigma);

        if mu == (2 * delta as u16 - 1) {
            break;
        }

        pp ^= mask12 & (mu ^ pp);
        d_p ^= mask12 & (d ^ d_p);
        for i in (1..=(delta as u16)).rev() {
            x_sigma_p[i as usize] =
                (mask12 & sigma_copy[(i - 1) as usize]) ^ (!mask12 & x_sigma_p[(i - 1) as usize]);
        }
        deg_sigma_p ^= mask12 & (deg_sigma_copy ^ deg_sigma_p);
        d = syndromes[(mu + 1) as usize];
        for i in 1..=upper {
            d ^= gf_mul(sigma[i as usize], syndromes[(mu + 1 - i) as usize]);
        }
    }
    deg_sigma
}

/// Chien search: find error positions by evaluating sigma at all field elements.
/// Sets error[i]=1 if alpha^i is a root of sigma(X) (i.e., position i has an error).
fn compute_roots(error: &mut [u8], sigma: &[u16], n1: usize) {
    for i in 0..n1 {
        // Evaluate sigma at alpha^{-i} (the root for error at position i).
        // alpha^{-0} = 1 = GF_EXP[0], alpha^{-i} = alpha^{255-i} = GF_EXP[255-i] for i>0.
        let eval = if i == 0 { GF_EXP[0] } else { GF_EXP[255 - i] };
        let mut val = sigma[0];
        let mut xp: u16 = 1;
        for &s in &sigma[1..] {
            xp = gf_mul(xp, eval);
            val ^= gf_mul(s, xp);
        }
        if val == 0 {
            error[i] = 1;
        }
    }
}

/// Compute the error-evaluator polynomial z(X) used in Forney's algorithm.
fn compute_z_poly(z: &mut [u16], sigma: &[u16], degree: u16, syndromes: &[u16], delta: usize) {
    z[0] = 1;
    for i in 1..=(delta) {
        let mask = 0u16.wrapping_sub((i as u16).wrapping_sub(degree).wrapping_sub(1) >> 15);
        z[i] = mask & sigma[i];
    }
    z[1] ^= syndromes[0];
    for i in 2..=(delta) {
        let mask = 0u16.wrapping_sub((i as u16).wrapping_sub(degree).wrapping_sub(1) >> 15);
        z[i] ^= mask & syndromes[i - 1];
        for j in 1..i {
            z[i] ^= mask & gf_mul(sigma[j], syndromes[i - j - 1]);
        }
    }
}

/// Forney algorithm: compute error values at known error positions.
/// Given error-locator and error-evaluator polynomials, compute the magnitude
/// of the error at each position.
fn compute_error_values(ev: &mut [u16], z: &[u16], error: &[u8], n1: usize, delta: usize) {
    let mut delta_counter: u16 = 0;
    let mut beta_j: [u16; MAX_DELTA] = [0u16; MAX_DELTA];
    let mut e_j: [u16; MAX_DELTA] = [0u16; MAX_DELTA];

    // Collect beta_j = alpha^i for each error position i.
    for i in 0..n1 {
        let mask1 = 0u16.wrapping_sub(0u16.wrapping_sub(error[i] as u16) >> 15);
        let mut found: u16 = 0;
        for j in 0..delta {
            let diff = (j as i32) ^ (delta_counter as i32);
            let mask2 = !(((-diff) >> 31) as u16);
            beta_j[j] = beta_j[j].wrapping_add(mask1 & mask2 & GF_EXP[i]);
            found = found.wrapping_add(mask1 & mask2 & 1);
        }
        delta_counter = delta_counter.wrapping_add(found);
    }
    let delta_real = delta_counter;

    // Compute error values via Forney algorithm.
    for i in 0..delta {
        let mut tmp1: u16 = 1;
        let mut tmp2: u16 = 1;
        let inv = gf_inverse(beta_j[i]);
        let mut inv_pow: u16 = 1;
        for j in 1..=delta {
            inv_pow = gf_mul(inv_pow, inv);
            tmp1 ^= gf_mul(inv_pow, z[j]);
        }
        for k in 1..delta {
            tmp2 = gf_mul(tmp2, 1 ^ gf_mul(inv, beta_j[(i + k) % delta]));
        }
        let mask1 = ((i as i32 - delta_real as i32) >> 15) as u16;
        e_j[i] = mask1 & gf_mul(tmp1, gf_inverse(tmp2));
    }

    // Place e_j values at error positions.
    let mut delta_counter: u16 = 0;
    for i in 0..n1 {
        let mask1 = 0u16.wrapping_sub(0u16.wrapping_sub(error[i] as u16) >> 15);
        let mut found: u16 = 0;
        for j in 0..delta {
            let diff = (j as i32) ^ (delta_counter as i32);
            let mask2 = !(((-diff) >> 31) as u16);
            ev[i] = ev[i].wrapping_add(mask1 & mask2 & e_j[j]);
            found = found.wrapping_add(mask1 & mask2 & 1);
        }
        delta_counter = delta_counter.wrapping_add(found);
    }
}

/// RS decoding: decode an n1-symbol codeword to extract the k-byte message.
/// Uses syndrome computation, Berlekamp-Massey, Chien search, and Forney algorithm.
pub(crate) fn rs_decode(cdw_k: &mut [u8], cdw_in: &[u8], n1: usize, k: usize, delta: usize) {
    let mut syndromes = [0u16; 2 * MAX_DELTA];
    let mut z: [u16; MAX_DELTA + 1] = [0u16; MAX_DELTA + 1];
    let mut ev: [u16; MAX_N1] = [0u16; MAX_N1];
    let mut sigma: [u16; 32] = [0u16; 32];
    let mut error: [u8; 256] = [0u8; 256];

    compute_syndromes(&mut syndromes, &cdw_in, n1, delta);
    let deg = compute_elp(&mut sigma, &syndromes, delta);
    compute_roots(&mut error, &sigma, n1);
    compute_z_poly(&mut z, &sigma, deg, &syndromes, delta);
    compute_error_values(&mut ev, &z, &error, n1, delta);

    let nm_k: usize = n1 - k;
    for i in nm_k..nm_k + k {
        cdw_k[i - nm_k] = cdw_in[i] ^ (ev[i] as u8);
    }
}

/// Encode a k-byte message into an n1-symbol RS codeword in systematic form.
/// Output format: [parity symbols (n1-k)] || [message symbols (k)].
pub(crate) fn rs_encode(cdw: &mut [u8], msg: &[u8], n1: usize, k: usize, g_poly: &[u8]) {
    let nm_k: usize = n1 - k; // = 2*delta = PARAM_G - 1
    for i in 0..k {
        let gate = (msg[k - 1 - i] ^ cdw[nm_k - 1]) as u16;
        let mut tmp = [0u8; MAX_N1];
        for (j, &c) in g_poly.iter().enumerate() {
            tmp[j] = gf_mul(gate, c as u16) as u8;
        }
        for kk in (1..nm_k).rev() {
            cdw[kk] = cdw[kk - 1] ^ tmp[kk];
        }
        cdw[0] = tmp[0];
    }
    cdw[nm_k..n1].copy_from_slice(msg);
}

