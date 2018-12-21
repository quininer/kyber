use ::params::{ N, Q, ZETAS, OMEGAS_INV_BITREV_MONTGOMERY, PSIS_INV_MONTGOMERY };
use ::reduce::{ montgomery_reduce, barrett_reduce };


pub fn ntt(p: &mut [u16; N]) {
    let mut k = 1;
    for level in (0..8).rev() {
        for start in (0..N).step_by(2 * (1 << level)) {
            let zeta = ZETAS[k];
            k += 1;

            for j in start..(start + (1 << level)) {
                let t = montgomery_reduce(u32::from(zeta) * u32::from(p[j + (1 << level)]));

                p[j + (1 << level)] = barrett_reduce(p[j] + 4 * (Q as u16) - t);
                p[j] =
                    if level & 1 != 0 { p[j] + t }
                    else { barrett_reduce(p[j] + t) };
            }
        }
    }
}

pub fn invntt(a: &mut [u16; N]) {
    for level in 0..8 {
        for start in 0..(1 << level) {
            for (jt, j) in (start..(N - 1)).step_by(2 * (1 << level)).enumerate() {
                let w = OMEGAS_INV_BITREV_MONTGOMERY[jt];
                let tmp = a[j];

                a[j] =
                    if level & 1 != 0 { barrett_reduce(tmp + a[j + (1 << level)]) }
                    else { tmp + a[j + (1 << level)] };

                let t = u32::from(w) * (u32::from(tmp) + 4 * (Q as u32) - u32::from(a[j + (1 << level)]));
                a[j + (1 << level)] = montgomery_reduce(t);
            }
        }
    }

    for j in 0..N {
        a[j] = montgomery_reduce(u32::from(a[j]) * u32::from(PSIS_INV_MONTGOMERY[j]));
    }
}
