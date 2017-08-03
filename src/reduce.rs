use ::params::Q;

const QINV: u32 = 7679; // -inverse_mod(q,2^18)
const RLOG: u32 = 18;


pub fn montgomery_reduce(mut a: u32) -> u16 {
    let mut u = a.wrapping_mul(QINV);
    u &= (1 << RLOG) - 1;
    u *= Q as u32;
    a += u;
    (a >> RLOG) as u16
}


pub fn barrett_reduce(a: u16) -> u16 {
    let mut u = a >> 13;
    u *= Q as u16;
    a - u
}

pub fn freeze(x: u16) -> u16 {
    let r = barrett_reduce(x);

    let m = r.wrapping_sub(Q as u16);
    let mut c = m as i16;
    c >>= 15;
    let c = c as u16;
    m ^ ((r ^ m) & c)
}
