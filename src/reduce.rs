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
    //static const uint16_t sinv = 8; // trunc((2^16/q))
    let mut u = a >> 13; //((uint32_t) a * sinv) >> 16;
    u *= Q as u16;
    a - u
}

pub fn freeze(x: u16) -> u16 {
    let r = barrett_reduce(x);

    let m = r.wrapping_sub(Q as u16);
    let c = m >> 15;
    m ^ ((r ^ m) & c)
}
