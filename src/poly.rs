use ::params::{
    N, Q, ETA,
    SYMBYTES,
    POLYBYTES, POLYCOMPRESSEDBYTES
};
use ::reduce::{ barrett_reduce, freeze };
use ::cbd::cbd;
pub use ::ntt::{ ntt, invntt };


pub type Poly = [u16; N];

pub fn compress(poly: &Poly, buf: &mut [u8; POLYCOMPRESSEDBYTES]) {
    let mut t = [0; 8];
    let mut k = 0;

    for i in (0..N).step_by(8) {
        for j in 0..8 {
            t[j] = (((u32::from(freeze(poly[i + j])) << 3) + Q as u32 / 2) / Q as u32) & 7;
        }

        buf[k]   = ( t[0]       | (t[1] << 3) | (t[2] << 6)) as u8;
        buf[k+1] = ((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) as u8;
        buf[k+2] = ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) as u8;
        k += 3;
    }
}

pub fn decompress(poly: &mut Poly, buf: &[u8; POLYCOMPRESSEDBYTES]) {
    let mut a = 0;
    for i in (0..N).step_by(8) {
        poly[i  ] =  (((u16::from(buf[a  ])       & 7) * Q as u16) + 4) >> 3;
        poly[i+1] = ((((u16::from(buf[a  ]) >> 3) & 7) * Q as u16) + 4) >> 3;
        poly[i+2] = ((((u16::from(buf[a  ]) >> 6) | ((u16::from(buf[a+1]) << 2) & 4)) * Q as u16) + 4) >> 3;
        poly[i+3] = ((((u16::from(buf[a+1]) >> 1) & 7) * Q as u16) + 4) >> 3;
        poly[i+4] = ((((u16::from(buf[a+1]) >> 4) & 7) * Q as u16) + 4) >> 3;
        poly[i+5] = ((((u16::from(buf[a+1]) >> 7) | ((u16::from(buf[a+2]) << 1) & 6)) * Q as u16) + 4) >> 3;
        poly[i+6] = ((((u16::from(buf[a+2]) >> 2) & 7) * Q as u16) + 4) >> 3;
        poly[i+7] = (( (u16::from(buf[a+2]) >> 5)      * Q as u16) + 4) >> 3;
        a += 3;
    }
}


pub fn tobytes(poly: &Poly, buf: &mut [u8; POLYBYTES]) {
    let mut t = [0; 8];
    for i in 0..(N / 8) {
        for j in 0..8 {
            t[j] = freeze(poly[8 * i + j]);
        }

        buf[13*i   ] = ( t[0]        & 0xff) as u8;
        buf[13*i+ 1] = ((t[0] >>  8) | ((t[1] & 0x07) << 5)) as u8;
        buf[13*i+ 2] = ((t[1] >>  3) & 0xff) as u8;
        buf[13*i+ 3] = ((t[1] >> 11) | ((t[2] & 0x3f) << 2)) as u8;
        buf[13*i+ 4] = ((t[2] >>  6) | ((t[3] & 0x01) << 7)) as u8;
        buf[13*i+ 5] = ((t[3] >>  1) & 0xff) as u8;
        buf[13*i+ 6] = ((t[3] >>  9) | ((t[4] & 0x0f) << 4)) as u8;
        buf[13*i+ 7] = ((t[4] >>  4) & 0xff) as u8;
        buf[13*i+ 8] = ((t[4] >> 12) | ((t[5] & 0x7f) << 1)) as u8;
        buf[13*i+ 9] = ((t[5] >>  7) | ((t[6] & 0x03) << 6)) as u8;
        buf[13*i+10] = ((t[6] >>  2) & 0xff) as u8;
        buf[13*i+11] = ((t[6] >> 10) | ((t[7] & 0x1f) << 3)) as u8;
        buf[13*i+12] = ( t[7] >>  5) as u8;
    }
}

pub fn frombytes(poly: &mut Poly, buf: &[u8; POLYBYTES]) {
    for i in 0..(N / 8) {
        poly[8*i  ] =  u16::from(buf[13*i   ])       | ((u16::from(buf[13*i+ 1]) & 0x1f) << 8);
        poly[8*i+1] = (u16::from(buf[13*i+ 1]) >> 5) | ((u16::from(buf[13*i+ 2])       ) << 3) | ((u16::from(buf[13*i+ 3]) & 0x03) << 11);
        poly[8*i+2] = (u16::from(buf[13*i+ 3]) >> 2) | ((u16::from(buf[13*i+ 4]) & 0x7f) << 6);
        poly[8*i+3] = (u16::from(buf[13*i+ 4]) >> 7) | ((u16::from(buf[13*i+ 5])       ) << 1) | ((u16::from(buf[13*i+ 6]) & 0x0f) <<  9);
        poly[8*i+4] = (u16::from(buf[13*i+ 6]) >> 4) | ((u16::from(buf[13*i+ 7])       ) << 4) | ((u16::from(buf[13*i+ 8]) & 0x01) << 12);
        poly[8*i+5] = (u16::from(buf[13*i+ 8]) >> 1) | ((u16::from(buf[13*i+ 9]) & 0x3f) << 7);
        poly[8*i+6] = (u16::from(buf[13*i+ 9]) >> 6) | ((u16::from(buf[13*i+10])       ) << 2) | ((u16::from(buf[13*i+11]) & 0x07) << 10);
        poly[8*i+7] = (u16::from(buf[13*i+11]) >> 3) | ((u16::from(buf[13*i+12])       ) << 5);
    }
}

pub fn getnoise(poly: &mut Poly, seed: &[u8; SYMBYTES], nonce: u8) {
    let mut buf = [0; ETA * N / 4];

    shake256!(&mut buf; &seed[..SYMBYTES], &[nonce]);

    cbd(poly, &buf);
}

#[inline]
pub fn add(r: &mut Poly, b: &Poly) {
    for i in 0..N {
        r[i] = barrett_reduce(r[i] + b[i]);
    }
}

#[inline]
pub fn sub(r: &mut Poly, b: &Poly) {
    for i in 0..N {
        r[i] = barrett_reduce(r[i] + 3 * Q as u16 - b[i]);
    }
}

#[inline]
pub fn frommsg(r: &mut Poly, msg: &[u8; SYMBYTES]) {
    for (i, b) in msg.iter().enumerate() {
        for j in 0..8 {
            let mask = ::core::u16::MIN.wrapping_sub(u16::from(b >> j) & 1);
            r[8 * i + j] = mask & ((Q as u16 + 1) / 2);
        }
    }
}

#[inline]
pub fn tomsg(a: &Poly, msg: &mut [u8; SYMBYTES]) {
    for (i, b) in msg.iter_mut().enumerate() {
        *b = 0;
        for j in 0..8 {
            let t = (freeze(a[8 * i + j]) << 1).wrapping_add(Q as u16 / 2).wrapping_div(Q as u16) & 1;
            *b |= (t << j) as u8;
        }
    }
}
