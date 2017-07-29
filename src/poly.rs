use sp800_185::CShake;
use ::params::{
    N, Q,
    SHAREDKEYBYTES,
    PSIS_BITREV_MONTGOMERY, OMEGAS_MONTGOMER,
    PSIS_INV_MONTGOMERY, OMEGAS_INV_BITREV_MONTGOMERY
};
use ::reduce::{ barrett_reduce, freeze };
use ::cbd::cbd;
use ::ntt::{ bitrev_vector, mul_coefficients, ntt as fft };


pub type Poly = [u16; N];

pub fn compress(poly: &Poly, buf: &mut [u8]) {
    let mut t = [0; 8];
    let mut k = 0;

    for i in (0..N).step_by(8) {
        for j in 0..8 {
            t[j] = ((((freeze(poly[i + j]) as u32) << 3) + Q as u32 / 2) / Q as u32) & 7;
        }

        macro_rules! compress {
            ( $i:expr; $( $op:tt $x:expr, $v:expr );*) => {
                buf[k + $i] = ( 0 $( | (t[$x] $op $v) )* ) as u8;
            }
        }

        compress!(0; >> 0, 0; << 1, 3; << 2, 6);
        compress!(1; >> 2, 2; << 3, 1; << 4, 4; << 5, 7);
        compress!(2; >> 5, 1; << 6, 2; << 7, 5);
        k += 3;
    }
}

pub fn decompress(poly: &mut Poly, buf: &[u8]) {
    const Q: u16 = ::params::Q as u16;
    let mut a = 0;
    for i in (0..N).step_by(8) {
        macro_rules! decompress {
            ( $i:expr ; $e:expr ) => {
                poly[i + $i] = (($e * Q) + 4) >> 3;
            };
            ( $i:expr ; $a:expr, $ax:expr ) => {
                decompress!($i; ((buf[a + $a] as u16) >> $ax));
            };
            ( $i:expr ; $a:expr, $ax:expr, $ay:expr ) => {
                decompress!($i; (((buf[a + $a] as u16) >> $ax) & $ay));
            };
            ( $i:expr ; $a:expr, $ax:expr; $b:expr, $bx:expr, $by:expr ) => {
                decompress!($i; (
                    ((buf[a + $a] as u16) >> $ax) |
                    (((buf[a + $b] as u16) << $bx) & $by)
                ));
            };
        }

        decompress!(0; 0, 0, 7);
        decompress!(1; 0, 3, 7);
        decompress!(2; 0, 6; 1, 2, 4);
        decompress!(3; 1, 1, 7);
        decompress!(4; 1, 4, 7);
        decompress!(5; 1, 7; 2, 1, 6);
        decompress!(6; 2, 2, 7);
        decompress!(7; 2, 5);
        a += 3;
    }
}


pub fn tobytes(poly: &Poly, buf: &mut [u8]) {
    let mut t = [0; 8];
    for i in 0..(N / 8) {
        for j in 0..8 {
            t[j] = freeze(poly[8 * i + j]);
        }

        buf[13*i   ] =  (t[0]        & 0xff)                    as u8;
        buf[13*i+ 1] = ((t[0] >>  8) | ((t[1] & 0x07) << 5))    as u8;
        buf[13*i+ 2] = ((t[1] >>  3) & 0xff)                    as u8;
        buf[13*i+ 3] = ((t[1] >> 11) | ((t[2] & 0x3f) << 2))    as u8;
        buf[13*i+ 4] = ((t[2] >>  6) | ((t[3] & 0x01) << 7))    as u8;
        buf[13*i+ 5] = ((t[3] >>  1) & 0xff)                    as u8;
        buf[13*i+ 6] = ((t[3] >>  9) | ((t[4] & 0x0f) << 4))    as u8;
        buf[13*i+ 7] = ((t[4] >>  4) & 0xff)                    as u8;
        buf[13*i+ 8] = ((t[4] >> 12) | ((t[5] & 0x7f) << 1))    as u8;
        buf[13*i+ 9] = ((t[5] >>  7) | ((t[6] & 0x03) << 6))    as u8;
        buf[13*i+10] = ((t[6] >>  2) & 0xff)                    as u8;
        buf[13*i+11] = ((t[6] >> 10) | ((t[7] & 0x1f) << 3))    as u8;
        buf[13*i+12] =  (t[7] >>  5)                            as u8;
    }
}

pub fn frombytes(poly: &mut Poly, buf: &[u8]) {
    for i in 0..(N / 8) {
        poly[8*i  ] =  (buf[13*i   ] as u16)       | ((buf[13*i+ 1] as u16 & 0x1f) << 8);
        poly[8*i+1] = ((buf[13*i+ 1] as u16) >> 5) | ((buf[13*i+ 2] as u16       ) << 3) | (((buf[13*i+ 3] as u16) & 0x03) << 11);
        poly[8*i+2] = ((buf[13*i+ 3] as u16) >> 2) | ((buf[13*i+ 4] as u16 & 0x7f) << 6);
        poly[8*i+3] = ((buf[13*i+ 4] as u16) >> 7) | ((buf[13*i+ 5] as u16       ) << 1) | (((buf[13*i+ 6] as u16) & 0x0f) <<  9);
        poly[8*i+4] = ((buf[13*i+ 6] as u16) >> 4) | ((buf[13*i+ 7] as u16       ) << 4) | (((buf[13*i+ 8] as u16) & 0x01) << 12);
        poly[8*i+5] = ((buf[13*i+ 8] as u16) >> 1) | ((buf[13*i+ 9] as u16 & 0x3f) << 7);
        poly[8*i+6] = ((buf[13*i+ 9] as u16) >> 6) | ((buf[13*i+10] as u16       ) << 2) | (((buf[13*i+11] as u16) & 0x07) << 10);
        poly[8*i+7] = ((buf[13*i+11] as u16) >> 3) | ((buf[13*i+12] as u16       ) << 5);
    }
}

pub fn getnoise(poly: &mut Poly, seed: &[u8], nonce: u8) {
    let mut buf = [0; N];

    let mut cshake = CShake::new_cshake128(&[], &[nonce, 0x00]);
    cshake.update(seed);
    cshake.finalize(&mut buf);

    cbd(poly, &buf);
}

pub fn ntt(poly: &mut Poly) {
    mul_coefficients(poly, &PSIS_BITREV_MONTGOMERY);
    fft(poly, &OMEGAS_MONTGOMER);
}

pub fn invntt(poly: &mut Poly) {
    bitrev_vector(poly);
    fft(poly, &OMEGAS_INV_BITREV_MONTGOMERY);
    mul_coefficients(poly, &PSIS_INV_MONTGOMERY);
}

pub fn add(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r[i] = barrett_reduce(a[i] + b[i]);
    }
}

pub fn sub(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r[i] = barrett_reduce(a[i] + 3 * Q as u16 - b[i]);
    }
}

pub fn frommsg(r: &mut Poly, msg: &[u8; SHAREDKEYBYTES]) {
    for (i, b) in msg.iter().enumerate() {
        for j in 0..8 {
            let mask = ::std::u16::MIN.wrapping_sub((b >> j) as u16 & 1);
            r[i] = mask & ((Q as u16 + 1) / 2);
        }
    }
}

pub fn tomsg(a: &Poly, msg: &mut [u8; SHAREDKEYBYTES]) {
    for (i, b) in msg.iter_mut().enumerate() {
        for j in 0..8 {
            let t = (((freeze(a[8 * i + j]) << 1) + Q as u16 / 2) / Q as u16) & 1;
            *b |= (t << j) as u8;
        }
    }
}
