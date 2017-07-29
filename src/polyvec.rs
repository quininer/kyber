use ::poly::{ self, Poly };
use ::params::{ N, D, Q, POLYBYTES };
use ::reduce::{ freeze, montgomery_reduce, barrett_reduce };


pub type PolyVec = [Poly; D];

pub fn compress(a: &PolyVec, r: &mut [u8]) {
    let mut pos = 0;
    for poly in a {
        for i in 0..(N / 8) {
            let mut t = [0; 8];
            for j in 0..8 {
                t[j] = (((((freeze(poly[8*i+j]) as u32) << 11) + Q as u32 / 2) / Q as u32) & 0x7ff) as u16;
            }

            macro_rules! compress {
                ( $i:expr ; $e:expr ) => {
                    r[pos + 11 * i + $i] = $e as u8;
                };
                ( $i:expr ; $a:expr, $ax:expr ) => {
                    compress!($i; (t[$a] >> $ax));
                };
                ( $i:expr ; $a:expr, $ax:expr; $b:expr, $bx:expr, $by:expr ) => {
                    compress!($i; ((t[$a] >> $ax) | ((t[$b] & $bx) << $by)));
                }
            }

            compress!( 0; 0,  0);
            compress!( 1; 0,  8; 1, 0x1f, 3);
            compress!( 2; 1,  5; 2, 0x03, 6);
            compress!( 3; 2,  2);
            compress!( 4; 2, 10; 3, 0x7f, 1);
            compress!( 5; 3,  7; 4, 0x0f, 4);
            compress!( 6; 4,  4; 5, 0x01, 7);
            compress!( 7; 5,  1);
            compress!( 8; 5,  9; 6, 0x3f, 2);
            compress!( 9; 6,  6; 7, 0x07, 5);
            compress!(10; 7,  3);
        }
        pos += 352;
    }
}


pub fn decompress(r: &mut PolyVec, a: &[u8]) {
    let mut pos = 0;
    for poly in r {
        for i in 0..(N / 8) {
            macro_rules! decompress {
                ( $i:expr; $e:expr ) => {
                    poly[pos + 8 * i + $i] = ((($e * Q as u32) + 1024) >> 11) as u16;
                };
                ( $i:expr ; $a:expr, $ax:expr ; $( $b:expr, $bx:expr, $by:expr );* ) => {
                    decompress!($i; (((a[11 * i + $a] as u32) >> $ax) $( | ((a[11 * i + $b] as u32 & $bx) << $by) )* ));
                };
            }

            decompress!(0; 0, 0;  1, 0x07, 8);
            decompress!(1; 1, 3;  2, 0x3f, 5);
            decompress!(2; 2, 6;  3, 0xff, 2; 4, 0x01, 10);
            decompress!(3; 4, 1;  5, 0x0f, 7);
            decompress!(4; 5, 4;  6, 0x7f, 4);
            decompress!(5; 6, 7;  7, 0xff, 1; 8, 0x03,  9);
            decompress!(6; 8, 2;  9, 0x1f, 6);
            decompress!(7; 9, 5; 10, 0xff, 3);
        }
        pos += 352;
    }
}

pub fn tobytes(a: &PolyVec, r: &mut [u8]) {
    for (i, poly) in a.iter().enumerate() {
        poly::tobytes(poly, &mut r[i * POLYBYTES..][..POLYBYTES]);
    }
}

pub fn frombytes(r: &mut PolyVec, a: &[u8]) {
    for (i ,poly) in r.iter_mut().enumerate() {
        poly::frombytes(poly, &a[i * POLYBYTES..][..POLYBYTES])
    }
}

pub fn ntt(r: &mut PolyVec) {
    for poly in r {
        poly::ntt(poly);
    }
}

pub fn invntt(r: &mut PolyVec) {
    for poly in r {
        poly::invntt(poly);
    }
}

pub fn pointwise_acc(r: &mut Poly, a: &PolyVec, b: &PolyVec) {
    for j in 0..N {
        let mut tmp = 0;

        for i in 0..D {
            let t = montgomery_reduce(4613 * b[i][j] as u32);
            tmp += montgomery_reduce(a[i][j] as u32 * t as u32);
        }

        r[j] = barrett_reduce(tmp);
    }
}

pub fn add(r: &mut PolyVec, a: &PolyVec, b: &PolyVec) {
    for i in 0..D {
        poly::add(&mut r[i], &a[i], &b[i]);
    }
}
