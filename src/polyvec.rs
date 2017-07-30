use ::poly::{ self, Poly };
use ::params::{ N, D, Q, POLYBYTES };
use ::reduce::{ freeze, montgomery_reduce, barrett_reduce };


pub type PolyVec = [Poly; D];

pub fn compress(a: &PolyVec, r: &mut [u8]) {
    let mut p = 0;
    for poly in a {
        for i in 0..(N / 8) {
            let mut t = [0; 8];
            for j in 0..8 {
                t[j] = (((((freeze(poly[8*i+j]) as u32) << 11) + Q as u32 / 2) / Q as u32) & 0x7ff) as u16;
            }

            r[p+11*i+ 0] = ( t[0] & 0xff) as u8;
            r[p+11*i+ 1] = ((t[0] >>  8) | ((t[1] & 0x1f) << 3)) as u8;
            r[p+11*i+ 2] = ((t[1] >>  5) | ((t[2] & 0x03) << 6)) as u8;
            r[p+11*i+ 3] = ((t[2] >>  2) & 0xff) as u8;
            r[p+11*i+ 4] = ((t[2] >> 10) | ((t[3] & 0x7f) << 1)) as u8;
            r[p+11*i+ 5] = ((t[3] >>  7) | ((t[4] & 0x0f) << 4)) as u8;
            r[p+11*i+ 6] = ((t[4] >>  4) | ((t[5] & 0x01) << 7)) as u8;
            r[p+11*i+ 7] = ((t[5] >>  1) & 0xff) as u8;
            r[p+11*i+ 8] = ((t[5] >>  9) | ((t[6] & 0x3f) << 2)) as u8;
            r[p+11*i+ 9] = ((t[6] >>  6) | ((t[7] & 0x07) << 5)) as u8;
            r[p+11*i+10] = ((t[7] >>  3)) as u8;
        }
        p += 352;
    }
}


pub fn decompress(r: &mut PolyVec, a: &[u8]) {
    let mut p = 0;
    for poly in r {
        for i in 0..(N / 8) {
            poly[8*i+0] =  ((((a[p+11*i+ 0] as u16)       | (((a[p+11*i+ 1] as u16) & 0x07) << 8)) * Q as u16) +1024) >> 11;
            poly[8*i+1] = (((((a[p+11*i+ 1] as u16) >> 3) | (((a[p+11*i+ 2] as u16) & 0x3f) << 5)) * Q as u16) +1024) >> 11;
            poly[8*i+2] = (((((a[p+11*i+ 2] as u16) >> 6) | (((a[p+11*i+ 3] as u16) & 0xff) << 2)  | (((a[p+11*i+ 4] as u16) & 0x01) << 10)) * Q as u16) + 1024) >> 11;
            poly[8*i+3] = (((((a[p+11*i+ 4] as u16) >> 1) | (((a[p+11*i+ 5] as u16) & 0x0f) << 7)) * Q as u16) + 1024) >> 11;
            poly[8*i+4] = (((((a[p+11*i+ 5] as u16) >> 4) | (((a[p+11*i+ 6] as u16) & 0x7f) << 4)) * Q as u16) + 1024) >> 11;
            poly[8*i+5] = (((((a[p+11*i+ 6] as u16) >> 7) | (((a[p+11*i+ 7] as u16) & 0xff) << 1)  | (((a[p+11*i+ 8] as u16) & 0x03) <<  9)) * Q as u16) + 1024) >> 11;
            poly[8*i+6] = (((((a[p+11*i+ 8] as u16) >> 2) | (((a[p+11*i+ 9] as u16) & 0x1f) << 6)) * Q as u16) + 1024) >> 11;
            poly[8*i+7] = (((((a[p+11*i+ 9] as u16) >> 5) | (((a[p+11*i+10] as u16) & 0xff) << 3)) * Q as u16) + 1024) >> 11;
        }
        p += 352;
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
