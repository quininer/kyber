use ::poly::{ self, Poly };
use ::params::{ N, D, Q, POLYBYTES };
use ::reduce::{ freeze, montgomery_reduce, barrett_reduce };


pub type PolyVec = [Poly; D];

pub fn compress(a: &PolyVec, r: &mut [u8]) {
    let mut p = 0;
    let mut t = [0; 8];
    for poly in a {
        for i in 0..(N / 8) {
            for j in 0..8 {
                t[j] = ((((u32::from(freeze(poly[8*i+j])) << 11) + Q as u32 / 2) / Q as u32) & 0x7ff) as u16;
            }

            r[p+11*i   ] = ( t[0] & 0xff) as u8;
            r[p+11*i+ 1] = ((t[0] >>  8) | ((t[1] & 0x1f) << 3)) as u8;
            r[p+11*i+ 2] = ((t[1] >>  5) | ((t[2] & 0x03) << 6)) as u8;
            r[p+11*i+ 3] = ((t[2] >>  2) & 0xff) as u8;
            r[p+11*i+ 4] = ((t[2] >> 10) | ((t[3] & 0x7f) << 1)) as u8;
            r[p+11*i+ 5] = ((t[3] >>  7) | ((t[4] & 0x0f) << 4)) as u8;
            r[p+11*i+ 6] = ((t[4] >>  4) | ((t[5] & 0x01) << 7)) as u8;
            r[p+11*i+ 7] = ((t[5] >>  1) & 0xff) as u8;
            r[p+11*i+ 8] = ((t[5] >>  9) | ((t[6] & 0x3f) << 2)) as u8;
            r[p+11*i+ 9] = ((t[6] >>  6) | ((t[7] & 0x07) << 5)) as u8;
            r[p+11*i+10] = ( t[7] >>  3) as u8;
        }
        p += 352;
    }
}


pub fn decompress(r: &mut PolyVec, a: &[u8]) {
    let mut p = 0;
    for poly in r {
        for i in 0..(N / 8) {
            poly[8*i  ] = ( (((u32::from(a[p+11*i   ])       | ((u32::from(a[p+11*i+ 1]) & 0x07) << 8)) * Q as u32) +1024) >> 11) as u16;
            poly[8*i+1] = (((((u32::from(a[p+11*i+ 1]) >> 3) | ((u32::from(a[p+11*i+ 2]) & 0x3f) << 5)) * Q as u32) +1024) >> 11) as u16;
            poly[8*i+2] = (((((u32::from(a[p+11*i+ 2]) >> 6) | ((u32::from(a[p+11*i+ 3]) & 0xff) << 2)  | ((u32::from(a[p+11*i+ 4]) & 0x01) << 10)) * Q as u32) + 1024) >> 11) as u16;
            poly[8*i+3] = (((((u32::from(a[p+11*i+ 4]) >> 1) | ((u32::from(a[p+11*i+ 5]) & 0x0f) << 7)) * Q as u32) + 1024) >> 11) as u16;
            poly[8*i+4] = (((((u32::from(a[p+11*i+ 5]) >> 4) | ((u32::from(a[p+11*i+ 6]) & 0x7f) << 4)) * Q as u32) + 1024) >> 11) as u16;
            poly[8*i+5] = (((((u32::from(a[p+11*i+ 6]) >> 7) | ((u32::from(a[p+11*i+ 7]) & 0xff) << 1)  | ((u32::from(a[p+11*i+ 8]) & 0x03) <<  9)) * Q as u32) + 1024) >> 11) as u16;
            poly[8*i+6] = (((((u32::from(a[p+11*i+ 8]) >> 2) | ((u32::from(a[p+11*i+ 9]) & 0x1f) << 6)) * Q as u32) + 1024) >> 11) as u16;
            poly[8*i+7] = (((((u32::from(a[p+11*i+ 9]) >> 5) | ((u32::from(a[p+11*i+10]) & 0xff) << 3)) * Q as u32) + 1024) >> 11) as u16;
        }
        p += 352;
    }
}

#[inline]
pub fn tobytes(a: &PolyVec, r: &mut [u8]) {
    for (i, poly) in a.iter().enumerate() {
        poly::tobytes(poly, &mut r[i * POLYBYTES..][..POLYBYTES]);
    }
}

#[inline]
pub fn frombytes(r: &mut PolyVec, a: &[u8]) {
    for (i ,poly) in r.iter_mut().enumerate() {
        poly::frombytes(poly, &a[i * POLYBYTES..][..POLYBYTES])
    }
}

#[inline]
pub fn ntt(r: &mut PolyVec) {
    for poly in r {
        poly::ntt(poly);
    }
}

#[inline]
pub fn invntt(r: &mut PolyVec) {
    for poly in r {
        poly::invntt(poly);
    }
}

#[inline]
pub fn pointwise_acc(r: &mut Poly, a: &PolyVec, b: &PolyVec) {
    for j in 0..N {
        let tmp = (0..D)
            .map(|i| {
                let t = montgomery_reduce(4613 * u32::from(b[i][j]));
                montgomery_reduce(u32::from(a[i][j]) * u32::from(t))
            })
            .sum();

        r[j] = barrett_reduce(tmp);
    }
}

#[inline]
pub fn add(r: &mut PolyVec, b: &PolyVec) {
    for i in 0..D {
        poly::add(&mut r[i], &b[i]);
    }
}
