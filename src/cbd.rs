use byteorder::{ ByteOrder, LittleEndian };
use ::params::{ N, ETA, Q };
use ::poly::Poly;

const BUF_LEN: usize = ETA * N / 4;


#[cfg(feature = "kyber512")]
pub fn cbd(r: &mut Poly, buf: &[u8; BUF_LEN]) {
    let (mut a, mut b) = ([0; 4], [0; 4]);

    for i in 0..(N / 4) {
        let t = LittleEndian::read_uint(&buf[5 * i..], 5);
        let d = (0..5)
            .map(|j| (t >> j) & 0x08_4210_8421)
            .sum::<u64>();

        a[0] =  d & 0x1f;
        b[0] = (d >>  5) & 0x1f;
        a[1] = (d >> 10) & 0x1f;
        b[1] = (d >> 15) & 0x1f;
        a[2] = (d >> 20) & 0x1f;
        b[2] = (d >> 25) & 0x1f;
        a[3] = (d >> 30) & 0x1f;
        b[3] =  d >> 35;

        for j in 0..4 {
            r[4 * i + j] = (a[j] as u16) + (Q as u16) - (b[j] as u16);
        }
    }
}

#[cfg(feature = "kyber768")]
pub fn cbd(r: &mut Poly, buf: &[u8; BUF_LEN]) {
    let (mut a, mut b) = ([0; 4], [0; 4]);

    for i in 0..(N / 4) {
        let t = LittleEndian::read_u32(&buf[4 * i..]);
        let d = (0..4)
            .map(|j| (t >> j) & 0x1111_1111)
            .sum::<u32>();

        a[0] =  d & 0xf;
        b[0] = (d >>  4) & 0xf;
        a[1] = (d >>  8) & 0xf;
        b[1] = (d >> 12) & 0xf;
        a[2] = (d >> 16) & 0xf;
        b[2] = (d >> 20) & 0xf;
        a[3] = (d >> 24) & 0xf;
        b[3] =  d >> 28;

        for j in 0..4 {
            r[4 * i + j] = (a[j] as u16) + (Q as u16) - (b[j] as u16);
        }
    }
}

#[cfg(feature = "kyber1024")]
pub fn cbd(r: &mut Poly, buf: &[u8; BUF_LEN]) {
    let (mut a, mut b) = ([0; 4], [0; 4]);

    for i in 0..(N / 4) {
        let t = LittleEndian::read_u24(&buf[3 * i..]);
        let d = (0..3)
            .map(|j| (t >> j) & 0x249249)
            .sum::<u32>();

        a[0] =  d & 0x7;
        b[0] = (d >>  3) & 0x7;
        a[1] = (d >>  6) & 0x7;
        b[1] = (d >>  9) & 0x7;
        a[2] = (d >> 12) & 0x7;
        b[2] = (d >> 15) & 0x7;
        a[3] = (d >> 18) & 0x7;
        b[3] =  d >> 21;

        for j in 0..4 {
            r[4 * i + j] = (a[j] as u16) + (Q as u16) - (b[j] as u16);
        }
    }
}
