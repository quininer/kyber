use byteorder::{ ByteOrder, LittleEndian };
use ::params::{ N, ETA, Q };
use ::poly::Poly;


pub fn cbd(r: &mut Poly, buf: &[u8; N]) {
    debug_assert_eq!(ETA, 4);

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
        b[3] = d >> 28;

        for j in 0..4 {
            r[4 * i + j] = (a[j] as u16) + (Q as u16) - (b[j] as u16);
        }
    }
}
