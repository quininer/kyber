use byteorder::{ ByteOrder, LittleEndian };
use ::params::{ N, K, Q };
use ::poly::Poly;


pub fn cbd(r: &mut Poly, buf: &[u8]) {
    debug_assert_eq!(K, 4);

    let mut x = [0; 8];

    for i in 0..(N / 4) {
        let t = LittleEndian::read_u32(&buf[4 * i..]);
        let d = (0..4)
            .map(|j| (t >> j) & 0x11111111)
            .sum();

        LittleEndian::write_u32(&mut x, d);

        for j in 0..4 {
            r[4 * i + j] = (x[j] as u16) + (Q as u16) - (x[4 + j] as u16);
        }
    }
}
