#[inline(never)]
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    use std::ops::BitOr;

    a.iter().zip(b)
        .map(|(&x, &y)| x ^ y)
        .fold(0, BitOr::bitor)
        .eq(&0)
}

fn select_u8(flag: u8, x: u8, y: u8) -> u8 {
    ((::std::u8::MAX ^ flag.wrapping_sub(1)) & x)
        | (flag.wrapping_sub(1) & y)
}

#[inline(never)]
pub fn select_mov(r: &mut [u8], x: &[u8], flag: bool) {
    for (r, &x) in r.iter_mut().zip(x) {
        *r = select_u8(flag as u8, *r, x);
    }
}

#[test]
fn test_select_u8() {
    assert_eq!(select_u8(0, 1, 2), 2);
    assert_eq!(select_u8(1, 3, 4), 3);
}
