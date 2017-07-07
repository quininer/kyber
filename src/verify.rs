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

#[test]
fn test_verify_select_mov() {
    let a = [1, 2, 3];
    let b = [3, 2, 1];
    let mut r = [0, 0, 0];
    let x = [3, 3, 3];


    let flag = eq(&a, &a);
    select_mov(&mut r, &x, flag);
    assert_eq!(r, [0, 0, 0]);

    let flag = eq(&a, &b);
    select_mov(&mut r, &x, flag);
    assert_eq!(r, x);
}
