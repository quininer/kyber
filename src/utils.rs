macro_rules! shake128 {
    ( $output:expr; $( $input:expr ),* ) => {
        let mut shake = ::tiny_keccak::Keccak::new_shake128();
        $(
            shake.update($input);
        )*
        shake.finalize($output);
    }
}


pub fn eq(a: &[u8], b: &[u8]) -> bool {
    use std::ops::BitOr;

    a.iter().zip(b)
        .map(|(&x, &y)| x ^ y)
        .fold(0, BitOr::bitor)
        .eq(&0)
}

pub fn select_mov(r: &mut [u8], x: &[u8], flag: bool) {
    let flag = ::std::u8::MIN.wrapping_sub((!flag) as u8);
    for (r, &x) in r.iter_mut().zip(x) {
        *r ^= flag & (x ^ *r);
    }
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
