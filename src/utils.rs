macro_rules! shake256 {
    ( $output:expr ; $( $input:expr ),* ) => {
        let mut shake = ::sha3::Shake256::default();
        $(
            ::digest::Input::process(&mut shake, $input);
        )*
        let mut reader = ::digest::ExtendableOutput::xof_result(shake);
        ::digest::XofReader::read(&mut reader, $output);
    }
}


pub fn eq(a: &[u8], b: &[u8]) -> bool {
    use core::ops::BitOr;

    a.iter().zip(b)
        .map(|(&x, &y)| x ^ y)
        .fold(0, BitOr::bitor)
        .eq(&0)
}

pub fn select_mov(r: &mut [u8], x: &[u8], flag: bool) {
    let flag = ::core::u8::MIN.wrapping_sub(!flag as u8);
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
