use rand::Rng;
use subtle::{ slices_equal, ConditionallyAssignable };
use ::params::{
    SYMBYTES,
    CIPHERTEXTBYTES, PUBLICKEYBYTES, SECRETKEYBYTES,
    INDCPA_BYTES,
    INDCPA_SECRETKEYBYTES, INDCPA_PUBLICKEYBYTES,
    POLYVECBYTES
};
use ::indcpa;


pub fn keypair<R: Rng>(rng: &mut R, pk: &mut [u8; PUBLICKEYBYTES], sk: &mut [u8; SECRETKEYBYTES]) {
    indcpa::keypair(rng, pk, array_mut_ref!(sk, 0, POLYVECBYTES));
    array_mut_ref!(sk, INDCPA_SECRETKEYBYTES, INDCPA_PUBLICKEYBYTES).clone_from(pk);

    sha3_256!(&mut sk[SECRETKEYBYTES - 2 * SYMBYTES..][..SYMBYTES]; &pk[..PUBLICKEYBYTES]);

    rng.fill_bytes(&mut sk[SECRETKEYBYTES - SYMBYTES..][..SYMBYTES]);
}

pub fn enc<R: Rng>(rng: &mut R, c: &mut [u8; CIPHERTEXTBYTES], k: &mut [u8; SYMBYTES], pk: &[u8; PUBLICKEYBYTES]) {
    let mut buf = [0; SYMBYTES];
    let mut buf2 = [0; SYMBYTES];
    let mut kr = [0; SYMBYTES + SYMBYTES];

    rng.fill_bytes(&mut buf);
    sha3_256!(&mut buf; &buf);

    sha3_256!(&mut buf2; &pk[..PUBLICKEYBYTES]);
    sha3_512!(&mut kr; &buf, &buf2);

    indcpa::enc(array_mut_ref!(c, 0, INDCPA_BYTES), &buf, pk, array_ref!(&kr, SYMBYTES, SYMBYTES));

    sha3_256!(&mut kr[SYMBYTES..][..SYMBYTES]; c);
    sha3_256!(k; &kr);
}

pub fn dec(k: &mut [u8; SYMBYTES], c: &[u8; CIPHERTEXTBYTES], sk: &[u8; SECRETKEYBYTES]) -> bool {
    let mut cmp = [0; CIPHERTEXTBYTES];
    let mut buf = [0; SYMBYTES];
    let mut kr = [0; SYMBYTES + SYMBYTES];
    let pk = array_ref!(sk, INDCPA_SECRETKEYBYTES, INDCPA_PUBLICKEYBYTES);

    indcpa::dec(&mut buf, array_ref!(c, 0, INDCPA_BYTES), array_ref!(sk, 0, POLYVECBYTES));
    sha3_512!(&mut kr; &buf, &sk[SECRETKEYBYTES - SYMBYTES - SYMBYTES..][..SYMBYTES]);

    indcpa::enc(&mut cmp, &buf, pk, array_ref!(&kr, SYMBYTES, SYMBYTES));

    let flag = slices_equal(c, &cmp);

    sha3_256!(&mut kr[SYMBYTES..][..SYMBYTES]; &c[..CIPHERTEXTBYTES]);

    {
        let kr = array_mut_ref!(kr, 0, SYMBYTES);
        let sk = array_ref!(sk, SECRETKEYBYTES - SYMBYTES, SYMBYTES);
        kr.conditional_assign(sk, flag ^ 1);
    }

    sha3_256!(k; &kr);

    flag == 1
}
