use rand::Rng;
use ::params::{
    COINBYTES,
    SHAREDKEYBYTES, CIPHERTEXTBYTES,
    PUBLICKEYBYTES, SECRETKEYBYTES,
    INDCPA_BYTES,
    INDCPA_SECRETKEYBYTES, INDCPA_PUBLICKEYBYTES,
    POLYVECBYTES
};
use ::{ indcpa, utils };


pub fn keypair(rng: &mut Rng, pk: &mut [u8; PUBLICKEYBYTES], sk: &mut [u8; SECRETKEYBYTES]) {
    indcpa::keypair(rng, pk, array_mut_ref!(sk, 0, POLYVECBYTES));
    array_mut_ref!(sk, INDCPA_SECRETKEYBYTES, INDCPA_PUBLICKEYBYTES).clone_from(pk);

    shake256!(&mut sk[SECRETKEYBYTES-64..][..32]; &pk[..PUBLICKEYBYTES]);

    rng.fill_bytes(&mut sk[SECRETKEYBYTES-SHAREDKEYBYTES..][..SHAREDKEYBYTES]);
}

pub fn enc(rng: &mut Rng, c: &mut [u8; CIPHERTEXTBYTES], k: &mut [u8; SHAREDKEYBYTES], pk: &[u8; PUBLICKEYBYTES]) {
    let mut buf = [0; SHAREDKEYBYTES];
    let mut buf2 = [0; 32];
    let mut krq = [0; 96];

    rng.fill_bytes(&mut buf);
    shake256!(&mut buf; &buf);

    shake256!(&mut buf2; &pk[..PUBLICKEYBYTES]);
    shake256!(&mut krq; &buf, &buf2);

    indcpa::enc(array_mut_ref!(c, 0, INDCPA_BYTES), &buf, pk, array_ref!(&krq, 32, COINBYTES));

    array_mut_ref!(c, INDCPA_BYTES, 32).clone_from(array_ref!(krq, 64, 32));

    shake256!(&mut krq[32..][..32]; c);
    shake256!(k; &krq[..64]);
}

pub fn dec(k: &mut [u8; SHAREDKEYBYTES], c: &[u8; CIPHERTEXTBYTES], sk: &[u8; SECRETKEYBYTES]) -> bool {
    let mut cmp = [0; CIPHERTEXTBYTES];
    let mut buf = [0; SHAREDKEYBYTES];
    let mut krq = [0; 96];
    let pk = array_ref!(sk, INDCPA_SECRETKEYBYTES, INDCPA_PUBLICKEYBYTES);

    indcpa::dec(&mut buf, array_ref!(c, 0, INDCPA_BYTES), array_ref!(sk, 0, POLYVECBYTES));
    shake256!(&mut krq; &buf, &sk[SECRETKEYBYTES-64..][..32]);

    indcpa::enc(array_mut_ref!(cmp, 0, INDCPA_BYTES), &buf, pk, array_ref!(&krq, 32, COINBYTES));
    array_mut_ref!(cmp, INDCPA_BYTES, 32).clone_from(array_ref!(krq, 64, 32));

    let flag = utils::eq(c, &cmp);

    shake256!(&mut krq[32..][..32]; &c[..CIPHERTEXTBYTES]);

    utils::select_mov(&mut krq, &sk[SECRETKEYBYTES-SHAREDKEYBYTES..][..SHAREDKEYBYTES], flag);

    shake256!(k; &krq[..64]);

    flag
}
