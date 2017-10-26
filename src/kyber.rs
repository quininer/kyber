use rand::Rng;
use ::params::{
    SHAREDKEYBYTES, CIPHERTEXTBYTES,
    PUBLICKEYBYTES, SECRETKEYBYTES,
    INDCPA_BYTES,
    INDCPA_SECRETKEYBYTES, INDCPA_PUBLICKEYBYTES
};
use ::{ indcpa, utils };


pub fn keypair(rng: &mut Rng, pk: &mut [u8], sk: &mut [u8]) {
    indcpa::keypair(rng, pk, sk);
    sk[INDCPA_SECRETKEYBYTES..][..INDCPA_PUBLICKEYBYTES].copy_from_slice(&pk[..INDCPA_PUBLICKEYBYTES]);

    shake256!(&mut sk[SECRETKEYBYTES-64..][..32]; &pk[..PUBLICKEYBYTES]);

    rng.fill_bytes(&mut sk[SECRETKEYBYTES-SHAREDKEYBYTES..][..SHAREDKEYBYTES]);
}

pub fn enc(rng: &mut Rng, c: &mut [u8], k: &mut [u8; SHAREDKEYBYTES], pk: &[u8]) {
    let mut buf = [0; SHAREDKEYBYTES];
    let mut buf2 = [0; 32];
    let mut krq = [0; 96];

    rng.fill_bytes(&mut buf);
    shake256!(&mut buf; &buf);

    shake256!(&mut buf2; &pk[..PUBLICKEYBYTES]);
    shake256!(&mut krq; &buf, &buf2);

    indcpa::enc(c, &buf, pk, &krq[32..]);

    c[INDCPA_BYTES..][..32].copy_from_slice(&krq[64..]);

    shake256!(&mut krq[32..][..32]; &c[..CIPHERTEXTBYTES]);
    shake256!(k; &krq[..64]);
}

pub fn dec(k: &mut [u8; SHAREDKEYBYTES], c: &[u8], sk: &[u8]) {
    let mut cmp = [0; CIPHERTEXTBYTES];
    let mut buf = [0; SHAREDKEYBYTES];
    let mut buf2 = [0; 32];
    let mut krq = [0; 96];
    let pk = &sk[INDCPA_SECRETKEYBYTES..][..INDCPA_PUBLICKEYBYTES];

    indcpa::dec(&mut buf, c, sk);

    buf2.copy_from_slice(&sk[SECRETKEYBYTES-64..][..32]);
    shake256!(&mut krq; &buf, &buf2);

    indcpa::enc(&mut cmp, &buf, pk, &krq[32..]);

    cmp[INDCPA_BYTES..][..32].copy_from_slice(&krq[64..]);

    let flag = utils::eq(c, &cmp);

    shake256!(&mut krq[32..][..32]; &c[..CIPHERTEXTBYTES]);

    utils::select_mov(&mut krq, &sk[SECRETKEYBYTES-SHAREDKEYBYTES..][..SHAREDKEYBYTES], flag);

    shake256!(k; &krq[..64]);
}
