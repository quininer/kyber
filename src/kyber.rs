use rand::Rng;
use ::params::{
    SHAREDKEYBYTES, BYTES,
    PUBLICKEYBYTES, SECRETKEYBYTES,
    INDCPA_BYTES,
    INDCPA_SECRETKEYBYTES, INDCPA_PUBLICKEYBYTES
};
use ::{ indcpa, utils };


pub fn keypair(rng: &mut Rng, pk: &mut [u8], sk: &mut [u8]) {
    indcpa::keypair(rng, pk, sk);
    sk[INDCPA_SECRETKEYBYTES..][..INDCPA_PUBLICKEYBYTES].copy_from_slice(&pk[..INDCPA_PUBLICKEYBYTES]);

    shake128!(&mut sk[SECRETKEYBYTES-64..][..32]; &pk[..PUBLICKEYBYTES]);

    rng.fill_bytes(&mut sk[SECRETKEYBYTES-SHAREDKEYBYTES..][..SHAREDKEYBYTES]);
}

pub fn enc(rng: &mut Rng, c: &mut [u8], k: &mut [u8; SHAREDKEYBYTES], pk: &[u8]) {
    let mut buf = [0; SHAREDKEYBYTES];
    let mut buf2 = [0; 32];
    let mut krq = [0; 96];

    rng.fill_bytes(&mut buf);
    shake128!(&mut buf; &buf);

    shake128!(&mut buf2; &pk[..PUBLICKEYBYTES]);
    shake128!(&mut krq; &buf, &buf2);

    indcpa::enc(c, &buf, pk, &krq[32..]);

    c[INDCPA_BYTES..][..32].copy_from_slice(&krq[64..]);

    shake128!(&mut krq[32..][..32]; &c[..BYTES]);
    shake128!(k; &krq[..64]);
}

pub fn dec(k: &mut [u8; SHAREDKEYBYTES], c: &[u8], sk: &[u8]) {
    let mut cmp = [0; BYTES];
    let mut buf = [0; SHAREDKEYBYTES];
    let mut buf2 = [0; 32];
    let mut krq = [0; 96];
    let pk = &sk[INDCPA_SECRETKEYBYTES..][..INDCPA_PUBLICKEYBYTES];

    indcpa::dec(&mut buf, c, sk);

    buf2.copy_from_slice(&sk[SECRETKEYBYTES-64..][..32]);
    shake128!(&mut krq; &buf, &buf2);

    indcpa::enc(&mut cmp, &buf, pk, &krq[32..]);

    cmp[INDCPA_BYTES..][..32].copy_from_slice(&krq[64..]);

    let flag = utils::eq(c, &cmp);

    shake128!(&mut krq[32..][..32]; &c[..BYTES]);

    utils::select_mov(&mut krq, &sk[SECRETKEYBYTES-SHAREDKEYBYTES..][..SHAREDKEYBYTES], flag);

    shake128!(k; &krq[..64]);
}
