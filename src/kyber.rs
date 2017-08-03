use rand::Rng;
use ::params::{
    SHAREDKEYBYTES,
    SECRETKEYBYTES, BYTES,
    INDCPA_BYTES,
    INDCPA_SECRETKEYBYTES, INDCPA_PUBLICKEYBYTES
};
use ::{ indcpa, utils };


pub fn keypair(rng: &mut Rng, pk: &mut [u8], sk: &mut [u8]) {
    indcpa::keypair(rng, pk, sk);
    sk[INDCPA_SECRETKEYBYTES..][..INDCPA_PUBLICKEYBYTES].copy_from_slice(pk);

    shake128!(&mut sk[SECRETKEYBYTES-64..][..32]; pk);

    rng.fill_bytes(&mut sk[SECRETKEYBYTES-SHAREDKEYBYTES..][..SHAREDKEYBYTES]);
}

pub fn enc(rng: &mut Rng, c: &mut [u8], k: &mut [u8], pk: &[u8]) {
    let mut buf = [0; 32];
    let mut buf2 = [0; 32];
    let mut krq = [0; 96];

    rng.fill_bytes(&mut buf);
    shake128!(&mut buf; &buf);

    shake128!(&mut buf2; pk);
    shake128!(&mut krq; &buf, &buf2);

    indcpa::enc(c, &buf, pk, &krq[32..]);

    c[INDCPA_BYTES..][..32].copy_from_slice(&krq[64..]);

    shake128!(&mut krq[32..][..32]; &c[..BYTES]);
    shake128!(&mut k[..32]; &krq[..64]);
}

pub fn dec(k: &mut [u8], c: &[u8], sk: &[u8]) {
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

    shake128!(&mut k[..32]; &krq[..64]);
}
