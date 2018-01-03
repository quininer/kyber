use rand::Rng;
use byteorder::{ ByteOrder, LittleEndian };
use ::poly::{ self, Poly };
use ::polyvec::{ self, PolyVec };
use ::params::{
    N, K, Q,
    INDCPA_PUBLICKEYBYTES, INDCPA_SECRETKEYBYTES, INDCPA_BYTES, INDCPA_MSGBYTES,
    POLYVECBYTES, POLYCOMPRESSEDBYTES, POLYVECCOMPRESSEDBYTES,
    SYMBYTES
};


#[inline]
pub fn pack_sk(r: &mut [u8; INDCPA_SECRETKEYBYTES], sk: &PolyVec) {
    polyvec::tobytes(sk, r);
}

#[inline]
pub fn unpack_sk(sk: &mut PolyVec, a: &[u8; INDCPA_SECRETKEYBYTES]) {
    polyvec::frombytes(sk, a);
}

#[inline]
pub fn pack_pk(r: &mut [u8; INDCPA_PUBLICKEYBYTES], pk: &PolyVec, seed: &[u8; SYMBYTES]) {
    polyvec::compress(pk, array_mut_ref!(r, 0, POLYVECCOMPRESSEDBYTES));
    array_mut_ref!(r, POLYVECCOMPRESSEDBYTES, SYMBYTES).clone_from(seed);
}

#[inline]
pub fn unpack_pk(pk: &mut PolyVec, seed: &mut [u8; SYMBYTES], packedpk: &[u8; INDCPA_PUBLICKEYBYTES]) {
    polyvec::decompress(pk, array_ref!(packedpk, 0, POLYVECCOMPRESSEDBYTES));
    seed.clone_from(array_ref!(packedpk, POLYVECCOMPRESSEDBYTES, SYMBYTES));
}

#[inline]
pub fn pack_ciphertext(r: &mut [u8; INDCPA_BYTES], b: &PolyVec, v: &Poly) {
    polyvec::compress(b, array_mut_ref!(r, 0, POLYVECCOMPRESSEDBYTES));
    poly::compress(v, array_mut_ref!(r, POLYVECCOMPRESSEDBYTES, POLYCOMPRESSEDBYTES));
}

#[inline]
pub fn unpack_ciphertext(b: &mut PolyVec, v: &mut Poly, r: &[u8; INDCPA_BYTES]) {
    polyvec::decompress(b, array_ref!(r, 0, POLYVECCOMPRESSEDBYTES));
    poly::decompress(v, array_ref!(r, POLYVECCOMPRESSEDBYTES, POLYCOMPRESSEDBYTES));
}

pub fn gen_matrix(a: &mut [PolyVec], seed: &[u8; SYMBYTES], transposed: bool) {
    use sha3::Shake128;
    use digest::{ Input, ExtendableOutput, XofReader };

    const SHAKE128_RATE: usize = 168;

    for i in 0..K {
        for j in 0..K {
            let mut shake = Shake128::default();
            let (mut nblocks, mut pos, mut ctr) = (4, 0, 0);
            let mut buf = [0; SHAKE128_RATE * 4];
            let sep = if transposed { [i as u8, j as u8] } else { [j as u8, i as u8] };

            shake.process(seed);
            shake.process(&sep);
            let mut xof = shake.xof_result();
            xof.read(&mut buf);

            while ctr < N {
                let val = LittleEndian::read_u16(&buf[pos..]) & 0x1fff;
                if val < Q as u16 {
                    a[i][j][ctr] = val;
                    ctr += 1;
                }
                pos += 2;

                if pos > SHAKE128_RATE * nblocks - 2 {
                    nblocks = 1;
                    xof.read(&mut buf);
                    pos = 0;
                }
            }
        }
    }
}

pub fn keypair<R: Rng>(rng: &mut R, pk: &mut [u8; INDCPA_PUBLICKEYBYTES], sk: &mut [u8; INDCPA_SECRETKEYBYTES]) {
    let mut seed = [0; SYMBYTES + SYMBYTES];
    let mut a = [[[0; N]; K]; K];
    let mut e = [[0; N]; K];
    let mut pkpv = [[0; N]; K];
    let mut skpv = [[0; N]; K];
    let mut nonce = 0;

    rng.fill_bytes(&mut seed[..SYMBYTES]);
    sha3_512!(&mut seed; &seed[..SYMBYTES]);

    let publicseed = array_ref!(seed, 0, SYMBYTES);
    let noiseseed = array_ref!(seed, SYMBYTES, SYMBYTES);

    gen_matrix(&mut a, publicseed, false);

    for poly in &mut skpv {
        poly::getnoise(poly, noiseseed, nonce);
        nonce += 1;
    }

    polyvec::ntt(&mut skpv);

    for poly in &mut e {
        poly::getnoise(poly, noiseseed, nonce);
        nonce += 1;
    }

    for i in 0..K {
        polyvec::pointwise_acc(&mut pkpv[i], &skpv, &a[i]);
    }
    polyvec::invntt(&mut pkpv);
    polyvec::add(&mut pkpv, &e);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);
}

pub fn enc(c: &mut [u8; INDCPA_BYTES], m: &[u8; INDCPA_MSGBYTES], pk: &[u8; INDCPA_PUBLICKEYBYTES], coins: &[u8; SYMBYTES]) {
    let (mut k, mut v, mut epp) = ([0; N], [0; N], [0; N]);
    let (mut sp, mut ep, mut bp) = ([[0; N]; K], [[0; N]; K], [[0; N]; K]);
    let mut pkpv = [[0; N]; K];
    let mut at = [[[0; N]; K]; K];
    let mut seed = [0; SYMBYTES];
    let mut nonce = 0;

    unpack_pk(&mut pkpv, &mut seed, pk);
    poly::frommsg(&mut k, m);

    polyvec::ntt(&mut pkpv);

    gen_matrix(&mut at, &seed, true);

    for poly in &mut sp {
        poly::getnoise(poly, coins, nonce);
        nonce += 1;
    }
    polyvec::ntt(&mut sp);

    for poly in &mut ep {
        poly::getnoise(poly, coins, nonce);
        nonce += 1;
    }

    for i in 0..K {
        polyvec::pointwise_acc(&mut bp[i], &sp, &at[i]);
    }
    polyvec::invntt(&mut bp);
    polyvec::add(&mut bp, &ep);

    polyvec::pointwise_acc(&mut v, &pkpv, &sp);
    poly::invntt(&mut v);

    poly::getnoise(&mut epp, coins, nonce);

    poly::add(&mut v, &epp);
    poly::add(&mut v, &k);

    pack_ciphertext(c, &bp, &v);
}

pub fn dec(m: &mut [u8; INDCPA_MSGBYTES], c: &[u8; INDCPA_BYTES], sk: &[u8; POLYVECBYTES]) {
    let (mut bp, mut skpv) = ([[0; N]; K], [[0; N]; K]);
    let (mut v, mut mp) = ([0; N], [0; N]);

    unpack_ciphertext(&mut bp, &mut v, c);
    unpack_sk(&mut skpv, sk);

    polyvec::ntt(&mut bp);

    polyvec::pointwise_acc(&mut mp, &skpv, &bp);
    poly::invntt(&mut mp);

    poly::sub(&mut mp, &v);

    poly::tomsg(&mp, m);
}
