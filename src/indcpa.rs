use rand::Rng;
use byteorder::{ ByteOrder, LittleEndian };
use sp800_185::CShake;
use ::ntt::bitrev_vector;
use ::poly::{ self, Poly };
use ::polyvec::{ self, PolyVec };
use ::params::{
    N, K, Q,
    SHAREDKEYBYTES,
    POLYVECCOMPRESSEDBYTES,
    SEEDBYTES, COINBYTES
};


#[inline]
pub fn pack_sk(r: &mut [u8], sk: &PolyVec) {
    polyvec::tobytes(sk, r);
}

#[inline]
pub fn unpack_sk(sk: &mut PolyVec, a: &[u8]) {
    polyvec::frombytes(sk, a);
}

#[inline]
pub fn pack_pk(r: &mut [u8], pk: &PolyVec, seed: &[u8]) {
    polyvec::compress(pk, r);
    r[POLYVECCOMPRESSEDBYTES..][..SEEDBYTES].copy_from_slice(seed);
}

#[inline]
pub fn unpack_pk(pk: &mut PolyVec, seed: &mut [u8], packedpk: &[u8]) {
    polyvec::decompress(pk, packedpk);
    seed[..SEEDBYTES].copy_from_slice(&packedpk[POLYVECCOMPRESSEDBYTES..][..SEEDBYTES]);
}

#[inline]
pub fn pack_ciphertext(r: &mut [u8], b: &PolyVec, v: &Poly) {
    polyvec::compress(b, r);
    poly::compress(v, &mut r[POLYVECCOMPRESSEDBYTES..]);
}

#[inline]
pub fn unpack_ciphertext(b: &mut PolyVec, v: &mut Poly, r: &[u8]) {
    polyvec::decompress(b, &r[..POLYVECCOMPRESSEDBYTES]);
    poly::decompress(v, &r[POLYVECCOMPRESSEDBYTES..]);
}

pub fn gen_matrix(a: &mut [PolyVec], seed: &[u8], transposed: bool) {
    const SHAKE128_RATE: usize = 168;

    for i in 0..K {
        for j in 0..K {
            let mut sep = [0; 2];
            let dsep = if transposed { j + (i << 8) } else { i + (j << 8) };
            LittleEndian::write_u16(&mut sep, dsep as u16);

            let (mut nblocks, mut pos, mut ctr) = (4, 0, 0);
            let mut buf = [0; SHAKE128_RATE * 4];
            let mut cshake = CShake::new_cshake128(&[], &sep);
            cshake.update(seed);
            cshake.finalize(&mut buf);

            while ctr < N {
                let val = LittleEndian::read_u16(&buf[pos..]) & 0x1fff;
                if val < Q as u16 {
                    a[i][j][ctr] = val;
                    ctr += 1;
                }
                pos += 2;

                if pos > SHAKE128_RATE * nblocks - 2 {
                    nblocks = 1;
                    cshake.squeeze(&mut buf);
                    pos = 0;
                }
            }
        }
    }
}

pub fn keypair(rng: &mut Rng, pk: &mut [u8], sk: &mut [u8]) {
    let mut seed = [0; SEEDBYTES];
    let mut noiseseed = [0; COINBYTES];
    let mut a = [[[0; N]; K]; K];
    let mut e = [[0; N]; K];
    let mut pkpv = [[0; N]; K];
    let mut skpv = [[0; N]; K];
    let mut nonce = 0;

    rng.fill_bytes(&mut seed);
    rng.fill_bytes(&mut noiseseed);
    shake128!(&mut seed; &seed);

    gen_matrix(&mut a, &seed, false);

    for poly in &mut skpv {
        poly::getnoise(poly, &noiseseed, nonce);
        nonce += 1;
    }

    polyvec::ntt(&mut skpv);

    for poly in &mut e {
        poly::getnoise(poly, &noiseseed, nonce);
        nonce += 1;
    }

    for i in 0..K {
        polyvec::pointwise_acc(&mut pkpv[i], &skpv, &a[i]);
    }
    polyvec::invntt(&mut pkpv);
    polyvec::add(&mut pkpv, &e);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, &seed);
}

pub fn enc(c: &mut [u8], m: &[u8; SHAREDKEYBYTES], pk: &[u8], coins: &[u8]) {
    let (mut k, mut v, mut epp) = ([0; N], [0; N], [0; N]);
    let (mut sp, mut ep, mut bp) = ([[0; N]; K], [[0; N]; K], [[0; N]; K]);
    let mut pkpv = [[0; N]; K];
    let mut at = [[[0; N]; K]; K];
    let mut seed = [0; SEEDBYTES];
    let mut nonce = 0;

    unpack_pk(&mut pkpv, &mut seed, pk);
    poly::frommsg(&mut k, m);

    for poly in &mut pkpv {
        bitrev_vector(poly);
    }
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

pub fn dec(m: &mut [u8; SHAREDKEYBYTES], c: &[u8], sk: &[u8]) {
    let (mut bp, mut skpv) = ([[0; N]; K], [[0; N]; K]);
    let (mut v, mut mp) = ([0; N], [0; N]);

    unpack_ciphertext(&mut bp, &mut v, c);
    unpack_sk(&mut skpv, sk);

    for poly in &mut bp {
        bitrev_vector(poly);
    }
    polyvec::ntt(&mut bp);

    polyvec::pointwise_acc(&mut mp, &skpv, &bp);
    poly::invntt(&mut mp);

    poly::sub(&mut mp, &v);

    poly::tomsg(&mp, m);
}
