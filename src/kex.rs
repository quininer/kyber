use rand::Rng;
use ::params::{ PUBLICKEYBYTES, SECRETKEYBYTES, SHAREDKEYBYTES, CIPHERTEXTBYTES };
use ::kem;


pub mod uake {
    use ::params::{ UAKE_SENDABYTES, UAKE_SENDBBYTES };
    use super::*;

    pub fn init_a(
        rng: &mut Rng,
        send: &mut [u8; UAKE_SENDABYTES],
        tk: &mut [u8; SHAREDKEYBYTES],
        sk: &mut [u8; SECRETKEYBYTES],
        pkb: &[u8; PUBLICKEYBYTES]
    ) {
        kem::keypair(rng, send, sk);
        kem::enc(rng, &mut send[PUBLICKEYBYTES..], tk, pkb);
    }

    pub fn shared_b(
        rng: &mut Rng,
        send: &mut [u8; UAKE_SENDBBYTES],
        k: &mut [u8; SHAREDKEYBYTES],
        recv: &[u8; UAKE_SENDABYTES],
        skb: &[u8; SECRETKEYBYTES]
    ) {
        let mut buf = [0; SHAREDKEYBYTES];
        let mut buf2 = [0; SHAREDKEYBYTES];
        kem::enc(rng, send, &mut buf, recv);
        kem::dec(&mut buf2, &recv[PUBLICKEYBYTES..], skb);
        shake256!(k; &buf, &buf2);
    }

    pub fn shared_a(
        k: &mut [u8; SHAREDKEYBYTES],
        recv: &[u8; UAKE_SENDBBYTES],
        tk: &[u8; SHAREDKEYBYTES],
        sk: &[u8; SECRETKEYBYTES]
    ) {
        let mut buf = [0; SHAREDKEYBYTES];
        kem::dec(&mut buf, recv, sk);
        shake256!(k; &buf, &tk[..SHAREDKEYBYTES]);
    }
}

pub mod ake {
    use ::params::{ AKE_SENDABYTES, AKE_SENDBBYTES };
    use super::*;

    pub fn init_a(
        rng: &mut Rng,
        send: &mut [u8; AKE_SENDABYTES],
        tk: &mut [u8; SHAREDKEYBYTES],
        sk: &mut [u8; SECRETKEYBYTES],
        pkb: &[u8; PUBLICKEYBYTES]
    ) {
        kem::keypair(rng, send, sk);
        kem::enc(rng, &mut send[PUBLICKEYBYTES..], tk, pkb);
    }

    pub fn shared_b(
        rng: &mut Rng,
        send: &mut [u8; AKE_SENDBBYTES],
        k: &mut [u8; SHAREDKEYBYTES],
        recv: &[u8; AKE_SENDABYTES],
        skb: &[u8; SECRETKEYBYTES],
        pka: &[u8; PUBLICKEYBYTES]
    ) {
        let mut buf = [0; SHAREDKEYBYTES];
        let mut buf2 = [0; SHAREDKEYBYTES];
        let mut buf3 = [0; SHAREDKEYBYTES];
        kem::enc(rng, send, &mut buf, recv);
        kem::enc(rng, &mut send[CIPHERTEXTBYTES..], &mut buf2, pka);
        kem::dec(&mut buf3, &recv[PUBLICKEYBYTES..], skb);
        shake256!(k; &buf, &buf2, &buf3);
    }

    pub fn shared_a(
        k: &mut [u8; SHAREDKEYBYTES],
        recv: &[u8; AKE_SENDBBYTES],
        tk: &[u8; SHAREDKEYBYTES],
        sk: &[u8; SECRETKEYBYTES],
        ska: &[u8; SECRETKEYBYTES]
    ) {
        let mut buf = [0; SHAREDKEYBYTES];
        let mut buf2 = [0; SHAREDKEYBYTES];
        kem::dec(&mut buf, recv, sk);
        kem::dec(&mut buf2, &recv[CIPHERTEXTBYTES..], ska);
        shake256!(k; &buf, &buf2, &tk[..SHAREDKEYBYTES]);
    }
}
