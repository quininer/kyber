use rand::Rng;
use ::params::{ PUBLICKEYBYTES, SECRETKEYBYTES, SHAREDKEYBYTES, BYTES };
use ::kyber;


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
        kyber::keypair(rng, send, sk);
        kyber::enc(rng, &mut send[PUBLICKEYBYTES..], tk, pkb);
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
        kyber::enc(rng, send, &mut buf, recv);
        kyber::dec(&mut buf2, &recv[PUBLICKEYBYTES..], skb);
        shake128!(k; &buf, &buf2);
    }

    pub fn shared_a(
        k: &mut [u8; SHAREDKEYBYTES],
        recv: &[u8; UAKE_SENDBBYTES],
        tk: &[u8; SHAREDKEYBYTES],
        sk: &[u8; SECRETKEYBYTES]
    ) {
        let mut buf = [0; SHAREDKEYBYTES];
        let mut buf2 = [0; SHAREDKEYBYTES];
        kyber::dec(&mut buf, recv, sk);
        buf2.copy_from_slice(&tk[..SHAREDKEYBYTES]);
        shake128!(k; &buf, &buf2);
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
        kyber::keypair(rng, send, sk);
        kyber::enc(rng, &mut send[PUBLICKEYBYTES..], tk, pkb);
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
        kyber::enc(rng, send, &mut buf, recv);
        kyber::enc(rng, &mut send[BYTES..], &mut buf2, pka);
        kyber::dec(&mut buf3, &recv[PUBLICKEYBYTES..], skb);
        shake128!(k; &buf, &buf2, &buf3);
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
        let mut buf3 = [0; SHAREDKEYBYTES];
        kyber::dec(&mut buf, recv, sk);
        kyber::dec(&mut buf2, &recv[BYTES..], ska);
        buf3.copy_from_slice(&tk[..SHAREDKEYBYTES]);
        shake128!(k; &buf, &buf2, &buf3);
    }
}
