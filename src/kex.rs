use rand::Rng;
use ::params::{ PUBLICKEYBYTES, SHAREDKEYBYTES, BYTES };
use ::kyber;


pub mod uake {
    use super::*;

    pub fn init_a(rng: &mut Rng, send: &mut [u8], tk: &mut [u8], sk: &mut [u8], pkb: &[u8]) {
        kyber::keypair(rng, send, sk);
        kyber::enc(rng, &mut send[PUBLICKEYBYTES..], tk, pkb);
    }

    pub fn shared_b(rng: &mut Rng, send: &mut [u8], k: &mut [u8], recv: &[u8], skb: &[u8]) {
        let mut buf = [0; 2 * SHAREDKEYBYTES];
        kyber::enc(rng, send, &mut buf, recv);
        kyber::dec(&mut buf[SHAREDKEYBYTES..], &recv[PUBLICKEYBYTES..], skb);
        shake128!(k; &buf);
    }

    pub fn shared_a(k: &mut [u8], recv: &[u8], tk: &[u8], sk: &[u8]) {
        let mut buf = [0; 2 * SHAREDKEYBYTES];
        kyber::dec(&mut buf, recv, sk);
        buf[SHAREDKEYBYTES..].copy_from_slice(&tk[..SHAREDKEYBYTES]);
        shake128!(k; &buf);
    }
}

pub mod ake {
    use super::*;

    pub fn init_a(rng: &mut Rng, send: &mut [u8], tk: &mut [u8], sk: &mut [u8], pkb: &[u8]) {
        kyber::keypair(rng, send, sk);
        kyber::enc(rng, &mut send[PUBLICKEYBYTES..], tk, pkb);
    }

    pub fn shared_b(rng: &mut Rng, send: &mut [u8], k: &mut [u8], recv: &[u8], skb: &[u8], pka: &[u8]) {
        let mut buf = [0; 3 * SHAREDKEYBYTES];
        kyber::enc(rng, send, &mut buf, recv);
        kyber::enc(rng, &mut send[BYTES..], &mut buf[SHAREDKEYBYTES..], pka);
        kyber::dec(&mut buf[2 * SHAREDKEYBYTES..], &recv[PUBLICKEYBYTES..], skb);
        shake128!(k; &buf);
    }

    pub fn shared_a(k: &mut [u8], recv: &[u8], tk: &[u8], sk: &[u8], ska: &[u8]) {
        let mut buf = [0; 3 * SHAREDKEYBYTES];
        kyber::dec(&mut buf, recv, sk);
        kyber::dec(&mut buf[SHAREDKEYBYTES..], &recv[BYTES..], ska);
        buf[2 * SHAREDKEYBYTES..].copy_from_slice(&tk[..SHAREDKEYBYTES]);
        shake128!(k; &buf);
    }
}
